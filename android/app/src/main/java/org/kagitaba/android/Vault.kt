package org.kagitaba.android

import android.content.Context
import android.util.AtomicFile
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.ObjectId
import org.eclipse.jgit.revwalk.RevWalk
import org.eclipse.jgit.transport.RefSpec
import org.eclipse.jgit.transport.RemoteRefUpdate
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URI

class Vault(private val context: Context, private val directory: File = context.noBackupFilesDir, val walletId: String = "legacy") {
    init { directory.mkdirs() }
    // Product-level selection: DeviceIdentity is retained, but deliberately not
    // reachable from setup, unlock, providers, or autofill in this build.
    val device = PivIdentity(context)
    private val gate = Any()
    private val session = UnlockSession { (context as KagitabaApp).nextEpoch() }
    val epoch get() = session.epoch
    private val operations = Mutex()
    private val stateFile = AtomicFile(File(directory, "wallet-state.json"))
    private val repoDir = File(directory, "wallet")
    private var pendingToken: ByteArray? = null
    @Volatile private var state = if (stateFile.baseFile.exists()) JSONObject(String(stateFile.readFully())) else JSONObject()
    @Volatile private var snapshot: JSONObject? = null
    val lockListeners = mutableSetOf<() -> Unit>()
    val unlocked get() = session.unlocked
    val connected get() = synchronized(gate) { state.has("head") }
    fun settings(): JSONObject = synchronized(gate) { JSONObject(state.toString()).apply { remove("token") } }
    fun unlock(bytes: ByteArray) { session.open(bytes); (context as KagitabaApp).touch() }
    fun lock() {
        session.invalidate()
        synchronized(gate) { snapshot = null; pendingToken?.fill(0); pendingToken = null }
        device.close()
        RequestTickets.clear(); AutofillRequests.clear()
        val notify = Runnable { lockListeners.toList().forEach { it() } }
        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) notify.run()
        else android.os.Handler(android.os.Looper.getMainLooper()).post(notify)
    }
    private fun <T> secret(block: (String) -> T): T = session.use { bytes ->
        block(if (bytes.take(4) == "piv:".toByteArray().toList()) String(bytes, Charsets.UTF_8) else b64(bytes))
    }
    private fun persist(next: JSONObject) = synchronized(gate) {
        var stream: java.io.FileOutputStream? = null
        try { stream = stateFile.startWrite(); stream.write(next.toString().toByteArray()); stateFile.finishWrite(stream) }
        catch (e: Exception) { stateFile.failWrite(stream); throw e }
        state = next
    }
    private fun accepted(result: JSONObject) {
        val next = JSONObject(state.toString()).put("root", result.getString("root")).put("head", result.getString("head"))
            .put("syncStatus", "Saved locally · synchronization pending")
        persist(next)
        snapshot = result
    }
    fun recordSyncFailure() = synchronized(gate) {
        persist(JSONObject(state.toString()).put("syncStatus", "Synchronization failed. Local changes are retained; check connection and retry."))
    }
    private fun request(op: String, extra: JSONObject = JSONObject()): JSONObject {
        extra.put("path", repoDir.absolutePath)
        if (state.has("root")) extra.put("root", state.getString("root")).put("checkpoint", state.getString("head"))
        return NativeBridge.call(op, extra)
    }
    private fun read(): JSONObject = request("store_open").also { snapshot = it }
    suspend fun create() = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        check(!connected) { "A wallet is already connected" }
        accepted(request("store_create", json("identity" to key, "device" to device.publicInfo().getJSONObject("device"))))
        persist(JSONObject(state.toString()).put("createdHere", true))
    } } }
    private fun canonicalUrl(url: String): String {
        val uri = URI(url.trim())
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.query == null && uri.fragment == null) { "Use an HTTPS Git URL without embedded credentials" }
        return uri.toASCIIString()
    }
    private fun git(): Git = if (File(repoDir, ".git").exists()) Git.open(repoDir) else Git.init().setDirectory(repoDir).call()
    private fun fetch(git: Git, url: String, username: String, token: String) {
        git.repository.config.setString("http", null, "followRedirects", "false")
        git.repository.config.setBoolean("http", null, "sslVerify", true)
        git.fetch().setRemote(url).setRefSpecs(RefSpec("+refs/heads/*:refs/remotes/origin/*"))
            .setRemoveDeletedRefs(true).setCheckFetchedObjects(true)
            .setCredentialsProvider(UsernamePasswordCredentialsProvider(username, token)).setTimeout(30).call()
    }
    suspend fun connect(url: String, username: String, token: String, autoSync: Boolean) = withContext(Dispatchers.IO) { operations.withLock {
        val canonical = canonicalUrl(url)
        check(!connected) { "Use synchronization for your connected wallet" }
        git().use { git ->
            fetch(git, canonical, username, token)
            val head = git.repository.resolve("refs/remotes/origin/wallet") ?: error("Remote wallet branch is missing")
            git.repository.updateRef("refs/heads/wallet").apply { setNewObjectId(head); setForceUpdate(true); update() }
            synchronized(gate) {
                val verified = request("store_connect")
                // Only materialize the encrypted checkout after Rust has verified
                // committed history. A fresh JGit init otherwise stays on its
                // unborn default branch with no index, so later signed writes fail.
                git.checkout().setName("wallet").call()
                val next = JSONObject(state.toString()).put("url", canonical).put("username", username).put("autoSync", autoSync)
                next.remove("token")
                next.put("root", verified.getString("root")).put("head", verified.getString("head"))
                persist(next); snapshot = verified
                pendingToken?.fill(0); pendingToken = token.toByteArray()
            }
        }
    } }
    private fun authContext(url: String, username: String) = json("application" to "kagitaba-android-git-v1", "url" to url, "username" to username).toString()
    suspend fun unlockCandidates(): JSONArray = withContext(Dispatchers.IO) { operations.withLock { synchronized(gate) {
        val verified = read()
        val signers = verified.getJSONObject("signingKeys")
        val devices = verified.getJSONObject("devices")
        val participants = verified.getJSONObject("participants")
        JSONArray(participants.keys().asSequence().filter { signers.has(it) }.map { id ->
            json("participantId" to id, "participantPem" to participants.getString(id), "signingPem" to signers.getString(id),
                "name" to "", "device" to devices.optJSONObject(id))
        }.toList())
    } } }
    suspend fun finishUnlock() = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        if (connected) requireParticipant(read())
        val token = synchronized(gate) { pendingToken?.copyOf() }
        token?.let { bytes ->
            try {
                val encrypted = NativeBridge.call("local_encrypt", json("identity" to key, "context" to authContext(state.getString("url"), state.optString("username")), "plaintext" to String(bytes)))
                persist(JSONObject(state.toString()).put("token", encrypted.getString("envelope")))
                synchronized(gate) { pendingToken?.fill(0); pendingToken = null }
            } finally { bytes.fill(0) }
        }
    } } }
    private fun requireParticipant(verified: JSONObject) {
        check(verified.getJSONObject("participants").has(device.publicInfo().getString("participantId"))) {
            "This YubiKey participant is not enrolled in this wallet. Select its existing slots or enroll it on your computer."
        }
    }
    suspend fun saveConnection(url: String, username: String, token: String, auto: Boolean) = withContext(Dispatchers.IO) { operations.withLock { synchronized(gate) {
        val canonical = canonicalUrl(url)
        val next = JSONObject(state.toString())
        if (token.isNotEmpty() || !state.has("token") || canonical != state.optString("url") || username != state.optString("username")) {
            if (unlocked) secret { key -> next.put("token", NativeBridge.call("local_encrypt", json("identity" to key, "context" to authContext(canonical, username), "plaintext" to token)).getString("envelope")) }
            else { next.remove("token"); pendingToken?.fill(0); pendingToken = token.toByteArray() }
        }
        next.put("url", canonical).put("username", username).put("autoSync", auto)
        // Changing endpoint preserves the existing root and checkpoint.
        persist(next)
    } } }
    suspend fun sync(): String = withContext(Dispatchers.IO) { operations.withLock {
        val credentials = secret { key ->
            check(state.has("token")) { "Re-enter the Git token for your YubiKey participant." }
            val url = state.getString("url"); val username = state.optString("username")
            Triple(url, username, NativeBridge.call("local_decrypt", json("identity" to key,
                "context" to authContext(url, username), "envelope" to state.getString("token"))).getString("plaintext"))
        }
        git().use { git ->
            fetch(git, credentials.first, credentials.second, credentials.third)
            val remote = git.repository.resolve("refs/remotes/origin/wallet")
            secret { _ ->
                val current = read(); val local = ObjectId.fromString(current.getString("head"))
                val result = RevWalk(git.repository).use { walk ->
                    when {
                        remote == null && state.optBoolean("createdHere") && !state.has("lastSync") -> "push"
                        remote == null -> error("Remote wallet branch is missing")
                        remote == local -> "Wallet is up to date"
                        walk.isMergedInto(walk.parseCommit(local), walk.parseCommit(remote)) -> {
                            accepted(request("store_accept", json("candidate" to remote.name))); "Downloaded wallet updates"
                        }
                        walk.isMergedInto(walk.parseCommit(remote), walk.parseCommit(local)) -> "push"
                        else -> error("Wallet histories diverged. No changes were discarded; resolve this on your computer.")
                    }
                }
                result
            }.let { result ->
                val outcome = if (result == "push") {
                    check(unlocked) { "Wallet locked before upload" }
                    val updates = git.push().setRemote(credentials.first).setRefSpecs(RefSpec("refs/heads/wallet:refs/heads/wallet"))
                        .setCredentialsProvider(UsernamePasswordCredentialsProvider(credentials.second, credentials.third)).setTimeout(30).call()
                    check(updates.flatMap { it.remoteUpdates }.all { it.status == RemoteRefUpdate.Status.OK || it.status == RemoteRefUpdate.Status.UP_TO_DATE }) { "Upload rejected. Synchronize again; remote history may have changed." }
                    "Uploaded wallet updates"
                } else result
                synchronized(gate) { persist(JSONObject(state.toString()).put("lastSync", System.currentTimeMillis()).put("syncStatus", outcome)) }
                outcome
            }
        }
    } }
    suspend fun entries(): List<WalletItem> = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        val verified = read()
        requireParticipant(verified)
        val id = device.publicInfo().getString("participantId")
        val entries = verified.getJSONArray("entries")
        val metadata = verified.getJSONObject("participantMetadata")
        val metadataIds = metadata.keys().asSequence().map { metadata.getString(it) }.toSet()
        (0 until entries.length()).mapNotNull { index ->
            val record = entries.getJSONObject(index)
            val grant = record.getJSONObject("grants").optString(id)
            if (grant.isEmpty() || record.getString("id") in metadataIds) null else {
                val payload = NativeBridge.call("entry_decrypt", json("identity" to key, "primary" to record.getString("primary"), "grant" to grant)).getString("payload")
                WalletItem(record.getString("id"), JSONObject(payload))
            }
        }
    } } }
    suspend fun save(item: WalletItem, expectedEpoch: Long = epoch, expectedPayload: String? = null) = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        check(epoch == expectedEpoch) { "Authentication expired" }
        val verified = read()
        val records = verified.getJSONArray("entries")
        val existing = (0 until records.length()).map { records.getJSONObject(it) }.find { it.getString("id") == item.id }
        if (expectedPayload != null) {
            // Large-blob writes must not overwrite a concurrent edit or resurrect a deletion.
            check(existing != null) { "The passkey changed while this request was open. Restart the request." }
            val grant = existing.getJSONObject("grants").getString(device.publicInfo().getString("participantId"))
            val current = NativeBridge.call("entry_decrypt", json("identity" to key, "primary" to existing.getString("primary"), "grant" to grant)).getString("payload")
            check(JSONObject(current).toString() == expectedPayload) { "The passkey changed while this request was open. Restart the request." }
        }
        val participants = verified.getJSONObject("participants")
        val ids = existing?.getJSONObject("grants")?.keys()?.asSequence()?.toList() ?: participants.keys().asSequence().toList()
        require(ids.isNotEmpty()) { "Select wallet recipients before saving" }
        val recipients = JSONArray(ids.map { participants.getString(it) })
        val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(), "recipients" to recipients))
        encrypted.put("identity", key).put("entryId", item.id)
        accepted(request("store_save", encrypted))
    } } }
    suspend fun delete(id: String) = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        accepted(request("store_delete", json("entryId" to id, "identity" to key)))
    } } }
    private fun metadataPayload(verified: JSONObject, participant: String, key: String): JSONObject? {
        val entryId = verified.getJSONObject("participantMetadata").optString(participant)
        if (entryId.isEmpty()) return null
        val records = verified.getJSONArray("entries")
        val record = (0 until records.length()).map { records.getJSONObject(it) }.first { it.getString("id") == entryId }
        val grant = record.getJSONObject("grants").optString(device.publicInfo().getString("participantId"))
        check(grant.isNotEmpty()) { "This participant cannot decrypt the metadata. Complete metadata grants on your computer." }
        return NativeBridge.call("metadata_decrypt", json("identity" to key, "participantId" to participant, "primary" to record.getString("primary"), "grant" to grant))
    }
    suspend fun participants(): List<Pair<String, String>> = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        val verified = read()
        verified.getJSONObject("participants").keys().asSequence().map { id -> id to (metadataPayload(verified, id, key)?.optString("name") ?: "") }.toList()
    } } }
    suspend fun nameParticipant(id: String, name: String) = withContext(Dispatchers.IO) { operations.withLock { secret { key ->
        val verified = read()
        val participants = verified.getJSONObject("participants")
        check(participants.has(id)) { "Unknown wallet participant" }
        val old = metadataPayload(verified, id, key)
        val entryId = verified.getJSONObject("participantMetadata").optString(id).ifEmpty { java.util.UUID.randomUUID().toString().replace("-", "") }
        val args = json("entryId" to entryId, "participantId" to id, "name" to name,
            "recipients" to JSONArray(participants.keys().asSequence().map { participants.getString(it) }.toList()))
        if (old != null) args.put("payload", old.getString("payload"))
        val encrypted = NativeBridge.call("metadata_encrypt", args)
        accepted(request("store_name_participant", encrypted.put("participantId", id).put("identity", key)))
    } } }
    suspend fun export(): String = withContext(Dispatchers.IO) { operations.withLock { synchronized(gate) { request("store_export").toString() } } }
    suspend fun importUpdate(transfer: String) = withContext(Dispatchers.IO) { operations.withLock { synchronized(gate) {
        accepted(request("store_import", json("transfer" to transfer)))
    } } }
}

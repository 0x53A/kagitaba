package org.kagitaba.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.transport.RefSpec
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** All data is synthetic; tests run through the packaged Android JNI library. */
@RunWith(AndroidJUnit4::class)
class NativeInteropTest {
    @Test fun androidJniWalletRoundTripAndJGitFetchPreserveSignedHistory() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.cacheDir, "interop-${java.util.UUID.randomUUID()}").apply { mkdirs() }
        try {
            val source = File(root, "source")
            val identity = NativeBridge.call("identity_generate")
            val created = NativeBridge.call("store_create", json("path" to source.absolutePath, "identity" to identity.getString("identity")))
            val item = WalletItem.create("Synthetic login", WalletItem.password("alice", "synthetic-only"), "https://example.test")
            val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(), "recipients" to JSONArray(listOf(identity.getString("participantPem")))))
            val saved = NativeBridge.call("store_save", encrypted.put("path", source.absolutePath).put("root", created.getString("root"))
                .put("checkpoint", created.getString("head")).put("identity", identity.getString("identity")).put("entryId", item.id))
            val clone = File(root, "clone")
            Git.init().setDirectory(clone).call().use { git ->
                git.fetch().setRemote(source.absolutePath).setRefSpecs(RefSpec("refs/heads/wallet:refs/heads/wallet")).call()
            }
            val reopened = NativeBridge.call("store_open", json("path" to clone.absolutePath, "root" to created.getString("root"), "checkpoint" to created.getString("head")))
            assertEquals(saved.getString("head"), reopened.getString("head"))
            // Match first connection: verify before checking out; then native
            // signed writes must work against JGit's materialized index/tree.
            Git.open(clone).use { it.checkout().setName("wallet").call() }
            val metadataId = "09090909090909090909090909090909"
            val metadata = NativeBridge.call("metadata_encrypt", json("entryId" to metadataId, "participantId" to identity.getString("participantId"), "name" to "Synthetic Android", "recipients" to org.json.JSONArray().put(identity.getString("participantPem"))))
            val named = NativeBridge.call("store_name_participant", metadata.put("path", clone.absolutePath).put("root", created.getString("root")).put("checkpoint", saved.getString("head"))
                .put("identity", identity.getString("identity")).put("participantId", identity.getString("participantId")))
            assertEquals(metadataId, named.getJSONObject("participantMetadata").getString(identity.getString("participantId")))
            val openedMetadata = NativeBridge.call("metadata_decrypt", json("identity" to identity.getString("identity"), "participantId" to identity.getString("participantId"), "primary" to metadata.getString("primary"), "grant" to metadata.getJSONObject("grants").getString(identity.getString("participantId"))))
            assertEquals("Synthetic Android", openedMetadata.getString("name"))
            val entry = reopened.getJSONArray("entries").getJSONObject(0)
            val plaintext = NativeBridge.call("entry_decrypt", json("identity" to identity.getString("identity"), "primary" to entry.getString("primary"),
                "grant" to entry.getJSONObject("grants").getString(identity.getString("participantId"))))
            assertEquals("synthetic-only", org.json.JSONObject(plaintext.getString("payload")).getJSONObject("entity").getJSONArray("credentials").getJSONObject(0).getJSONObject("password").getString("value"))
        } finally { root.deleteRecursively() }
    }
    @Test fun androidPlatformIndependentlyVerifiesRustPasskeySignature() {
        val clientCreate = b64(json("type" to "webauthn.create", "origin" to "https://example.test", "challenge" to b64(ByteArray(32) { 1 })).toString().toByteArray())
        val created = NativeBridge.call("passkey_create", json("rpId" to "example.test", "userHandle" to b64(ByteArray(16) { 2 }), "clientDataJSON" to clientCreate, "uv" to true))
        val clientHash = MessageDigest.getInstance("SHA-256").digest("synthetic browser data".toByteArray())
        val signed = NativeBridge.call("passkey_assert", json("rpId" to "example.test", "privateKey" to created.getString("privateKey"), "clientDataHash" to b64(clientHash), "uv" to true))
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(unb64(created.getString("publicKey"))))
        val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(publicKey); update(unb64(signed.getString("authenticatorData"))); update(clientHash) }
        assertTrue(verifier.verify(unb64(signed.getString("signature"))))
        assertArrayEquals(ByteArray(4), unb64(signed.getString("authenticatorData")).copyOfRange(33, 37))
    }
}

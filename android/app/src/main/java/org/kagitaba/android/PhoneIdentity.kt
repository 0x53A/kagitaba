package org.kagitaba.android

import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.Keep
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.KeyAgreement

@Keep
interface PhoneOperations {
    fun agree(point: ByteArray): ByteArray
    fun sign(message: ByteArray): ByteArray
}

/** Only EC private operations use platform crypto; payload/wrapping crypto remains Rust. */
class PhoneIdentity(private val context: Context) {
    companion object {
        const val ERROR = "Phone key operation failed. Authenticate again or use another enrolled key."
        const val PREFIX = "kagitaba.strongbox.v1."
        const val DEFAULT_SECONDS = 60
        fun validTimeout(seconds: Int) = seconds in 1..300
    }
    data class Key(val alias: String, val publicInfo: JSONObject, val seconds: Int)
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val stateGate = Any()
    private var session: Operations? = null
    private var handle: String? = null
    @Volatile private var info: JSONObject? = null
    @Volatile private var generation = 0L
    private var dialog: AlertDialog? = null
    @Volatile private var activity = java.lang.ref.WeakReference<FragmentActivity>(null)
    fun attach(value: FragmentActivity) { activity = java.lang.ref.WeakReference(value) }
    fun detach(host: FragmentActivity, owner: Vault, preserveSession: Boolean = false) {
        if (activity.get() !== host) return
        activity.clear()
        session?.cancelPrompt()
        if (!preserveSession) owner.lock()
    }
    fun publicInfo(): JSONObject = info ?: error("Unlock your wallet first")
    fun close() {
        val old = synchronized(stateGate) {
            generation++
            session?.close(); session = null
            val previous = handle; handle = null; info = null
            previous
        }
        val oldDialog = dialog; dialog = null
        android.os.Handler(Looper.getMainLooper()).post { oldDialog?.dismiss() }
        if (old != null) runCatching { NativeBridge.call("phone_close", json("identity" to old)) }
    }
    private fun read(alias: String): Key {
        val ks = store()
        val factory = KeyFactory.getInstance("EC", "AndroidKeyStore")
        val policies = listOf(".agreement" to KeyProperties.PURPOSE_AGREE_KEY, ".signing" to KeyProperties.PURPOSE_SIGN).map { (suffix, purpose) ->
            val privateKey = ks.getKey(alias + suffix, null) as PrivateKey
            val policy = factory.getKeySpec(privateKey, KeyInfo::class.java)
            check(policy.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX && policy.keySize == 256 &&
                policy.purposes == purpose && policy.isUserAuthenticationRequired &&
                policy.isUserAuthenticationRequirementEnforcedBySecureHardware && validTimeout(policy.userAuthenticationValidityDurationSeconds))
            policy
        }
        check(policies[0].userAuthenticationValidityDurationSeconds == policies[1].userAuthenticationValidityDurationSeconds)
        fun public(suffix: String) = ks.getCertificate(alias + suffix).publicKey.encoded
        fun pem(bytes: ByteArray) = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(bytes) + "\n-----END PUBLIC KEY-----\n"
        val enc = public(".agreement"); val sig = public(".signing")
        val id = MessageDigest.getInstance("SHA-256").digest(enc).joinToString("") { "%02x".format(it) }
        val seconds = policies[0].userAuthenticationValidityDurationSeconds
        return Key(alias, json("participantPem" to pem(enc), "signingPem" to pem(sig), "participantId" to id, "backend" to "strongbox", "authSeconds" to seconds), seconds)
    }
    fun available(candidates: JSONArray?): List<Key> {
        val ks = store()
        return ks.aliases().asSequence().filter { it.startsWith(PREFIX) && it.endsWith(".agreement") }
            .mapNotNull { runCatching { read(it.removeSuffix(".agreement")) }.getOrNull() }
            .filter { key -> candidates == null || (0 until candidates.length()).any { i ->
                val candidate = candidates.getJSONObject(i)
                fun der(pem: String) = Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""))
                listOf("participantPem", "signingPem").all { field ->
                    der(candidate.getString(field)).contentEquals(der(key.publicInfo.getString(field)))
                }
            } }.sortedBy { it.alias }.toList()
    }
    private fun generate(seconds: Int): Key {
        require(validTimeout(seconds))
        check(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        val alias = PREFIX + UUID.randomUUID()
        // Unique aliases; never overwrite existing keys. A partial failure leaves
        // no usable identity and cleans up only keys from this generation attempt.
        try {
            for ((suffix, purpose) in listOf(".agreement" to KeyProperties.PURPOSE_AGREE_KEY, ".signing" to KeyProperties.PURPOSE_SIGN)) {
                val builder = KeyGenParameterSpec.Builder(alias + suffix, purpose)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setIsStrongBoxBacked(true).setUnlockedDeviceRequired(true)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(seconds, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                if (purpose == KeyProperties.PURPOSE_SIGN) builder.setDigests(KeyProperties.DIGEST_SHA256)
                KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply { initialize(builder.build()) }.generateKeyPair()
            }
            return read(alias)
        } catch (e: Exception) {
            val ks = store()
            listOf(".agreement", ".signing").forEach { runCatching { ks.deleteEntry(alias + it) } }
            throw e
        }
    }
    fun authenticate(host: FragmentActivity, candidates: JSONArray?, owner: Vault, success: (ByteArray) -> Unit, failure: (String) -> Unit) {
        close(); attach(host)
        if (android.os.Build.VERSION.SDK_INT < 35) { failure("Phone StrongBox enrollment requires Android 15 or newer."); return }
        val captured = generation
        fun select(key: Key) {
            host.lifecycleScope.launch {
                val ops = Operations(key, owner)
                try {
                    synchronized(stateGate) { check(captured == generation); session = ops }
                    withContext(Dispatchers.IO) { ops.authorize() }
                    check(captured == generation && (context.applicationContext as KagitabaApp).vault === owner)
                    val request = key.publicInfo.toString().toByteArray()
                    val response = try { NativeBridge.openPhone(request, ops) } finally { request.fill(0) }
                    val opened = try { JSONObject(String(response)) } finally { response.fill(0) }
                    val nativeHandle = opened.getString("identity")
                    synchronized(stateGate) {
                        if (captured != generation || (context.applicationContext as KagitabaApp).vault !== owner) {
                            NativeBridge.call("phone_close", json("identity" to nativeHandle)); error(ERROR)
                        }
                        handle = nativeHandle
                        info = opened.put("backend", "strongbox").put("authSeconds", key.seconds)
                    }
                    success(nativeHandle.toByteArray())
                } catch (e: Exception) {
                    ops.close()
                    if (captured == generation) { close(); failure(ERROR) }
                }
            }
        }
        host.lifecycleScope.launch {
            try {
                val keys = withContext(Dispatchers.IO) { available(candidates) }
                if (captured != generation) return@launch
                val labels = keys.map { "${it.publicInfo.getString("participantId").take(16)} · ${it.seconds}s" }.toMutableList()
                if (candidates == null) labels.add("Create phone key…")
                if (labels.isEmpty()) { failure("No enrolled StrongBox key on this installation. Export a phone enrollment request and enroll it using an existing participant."); return@launch }
                dialog = AlertDialog.Builder(host).setTitle("Phone StrongBox key").setItems(labels.toTypedArray()) { _, index ->
                    if (index < keys.size) select(keys[index]) else {
                        val layout = LinearLayout(host).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 20, 32, 20) }
                        layout.addView(TextView(host).apply { text = "Authentication window in seconds (1–300). Fixed for these keys after creation. Default: 60.\nKeep another enrolled key for recovery; uninstalling loses this identity." })
                        val timeout = EditText(host).apply { inputType = InputType.TYPE_CLASS_NUMBER; setText(DEFAULT_SECONDS.toString()); isSaveEnabled = false; layout.addView(this) }
                        dialog = AlertDialog.Builder(host).setTitle("Create StrongBox keys").setView(layout).setNegativeButton("Cancel", null).setPositiveButton("Create", null).create().also { d ->
                            d.setOnShowListener { d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                                val seconds = timeout.text.toString().toIntOrNull()
                                if (seconds == null || !validTimeout(seconds)) { timeout.error = "Enter 1–300 seconds"; return@setOnClickListener }
                                d.dismiss()
                                host.lifecycleScope.launch {
                                    try {
                                        val key = withContext(Dispatchers.IO) { generate(seconds) }
                                        if (captured == generation) select(key)
                                    } catch (_: Exception) { if (captured == generation) failure("StrongBox key creation failed. Check device support and screen lock. No software fallback was used.") }
                                }
                            } }
                            d.show()
                        }
                    }
                }.setNegativeButton("Cancel", null).show()
            } catch (_: Exception) { if (captured == generation) failure(ERROR) }
        }
    }
    @Keep
    inner class Operations(private val key: Key, private val owner: Vault) : PhoneOperations {
        private val active = AtomicBoolean(true)
        private val gate = Any()
        private var pending: CountDownLatch? = null
        private var prompt: BiometricPrompt? = null
        fun close() {
            active.set(false)
            cancelPrompt()
        }
        fun cancelPrompt() {
            synchronized(gate) { pending?.countDown() }
            android.os.Handler(Looper.getMainLooper()).post { prompt?.cancelAuthentication(); prompt = null }
        }
        fun authorize() {
            check(Looper.myLooper() != Looper.getMainLooper())
            check(active.get())
            val latch = CountDownLatch(1)
            val accepted = AtomicBoolean(false)
            synchronized(gate) { check(active.get()); pending = latch }
            android.os.Handler(Looper.getMainLooper()).post {
                val host = activity.get()
                if (!active.get() || host == null || !host.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || (context.applicationContext as KagitabaApp).vault !== owner) { latch.countDown(); return@post }
                try {
                prompt = BiometricPrompt(host, host.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(code: Int, message: CharSequence) { latch.countDown() }
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (active.get()) { accepted.set(true); (context.applicationContext as KagitabaApp).touch() }
                        latch.countDown()
                    }
                }).also { it.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Authorize Kagitaba")
                    .setSubtitle("Phone key · ${key.seconds} second authentication window")
                    .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL).build()) }
                } catch (_: Exception) { latch.countDown() }
            }
            try { latch.await() } finally { synchronized(gate) { if (pending === latch) pending = null } }
            check(active.get() && accepted.get()) { ERROR }
        }
        private fun <T> operation(block: () -> T): T {
            check(active.get()) { ERROR }
            return try { block() } catch (_: UserNotAuthenticatedException) { authorize(); check(active.get()); block() }
        }
        override fun agree(point: ByteArray): ByteArray = operation {
            require(point.size == 65 && point[0] == 4.toByte())
            val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65))), parameters))
            val agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
            agreement.init(store().getKey(key.alias + ".agreement", null) as PrivateKey)
            agreement.doPhase(peer, true)
            agreement.generateSecret().also { if (!active.get()) { it.fill(0); error(ERROR) } }
        }
        override fun sign(message: ByteArray): ByteArray = operation {
            // Let initSign select Android's Keystore signature provider for this
            // non-exportable handle. AndroidKeyStore itself registers ECDH/key
            // management; ECDSA is registered by its companion provider.
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(store().getKey(key.alias + ".signing", null) as PrivateKey)
            signature.update(message)
            signature.sign().also { check(active.get()) { ERROR } }
        }
    }
}

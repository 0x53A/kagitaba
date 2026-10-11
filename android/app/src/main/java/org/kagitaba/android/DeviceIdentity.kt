package org.kagitaba.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/** The only platform crypto: a non-exportable, authentication-bound wrapping key. */
class DeviceIdentity(private val context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "identity.json"))
    private val alias = "kagitaba.identity.v1"
    val enrolled get() = file.baseFile.exists()
    private val aad = "Kagitaba/Android/v1/device-identity".toByteArray()
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        fun generate(strong: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setIsStrongBoxBacked(strong).build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
        }
        return try { generate(true) } catch (_: StrongBoxUnavailableException) { generate(false) }
    }
    fun authenticate(activity: FragmentActivity, onSuccess: (ByteArray) -> Unit, onError: (String) -> Unit) {
        try {
            val existing = if (enrolled) JSONObject(String(file.readFully())) else null
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            if (existing == null) cipher.init(Cipher.ENCRYPT_MODE, key())
            else cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, unb64(existing.getString("iv"))))
            val prompt = BiometricPrompt(activity, activity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { onError("Authentication cancelled or unavailable. Unlock your device and try again.") }
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    var clear: ByteArray? = null
                    var stage = "device authorization"
                    try {
                        // Some device-credential implementations omit the
                        // CryptoObject in the callback. The original Cipher is
                        // the same Keystore operation; doFinal still requires
                        // its hardware authentication token and fails closed.
                        val authenticated = result.cryptoObject?.cipher ?: cipher
                        // Keystore update operations, including AAD, must wait
                        // for the operation's authentication token.
                        authenticated.updateAAD(aad)
                        if (existing == null) {
                            stage = "identity generation"
                            val identity = NativeBridge.call("identity_generate")
                            clear = unb64(identity.getString("identity"))
                            stage = "identity protection"
                            val encrypted = authenticated.doFinal(clear)
                            val record = json("version" to 1, "iv" to b64(authenticated.iv), "ciphertext" to b64(encrypted),
                                "participantPem" to identity.getString("participantPem"), "participantId" to identity.getString("participantId"),
                                "signingPem" to identity.getString("signingPem"), "signingId" to identity.getString("signingId"))
                            var stream: java.io.FileOutputStream? = null
                            stage = "identity storage"
                            try { stream = file.startWrite(); stream.write(record.toString().toByteArray()); file.finishWrite(stream) }
                            catch (e: Exception) { file.failWrite(stream); throw e }
                        } else { stage = "identity decryption"; clear = authenticated.doFinal(unb64(existing.getString("ciphertext"))) }
                        stage = "session unlock"
                        onSuccess(clear!!.copyOf())
                    } catch (e: Exception) {
                        val category = when (e) {
                            is android.security.keystore.UserNotAuthenticatedException -> "device authentication required"
                            is android.security.keystore.KeyPermanentlyInvalidatedException -> "device key invalidated"
                            is javax.crypto.AEADBadTagException -> "identity authentication failed"
                            is IllegalStateException -> "operation unavailable"
                            is java.io.IOException -> "storage unavailable"
                            else -> "device operation failed"
                        }
                        onError("Could not complete $stage: $category.")
                    }
                    finally { clear?.fill(0) }
                }
            })
            prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(if (enrolled) "Unlock Kagitaba" else "Protect this installation")
                .setSubtitle("Use your fingerprint or device screen lock")
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL).build(), BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) { onError("Set up a secure device screen lock before using Kagitaba.") }
    }
    fun publicInfo(): JSONObject = JSONObject(String(file.readFully())).apply { remove("iv"); remove("ciphertext") }
    fun participant(): String = publicInfo().let {
        json("format" to "kagitaba-participant-1", "encryption" to it.getString("participantPem"), "signing" to it.getString("signingPem")).toString(2)
    }
}

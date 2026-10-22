package org.kagitaba.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Installation-owned Git credentials; independent of wallet participants. */
class DeviceToken(private val key: (Boolean) -> SecretKey = ::deviceTokenKey) {
    fun seal(token: String, context: String): String = safe {
        val clear = token.toByteArray(Charsets.UTF_8)
        try {
            require(clear.size <= 16384)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(true))
            cipher.updateAAD(context.toByteArray(Charsets.UTF_8))
            json("version" to 1, "iv" to b64(cipher.iv), "ciphertext" to b64(cipher.doFinal(clear))).toString()
        } finally { clear.fill(0) }
    }
    fun open(envelope: String, context: String): String = safe {
        require(envelope.length <= 65536)
        val data = JSONObject(envelope)
        require(data.getInt("version") == 1)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, unb64(data.getString("iv"))))
        cipher.updateAAD(context.toByteArray(Charsets.UTF_8))
        val clear = cipher.doFinal(unb64(data.getString("ciphertext")))
        try { String(clear, Charsets.UTF_8) } finally { clear.fill(0) }
    }
    private fun <T> safe(action: () -> T): T = try { action() } catch (_: Exception) {
        throw IllegalStateException(ERROR)
    }
    companion object {
        const val ERROR = "Device Git token unavailable. Re-enter it in Connection settings."
    }
}

@Synchronized
private fun deviceTokenKey(create: Boolean): SecretKey {
    val alias = "kagitaba.git-token.v1"
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey(alias, null) as? SecretKey)?.let { return it }
    check(create)
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256).setUserAuthenticationRequired(false).build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        .apply { init(spec) }.generateKey()
}

package org.kagitaba.android

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

class CallerPolicy(private val context: Context) {
    private val allowlist by lazy { context.assets.open("privileged-browsers.json").bufferedReader().use { it.readText() } }
    fun certificates(info: SigningInfo): Set<String> = info.apkContentsSigners.map {
        MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString(":") { byte -> "%02X".format(byte.toInt() and 255) }
    }.toSet()
    fun packageCertificates(name: String): Set<String> = certificates(context.packageManager.getPackageInfo(name,
        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())).signingInfo ?: error("Unsigned caller"))
    fun trustedBrowser(name: String, fingerprints: Set<String>): Boolean = JSONObject(allowlist).getJSONArray("apps").objects().any {
        val info = it.getJSONObject("info")
        info.getString("package_name") == name && fingerprints.isNotEmpty() &&
            info.getJSONArray("signatures").objects().map { signature -> signature.getString("cert_fingerprint_sha256") }.toSet().containsAll(fingerprints)
    }
    fun origin(info: CallingAppInfo): String {
        // getOrigin itself checks the browser package AND signing certificate.
        val web = info.getOrigin(allowlist)
        if (web != null) return exactOrigin(web).also { require(web.removeSuffix("/") == it) { "Invalid browser origin" } }
        val signers = info.signingInfo.apkContentsSigners
        require(signers.size == 1) { "Unsupported multi-signer app" }
        return "android:apk-key-hash:" + b64(MessageDigest.getInstance("SHA-256").digest(signers.single().toByteArray()))
    }
    fun authorizeRp(info: CallingAppInfo, rp: String): String {
        require(validRp(rp)) { "Invalid relying party" }
        val origin = origin(info)
        if (origin.startsWith("https://")) {
            // A privileged browser owns WebAuthn origin/RP and related-origin
            // validation. Do not undo its approved Related Origin Requests.
            return origin
        }
        require(assetLinks(rp, info.packageName, certificates(info.signingInfo))) { "This app is not associated with the passkey website" }
        return origin
    }
    private fun assetLinks(rp: String, packageName: String, fingerprints: Set<String>): Boolean {
        val connection = URL("https://$rp/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false; connection.connectTimeout = 8000; connection.readTimeout = 8000
        return try {
            if (connection.responseCode != 200) return false
            val bytes = connection.inputStream.use { it.readNBytes(262145) }
            if (bytes.size > 262144) return false
            assetLinksAuthorize(JSONArray(String(bytes)), packageName, fingerprints)
        } finally { connection.disconnect() }
    }
    companion object {
        fun validRp(rp: String): Boolean = rp.length in 1..253 && rp == rp.lowercase() && rp.split('.').all {
            it.length in 1..63 && it.first().isLetterOrDigit() && it.last().isLetterOrDigit() && it.all { c -> c in 'a'..'z' || c in '0'..'9' || c == '-' }
        }
        fun assetLinksAuthorize(statements: JSONArray, packageName: String, fingerprints: Set<String>): Boolean =
            fingerprints.isNotEmpty() && statements.objects().any {
                val target = it.optJSONObject("target") ?: return@any false
                it.optJSONArray("relation").strings().contains("delegate_permission/common.get_login_creds") &&
                    target.optString("namespace") == "android_app" && target.optString("package_name") == packageName &&
                    target.optJSONArray("sha256_cert_fingerprints").strings().map(String::uppercase).toSet().containsAll(fingerprints)
            }
    }
}

package org.kagitaba.android

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

class WalletItem(val id: String, val payload: JSONObject) {
    val entity: JSONObject get() = payload.getJSONObject("entity")
    val title: String get() = entity.optString("title", "Untitled")
    fun updateLogin(username: String, password: String) {
        val basic = credentials("basic-auth").first()
        for ((name, type, value) in listOf(Triple("username", "string", username), Triple("password", "concealed-string", password))) {
            val field = basic.optJSONObject(name) ?: json("fieldType" to type).also { basic.put(name, it) }
            field.put("value", value)
        }
    }
    fun credentials(type: String): List<JSONObject> = entity.optJSONArray("credentials").objects().filter { it.optString("type") == type }
    fun matches(origin: String): Boolean = entity.optJSONObject("scope")?.optJSONArray("urls").strings().any {
        runCatching { exactOrigin(it) == origin }.getOrDefault(false)
    }
    fun matchesApp(packageName: String, fingerprints: Set<String>): Boolean {
        // Our signed-certificate association is encrypted with the entry. Plain
        // imported bundle IDs are deliberately not enough to release a password.
        return entity.optJSONObject("kagitabaAndroid")?.optJSONArray("apps").objects().any {
            it.optString("package") == packageName && it.optJSONArray("certificates").strings().toSet().containsAll(fingerprints) && fingerprints.isNotEmpty()
        }
    }
    fun bindApp(packageName: String, fingerprints: Set<String>) {
        val extension = entity.optJSONObject("kagitabaAndroid") ?: JSONObject().also { entity.put("kagitabaAndroid", it) }
        val others = extension.optJSONArray("apps").objects().filter { it.optString("package") != packageName }
        extension.put("apps", JSONArray(others).put(json("package" to packageName, "certificates" to JSONArray(fingerprints.toList()))))
    }
    companion object {
        fun create(title: String, credential: JSONObject, origin: String? = null): WalletItem {
            val bytes = NativeBridge.random(16)
            val id = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
            return WalletItem(id, json("format" to "kagitaba-cxf", "version" to 1, "cxfVersion" to json("major" to 1, "minor" to 0),
                "kind" to "item", "entity" to json("id" to b64(bytes), "title" to title, "credentials" to JSONArray().put(credential),
                    "scope" to json("urls" to JSONArray(if (origin == null) emptyList<String>() else listOf(origin)), "androidApps" to JSONArray()))))
        }
        fun password(username: String, password: String): JSONObject = json("type" to "basic-auth",
            "username" to json("fieldType" to "string", "value" to username), "password" to json("fieldType" to "concealed-string", "value" to password))
    }
}
fun JSONArray?.objects(): List<JSONObject> = if (this == null) emptyList() else (0 until length()).mapNotNull { optJSONObject(it) }
fun JSONArray?.strings(): List<String> = if (this == null) emptyList() else (0 until length()).map { getString(it) }
fun exactOrigin(url: String): String {
    val uri = URI(url)
    require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null) { "An HTTPS website is required" }
    val port = if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"
    return "https://${uri.host.lowercase()}$port"
}

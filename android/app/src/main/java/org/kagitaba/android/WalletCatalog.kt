package org.kagitaba.android

import android.content.Context
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Public local wallet names/paths only. Every wallet owns its trust and Git state. */
class WalletCatalog(private val context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "wallets.json"))
    private var state = if (file.baseFile.exists()) JSONObject(String(file.readFully())) else json("wallets" to JSONArray())
    init {
        if (!file.baseFile.exists() && File(context.noBackupFilesDir, "wallet-state.json").exists()) {
            state.getJSONArray("wallets").put(json("id" to "legacy", "name" to "Existing wallet"))
            state.put("selected", "legacy"); persist()
        }
    }
    data class Wallet(val id: String, val name: String)
    @Synchronized fun all(): List<Wallet> = state.getJSONArray("wallets").objects().map { Wallet(it.getString("id"), it.getString("name")) }
        .filter { File(root(it.id), "wallet-state.json").exists() }
    @Synchronized fun selected(): String? = state.optString("selected").takeIf { it.isNotEmpty() }
    @Synchronized fun name(id: String): String = state.getJSONArray("wallets").objects().firstOrNull { it.getString("id") == id }?.getString("name") ?: "Wallet"
    fun root(id: String): File {
        require(id == "legacy" || id.matches(Regex("[0-9a-f]{32}")))
        return if (id == "legacy") context.noBackupFilesDir else File(context.noBackupFilesDir, "wallets/$id").also { it.mkdirs() }
    }
    @Synchronized fun add(name: String): String {
        val id = NativeBridge.random(16).joinToString("") { "%02x".format(it.toInt() and 255) }
        state.getJSONArray("wallets").put(json("id" to id, "name" to name.ifEmpty { "Wallet" }))
        persist(); return id
    }
    @Synchronized fun select(id: String) {
        require(state.getJSONArray("wallets").objects().any { it.getString("id") == id })
        state.put("selected", id); persist()
    }
    private fun persist() {
        var stream: java.io.FileOutputStream? = null
        try { stream = file.startWrite(); stream.write(state.toString().toByteArray()); file.finishWrite(stream) }
        catch (e: Exception) { file.failWrite(stream); throw e }
    }
}

package org.kagitaba.android

import org.json.JSONArray
import org.json.JSONObject

/** Listing hints only. Entry use must load and validate the encrypted payload. */
data class WalletIndexRow(val id: String, val title: String, val kind: String, val usernames: List<String>, val scopes: List<String>, val password: Boolean, val totp: Boolean, val passkey: Boolean)
class WalletIndex(rows: JSONArray) {
    val entries = rows.objects().map { row -> WalletIndexRow(row.getString("id"), row.getString("title"), row.getString("kind"), row.getJSONArray("usernames").let { a -> (0 until a.length()).map { a.getString(it) } }, row.getJSONArray("scopes").let { a -> (0 until a.length()).map { a.getString(it) } }, row.getBoolean("password"), row.getBoolean("totp"), row.getBoolean("passkey")) }
    val collections: List<CollectionNavigation.Node>
    private val membershipPaths = mutableMapOf<String, MutableList<String>>()
    fun collectionPaths(entryId: String): List<String> = membershipPaths[entryId].orEmpty().sorted()
    init {
        val accessible = entries.filter { it.kind == "item" }.map { it.id }.toSet()
        val nodes = mutableListOf<CollectionNavigation.Node>()
        fun walk(owner: String, node: JSONObject, depth: Int, ancestors: List<String>) {
            val links = node.getJSONArray("entries").let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }
            val path = ancestors + node.getString("title").ifEmpty { "Untitled collection" }
            for (entry in links.intersect(accessible)) membershipPaths.getOrPut(entry) { mutableListOf() }.add(path.joinToString(" › "))
            nodes.add(CollectionNavigation.Node("$owner:${node.getString("id")}", node.getString("title").ifEmpty { "Untitled collection" }, depth, links.intersect(accessible), node.getInt("unresolved") + links.count { it !in accessible }))
            for (child in node.getJSONArray("children").objects()) walk(owner, child, depth + 1, path)
        }
        for (row in rows.objects()) if (row.getString("kind") == "collection") row.optJSONObject("collection")?.let { walk(row.getString("id"), it, 0, emptyList()) }
        collections = nodes
    }
}

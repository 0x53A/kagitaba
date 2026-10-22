package org.kagitaba.android

import org.json.JSONObject
import java.util.Base64

/** Membership only; a link never authorizes decryption or credential use. */
object CollectionNavigation {
    data class Node(val key: String, val title: String, val depth: Int, val items: Set<String>, val unavailable: Int)
    fun nodes(entries: List<WalletItem>): List<Node> {
        val accessible=entries.filter { it.payload.optString("kind")=="item" }.map { it.id }.toSet()
        val result=mutableListOf<Node>()
        fun walk(owner: String, entity: JSONObject, depth: Int) {
            val members=mutableSetOf<String>(); var unavailable=0
            for(link in entity.optJSONArray("items").objects()) {
                val id=if(link.has("account")) null else runCatching {
                    val text=link.getString("item")
                    require(Regex("[A-Za-z0-9_-]+={0,2}").matches(text))
                    val bytes=Base64.getUrlDecoder().decode(text);require(bytes.size==16)
                    bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
                }.getOrNull()
                if(id!=null&&id in accessible)members.add(id) else unavailable++
            }
            result.add(Node("$owner:${entity.getString("id")}",entity.optString("title").ifEmpty{"Untitled collection"},depth,members,unavailable))
            for(child in entity.optJSONArray("subCollections").objects())walk(owner,child,depth+1)
        }
        for(entry in entries)if(entry.payload.optString("kind")=="collection")walk(entry.id,entry.entity,0)
        return result
    }
    fun usernames(item: WalletItem): List<String> = item.entity.optJSONArray("credentials").objects().mapNotNull {
        when(it.optString("type")) {
            "basic-auth" -> it.optJSONObject("username")?.optString("value")
            "passkey", "totp" -> it.optString("username")
            else -> null
        }?.takeIf { value -> value.isNotEmpty() }
    }.distinct()
}

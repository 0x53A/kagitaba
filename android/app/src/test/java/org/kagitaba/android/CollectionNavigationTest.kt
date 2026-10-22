package org.kagitaba.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class CollectionNavigationTest {
    private fun id(byte: Int)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16){byte.toByte()})
    @Test fun nestedCollectionsResolveOnlyDirectAccessibleUnqualifiedLinks() {
        val a="11".repeat(16);val b="22".repeat(16)
        val item=WalletItem(a,JSONObject("""{"kind":"item","entity":{"title":"A","credentials":[{"type":"basic-auth","username":{"value":"alice"}},{"type":"passkey","username":"alice"}]}}"""))
        val second=WalletItem(b,JSONObject("""{"kind":"item","entity":{"title":"B"}}"""))
        val collection=WalletItem("33".repeat(16),JSONObject("""{"kind":"collection","entity":{"id":"${id(51)}","title":"Root","items":[{"item":"${id(17)}=="},{"item":"${id(34)}","account":"external"},{"item":"${id(68)}"}],"subCollections":[{"id":"${id(85)}","title":"Child","items":[{"item":"${id(34)}"}]}]}}"""))
        val nodes=CollectionNavigation.nodes(listOf(item,second,collection))
        assertEquals(setOf(a),nodes[0].items);assertEquals(2,nodes[0].unavailable)
        assertEquals(setOf(b),nodes[1].items);assertEquals(1,nodes[1].depth)
        assertEquals(setOf(a,b),nodes.flatMap{it.items}.toSet())
        assertEquals(listOf("alice"),CollectionNavigation.usernames(item))
    }
}

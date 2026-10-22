package org.kagitaba.android
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
class WalletIndexTest {
    @Test fun summariesContainNoCredentialsAndCollectionsKeepUnavailableCounts() {
        val index=WalletIndex(JSONArray("""[
          {"id":"a","title":"Entry","kind":"item","usernames":["alice"],"scopes":["https://example.test"],"password":true,"totp":false,"passkey":false},
          {"id":"root","title":"Folder","kind":"collection","usernames":[],"scopes":[],"password":false,"totp":false,"passkey":false,
           "collection":{"id":"collection","title":"Folder","entries":["a","missing"],"unresolved":2,"children":[{"id":"child","title":"Child","entries":["a"],"unresolved":0,"children":[]}]}}
        ]"""))
        assertEquals(listOf("alice"),index.entries[0].usernames)
        assertEquals(listOf("https://example.test"),index.entries[0].scopes)
        assertTrue(index.entries[0].password)
        assertEquals(setOf("a"),index.collections[0].items)
        assertEquals(3,index.collections[0].unavailable)
        assertEquals(1,index.collections[1].depth)
        assertEquals(setOf("a"),index.collections[1].items)
        assertEquals(listOf("Folder", "Folder › Child"), index.collectionPaths("a"))
        assertTrue(index.collectionPaths("missing").isEmpty())
    }
}

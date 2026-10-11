package org.kagitaba.android

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class PolicyTest {
    @Test fun originMatchingDoesNotBroadenToOtherSchemesPortsOrSubdomains() {
        assertEquals("https://example.test", exactOrigin("https://example.test:443/login"))
        assertEquals("https://example.test:8443", exactOrigin("https://example.test:8443/login"))
        for (url in listOf("http://example.test", "https://user@example.test", "javascript:example.test")) {
            assertThrows(Exception::class.java) { exactOrigin(url) }
        }
        val item = WalletItem("synthetic", json("entity" to json("scope" to json("urls" to JSONArray(listOf("https://example.test/login"))))))
        assertTrue(item.matches("https://example.test"))
        assertFalse(item.matches("https://sub.example.test"))
        assertFalse(item.matches("https://example.test:8443"))
    }
    @Test fun nativeAppAssociationRequiresCorrectPackageRelationAndEverySigner() {
        val links = JSONArray("""[{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"org.example","sha256_cert_fingerprints":["AA:BB"]}}]""")
        assertTrue(CallerPolicy.assetLinksAuthorize(links, "org.example", setOf("AA:BB")))
        assertFalse(CallerPolicy.assetLinksAuthorize(links, "org.evil", setOf("AA:BB")))
        assertFalse(CallerPolicy.assetLinksAuthorize(links, "org.example", setOf("AA:BB", "CC:DD")))
        assertFalse(CallerPolicy.assetLinksAuthorize(links, "org.example", emptySet()))
        links.getJSONObject(0).put("relation", JSONArray(listOf("delegate_permission/common.handle_all_urls")))
        assertFalse(CallerPolicy.assetLinksAuthorize(links, "org.example", setOf("AA:BB")))
    }
    @Test fun importedPackageNameAloneDoesNotAuthorizePasswordRelease() {
        val item = WalletItem("synthetic", json("entity" to json("scope" to json("androidApps" to JSONArray().put(json("bundleId" to "org.example"))))))
        assertFalse(item.matchesApp("org.example", setOf("AA:BB")))
        item.bindApp("org.example", setOf("AA:BB"))
        assertTrue(item.matchesApp("org.example", setOf("AA:BB")))
        assertFalse(item.matchesApp("org.example", setOf("CC:DD")))
    }
    @Test fun rejectsUnsupportedAlgorithmsAndExtensions() {
        val options = JSONObject("""{"pubKeyCredParams":[{"type":"public-key","alg":-7}]}""")
        Passkeys.validateOptions(options, true)
        options.put("extensions", json("payment" to JSONObject()))
        assertThrows(Exception::class.java) { Passkeys.validateOptions(options, true) }
        options.remove("extensions")
        options.getJSONArray("pubKeyCredParams").getJSONObject(0).put("alg", -257)
        assertThrows(Exception::class.java) { Passkeys.validateOptions(options, true) }
    }
    @Test fun relyingPartyIdsRejectUrlsPortsAndMalformedLabels() {
        for (rp in listOf("example.test", "login.example.test")) assertTrue(CallerPolicy.validRp(rp))
        for (rp in listOf("https://example.test", "example.test:443", "-example.test", "example..test", "EXAMPLE.test", "")) assertFalse(CallerPolicy.validRp(rp))
    }
    @Test fun malformedAllowListsMustNotBecomeUnrestrictedRequests() {
        for (allowed in listOf<Any>("invalid", JSONObject.NULL, JSONArray().put(1),
            JSONArray().put(json("type" to "public-key", "id" to "")))) {
            assertThrows(Exception::class.java) {
                Passkeys.validateOptions(json("allowCredentials" to allowed), false)
            }
        }
    }
}

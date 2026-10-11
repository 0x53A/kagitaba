package org.kagitaba.android

import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class PasskeyExtensionsTest {
    private fun options(extensions: JSONObject) = json("extensions" to extensions,
        "allowCredentials" to JSONArray().put(json("type" to "public-key", "id" to "AQ")))
    private fun account(state: JSONObject? = null): Passkeys.Account {
        val credential = json("type" to "passkey", "credentialId" to "AQ", "rpId" to "example.test", "key" to "synthetic")
        if (state != null) credential.put(PasskeyExtensions.STATE, state)
        return Passkeys.Account(WalletItem("synthetic", json("entity" to json("credentials" to JSONArray().put(credential),
            "unknown" to "preserve"))), credential)
    }

    @Test fun registrationAdvertisesAndPersistsPrfWithoutLeakingItsKey() {
        val extensions = PasskeyExtensions.parse(options(json("credProps" to true,
            "prf" to json("eval" to json("first" to "", "second" to "AQ==")),
            "largeBlob" to json("support" to "required"))), true)
        val args = JSONObject()
        extensions.creationRequest(args)
        assertTrue(args.getBoolean("prf"))
        assertEquals("AQ", args.getJSONObject("prfEval").getString("second"))
        val native = json("prfKey" to b64(ByteArray(32) { 7 }), "prfResults" to json("first" to "result"))
        assertEquals(native.getString("prfKey"), extensions.creationState(native)!!.getString("prfKey"))
        val result = extensions.creationResults(native)
        assertTrue(result.getJSONObject("prf").getBoolean("enabled"))
        assertTrue(result.getJSONObject("credProps").getBoolean("rk"))
        assertTrue(result.getJSONObject("largeBlob").getBoolean("supported"))
        assertFalse(result.toString().contains(native.getString("prfKey")))
    }

    @Test fun prfSelectsCredentialSpecificInputsAndFallsBackToEval() {
        val request = options(json("prf" to json("eval" to json("first" to "Ag"),
            "evalByCredential" to json("AQ==" to json("first" to "Aw")))))
        val selected = account(json("version" to 1, "prfKey" to b64(ByteArray(32))))
        val args = JSONObject()
        PasskeyExtensions.parse(request, false).assertionRequest(args, selected.credential)
        assertEquals("Aw", args.getJSONObject("prfEval").getString("first"))
        request.getJSONObject("extensions").getJSONObject("prf").put("evalByCredential", JSONObject())
        PasskeyExtensions.parse(request, false).assertionRequest(args, selected.credential)
        assertEquals("Ag", args.getJSONObject("prfEval").getString("first"))
    }

    @Test fun prfWithoutSavedSecretNeverInventsResultsOrAReplacementKey() = runBlocking {
        val extensions = PasskeyExtensions.parse(options(json("prf" to json("eval" to json("first" to "")))), false)
        val selected = account()
        val args = JSONObject()
        extensions.assertionRequest(args, selected.credential)
        assertEquals(0, args.length())
        val result = extensions.assertionResults(JSONObject(), selected) { fail("Unexpected write") }
        assertEquals(0, result.getJSONObject("prf").length())
    }

    @Test fun largeBlobRoundTripsAndOnlyReportsSuccessAfterPersistence() = runBlocking {
        val selected = account(json("version" to 1, "prfKey" to b64(ByteArray(32)), "future" to "retained"))
        val original = selected.item.payload.toString()
        var saved: WalletItem? = null
        val write = PasskeyExtensions.parse(options(json("largeBlob" to json("write" to "AAEC"))), false)
        val result = write.assertionResults(JSONObject(), selected) {
            assertEquals(original, selected.item.payload.toString())
            saved = it
        }
        assertTrue(result.getJSONObject("largeBlob").getBoolean("written"))
        val updated = saved!!
        assertEquals("preserve", updated.entity.getString("unknown"))
        val credential = updated.credentials("passkey").single()
        assertEquals("retained", credential.getJSONObject(PasskeyExtensions.STATE).getString("future"))
        assertEquals(b64(ByteArray(32)), credential.getJSONObject(PasskeyExtensions.STATE).getString("prfKey"))
        val read = PasskeyExtensions.parse(options(json("largeBlob" to json("read" to true))), false)
        assertEquals("AAEC", read.assertionResults(JSONObject(), Passkeys.Account(updated, credential)) {
            fail("Read must not save")
        }.getJSONObject("largeBlob").getString("blob"))
        assertFalse(read.assertionResults(JSONObject(), account()) {}.getJSONObject("largeBlob").has("blob"))
        try {
            write.assertionResults(JSONObject(), selected) { throw IllegalStateException("synthetic save failure") }
            fail("A failed save must not return success")
        } catch (_: IllegalStateException) { }
        assertEquals(original, selected.item.payload.toString())
    }

    @Test fun rejectsMalformedOrInapplicableExtensionRequests() {
        val invalid = listOf(
            true to json("prf" to json("evalByCredential" to JSONObject())),
            true to json("prf" to json("eval" to json("second" to "AQ"))),
            true to json("prf" to json("eval" to json("first" to "!"))),
            true to json("credProps" to "true"),
            true to json("largeBlob" to json("read" to false)),
            true to json("largeBlob" to json("support" to "anything")),
            false to json("largeBlob" to json("support" to "required")),
            false to json("largeBlob" to json("read" to false, "write" to "")),
            false to json("prf" to json("evalByCredential" to json("Ag" to json("first" to "")))),
            false to json("prf" to json("evalByCredential" to json("AQ" to json("first" to ""), "AQ==" to json("first" to ""))))
        )
        for ((create, extensions) in invalid) assertThrows(PasskeyExtensionException::class.java) {
            PasskeyExtensions.parse(options(extensions), create)
        }
        for (extension in listOf(json("largeBlob" to json("write" to "")),
            json("prf" to json("evalByCredential" to json("AQ" to json("first" to "")))))) {
            val request = options(extension).put("allowCredentials", JSONArray())
            assertThrows(PasskeyExtensionException::class.java) { PasskeyExtensions.parse(request, false) }
        }
        assertThrows(PasskeyExtensionException::class.java) {
            PasskeyExtensions.parse(options(json("largeBlob" to json("write" to b64(ByteArray(32769))))), false)
        }
    }

    @Test fun unknownStateVersionAndMalformedSecretFailClosed() {
        for (state in listOf(json("version" to 2), json("version" to 1, "prfKey" to "AQ"))) {
            assertThrows(PasskeyExtensionException::class.java) {
                PasskeyExtensions.parse(options(json("prf" to JSONObject())), false)
                    .assertionRequest(JSONObject(), account(state).credential)
            }
        }
    }

    @Test fun diagnosticsListExtensionNamesButNeverValuesOrControlCharacters() {
        val error = assertThrows(PasskeyExtensionException::class.java) {
            PasskeyExtensions.parse(options(json("payment" to "secret value", "uvm" to true, "evil\nname" to "secret")), true)
        }
        assertTrue(error.userMessage.contains("payment"))
        assertTrue(error.userMessage.contains("uvm"))
        assertFalse(error.userMessage.contains("secret"))
        assertFalse(error.userMessage.contains('\n'))
    }
}

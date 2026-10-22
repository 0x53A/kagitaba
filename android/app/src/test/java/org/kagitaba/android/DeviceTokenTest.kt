package org.kagitaba.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.KeyGenerator

class DeviceTokenTest {
    private fun key() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test fun tokenSurvivesReopenWithoutParticipantIdentity() {
        val deviceKey = key()
        val saved = DeviceToken { create -> assertTrue(create); deviceKey }.seal("synthetic-token", "wallet/url/user")
        val reopened = DeviceToken { create -> assertFalse(create); deviceKey }
        assertEquals("synthetic-token", reopened.open(saved, "wallet/url/user"))
        assertFalse(saved.contains("synthetic-token"))
        assertNotEquals(saved, DeviceToken { deviceKey }.seal("synthetic-token", "wallet/url/user"))
    }

    @Test fun tamperingOtherContextsAndLostDeviceKeyFailWithFixedMessage() {
        val deviceKey = key()
        val tokens = DeviceToken { deviceKey }
        val saved = tokens.seal("synthetic-token", "wallet/url/user")
        fun rejected(action: () -> Unit) {
            try { action(); fail("must reject") } catch (e: IllegalStateException) { assertEquals(DeviceToken.ERROR, e.message) }
        }
        for (context in listOf("other-wallet/url/user", "wallet/other-url/user", "wallet/url/other-user")) {
            rejected { tokens.open(saved, context) }
        }
        val corrupted = JSONObject(saved).apply {
            val ciphertext = unb64(getString("ciphertext")); ciphertext[0] = (ciphertext[0].toInt() xor 1).toByte()
            put("ciphertext", b64(ciphertext))
        }
        rejected { tokens.open(corrupted.toString(), "wallet/url/user") }
        rejected { DeviceToken { key() }.open(saved, "wallet/url/user") }
        rejected { DeviceToken { error("private-error") }.open(saved, "wallet/url/user") }
        rejected { tokens.open("malformed-secret", "wallet/url/user") }
    }
}

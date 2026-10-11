package org.kagitaba.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/** No physical device, PIN guessing, or YubiKey provisioning. */
@RunWith(AndroidJUnit4::class)
class PivInteropTest {
    class Card(initialSlots: List<Int> = listOf(0x82, 0x83)) : PivTransport {
        private val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val keys = initialSlots.associateWith { generator.generateKeyPair() }.toMutableMap()
        var generations = 0
        var managementAuthenticated = false
        var verifies = 0
        private var verified = false
        private fun fixed(n: BigInteger): ByteArray = n.toByteArray().let { bytes -> ByteArray(32).also { out ->
            val count = minOf(32, bytes.size); bytes.copyInto(out, 32 - count, bytes.size - count)
        } }
        private fun point(key: ECPublicKey) = byteArrayOf(4) + fixed(key.w.affineX) + fixed(key.w.affineY)
        override fun exchange(command: ByteArray): ByteArray {
            val ins = command[1].toInt() and 255
            val slot = command[3].toInt() and 255
            val body = when (ins) {
                0xa4 -> { verified = false; byteArrayOf() }
                0xf8 -> byteArrayOf(0, 0, 0, 42)
                0xf7 -> {
                    if (slot == 0x9b) return byteArrayOf(1, 1, 3, 0x90.toByte(), 0)
                    val pair = keys[slot] ?: return byteArrayOf(0x6a, 0x88.toByte())
                    byteArrayOf(1, 1, 0x11, 4, 67, 0x86.toByte(), 65) + point(pair.public as ECPublicKey)
                }
                0x20 -> {
                    verifies++
                    if (!command.copyOfRange(5, 11).contentEquals("123456".toByteArray())) return byteArrayOf(0x63, 0xc2.toByte())
                    verified = true; byteArrayOf()
                }
                0x87 -> {
                    check(verified)
                    if (slot == 0x9b) {
                        if ((command[7].toInt() and 255) == 0x81) return byteArrayOf(0x7c, 10, 0x81.toByte(), 8) + ByteArray(8) + byteArrayOf(0x90.toByte(), 0)
                        val expected = javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding").run {
                            init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(ByteArray(24) { (it % 8 + 1).toByte() }, "DESede")); doFinal(ByteArray(8))
                        }
                        check(command.copyOfRange(9, command.size).contentEquals(expected))
                        managementAuthenticated = true
                        return byteArrayOf(0x90.toByte(), 0)
                    }
                    val input = command.copyOfRange(11, command.size)
                    val encryption = keys.getValue(slot)
                    val output = if ((command[9].toInt() and 255) == 0x85) {
                        val params = (encryption.public as ECPublicKey).params
                        val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, input.copyOfRange(1, 33)), BigInteger(1, input.copyOfRange(33, 65))), params))
                        KeyAgreement.getInstance("ECDH").apply { init(encryption.private); doPhase(peer, true) }.generateSecret()
                    } else Signature.getInstance("NONEwithECDSA").run { initSign(keys.getValue(slot).private); update(input); sign() }
                    byteArrayOf(0x7c, (output.size + 2).toByte(), 0x82.toByte(), output.size.toByte()) + output
                }
                0x47 -> {
                    check(verified && managementAuthenticated && slot !in keys)
                    val key = generator.generateKeyPair(); keys[slot] = key; generations++
                    byteArrayOf(0x7f, 0x49, 67, 0x86.toByte(), 65) + point(key.public as ECPublicKey)
                }
                else -> error("Unexpected APDU")
            }
            return body + byteArrayOf(0x90.toByte(), 0)
        }
    }
    private fun command(card: Card, fields: JSONObject): JSONObject {
        val request = fields.toString().toByteArray()
        try { return JSONObject(String(NativeBridge.openPiv(request, card))) } finally { request.fill(0) }
    }
    private fun open(card: Card, pin: String = "123456"): JSONObject {
        val request = json("encryptionSlot" to 0x82, "signingSlot" to 0x83, "pin" to pin).toString().toByteArray()
        try { return JSONObject(String(NativeBridge.openPiv(request, card))) } finally { request.fill(0) }
    }
    @Test fun hardwareParticipantDecryptsSignsAndClosesWithoutExportingItsKeys() {
        val card = Card()
        val info = open(card)
        val identity = info.getString("identity")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val path = File(context.cacheDir, "piv-test-${System.nanoTime()}")
        try {
            var snapshot = NativeBridge.call("store_create", json("identity" to identity, "path" to path.absolutePath, "device" to info.getJSONObject("device")))
            assertEquals(0x82, snapshot.getJSONObject("devices").getJSONObject(info.getString("participantId")).getInt("encryptionSlot"))
            val item = WalletItem.create("Synthetic PIV login", WalletItem.password("alice", "synthetic-password"), "https://example.com")
            val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(), "recipients" to JSONArray().put(info.getString("participantPem"))))
            snapshot = NativeBridge.call("store_save", encrypted.put("identity", identity).put("path", path.absolutePath)
                .put("root", snapshot.getString("root")).put("checkpoint", snapshot.getString("head")).put("entryId", item.id))
            val opened = NativeBridge.call("entry_decrypt", json("identity" to identity, "primary" to encrypted.getString("primary"),
                "grant" to encrypted.getJSONObject("grants").getString(info.getString("participantId"))))
            val decoded = WalletItem(item.id, JSONObject(opened.getString("payload")))
            assertEquals(item.title, decoded.title)
            assertEquals("synthetic-password", decoded.credentials("basic-auth").single().getJSONObject("password").getString("value"))
            val verified = NativeBridge.call("store_open", json("path" to path.absolutePath, "root" to snapshot.getString("root"), "checkpoint" to snapshot.getString("head")))
            assertEquals(snapshot.getString("head"), verified.getString("head"))
            val wrapped = NativeBridge.call("local_encrypt", json("identity" to identity, "context" to "synthetic-git-url-user", "plaintext" to "synthetic-token"))
            assertEquals("synthetic-token", NativeBridge.call("local_decrypt", json("identity" to identity, "context" to "synthetic-git-url-user", "envelope" to wrapped.getString("envelope"))).getString("plaintext"))
            assertThrows(IllegalStateException::class.java) { NativeBridge.call("local_decrypt", json("identity" to identity, "context" to "different-user", "envelope" to wrapped.getString("envelope"))) }
            assertEquals(1, card.verifies)
        } finally { NativeBridge.call("piv_close", json("identity" to identity)); path.deleteRecursively() }
        assertThrows(IllegalStateException::class.java) { NativeBridge.call("local_encrypt", json("identity" to identity, "context" to "closed", "plaintext" to "synthetic")) }
    }
    @Test fun incorrectPinIsNotRetried() {
        val card = Card()
        val error = assertThrows(IllegalStateException::class.java) { open(card, "654321") }
        assertEquals("Incorrect PIV PIN. 2 attempts remain. No automatic retry.", error.message)
        assertEquals(1, card.verifies)
    }
    @Test fun detectionUsesActualKeysAndNonDefaultSlotsWithoutSendingPin() {
        val card = Card(listOf(0x88, 0x91))
        fun pem(slot: Int): String = "-----BEGIN PUBLIC KEY-----\n" + java.util.Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(card.keys.getValue(slot).public.encoded) + "\n-----END PUBLIC KEY-----\n"
        val candidate = json("participantPem" to pem(0x88), "signingPem" to pem(0x91), "name" to "Synthetic participant",
            "device" to json("serial" to "42", "encryptionSlot" to 0x88, "signingSlot" to 0x91))
        val match = command(card, json("op" to "inspect", "candidates" to JSONArray().put(candidate))).getJSONArray("matches").getJSONObject(0)
        assertEquals(0x88, match.getInt("encryptionSlot")); assertEquals(0x91, match.getInt("signingSlot"))
        candidate.remove("device")
        assertEquals(1, command(card, json("op" to "inspect", "candidates" to JSONArray().put(candidate))).getJSONArray("matches").length())
        candidate.put("signingPem", NativeBridge.call("identity_generate").getString("signingPem"))
        assertEquals(0, command(card, json("op" to "inspect", "candidates" to JSONArray().put(candidate))).getJSONArray("matches").length())
        assertEquals(0, card.verifies); assertEquals(0, card.generations)
    }
    @Test fun provisioningRequiresConsentAndBothSlotsEmptyAndPreservesExistingKeys() {
        val card = Card()
        val old = card.keys.getValue(0x82).public.encoded
        val request = json("op" to "provision", "serial" to "42", "encryptionSlot" to 0x84, "signingSlot" to 0x82,
            "pin" to "123456", "managementKey" to "010203040506070801020304050607080102030405060708", "confirmed" to true)
        assertThrows(IllegalStateException::class.java) { command(card, request) }
        assertEquals(0, card.verifies); assertEquals(0, card.generations)
        request.put("signingSlot", 0x85).put("confirmed", false)
        assertThrows(IllegalStateException::class.java) { command(card, request) }
        assertEquals(0, card.generations)
        val result = command(card, request.put("confirmed", true))
        assertEquals(2, card.generations)
        assertArrayEquals(old, card.keys.getValue(0x82).public.encoded)
        NativeBridge.call("piv_close", json("identity" to result.getString("identity")))
    }
}

package org.kagitaba.android

import androidx.annotation.Keep
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement

/** Synthetic JCA callback verifies the packaged JNI path, not StrongBox hardware. */
@RunWith(AndroidJUnit4::class)
class PhoneInteropTest {
    @Keep
    class SyntheticPhone : PhoneOperations {
        private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val encryption = pair()
        val signing = pair()
        var agreements = 0
        var signatures = 0
        var fail = false
        var shortResult = false
        var signingEntered: java.util.concurrent.CountDownLatch? = null
        var signingResume: java.util.concurrent.CountDownLatch? = null
        fun pem(bytes: ByteArray) = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(bytes) + "\n-----END PUBLIC KEY-----\n"
        fun open(): JSONObject {
            val request = json("participantPem" to pem(encryption.public.encoded), "signingPem" to pem(signing.public.encoded)).toString().toByteArray()
            return JSONObject(String(NativeBridge.openPhone(request, this)))
        }
        override fun agree(point: ByteArray): ByteArray {
            agreements++
            check(!fail) { "Synthetic sensitive exception must not escape JNI" }
            if (shortResult) return ByteArray(31)
            val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, point.copyOfRange(1,33)), BigInteger(1, point.copyOfRange(33,65))), params))
            return KeyAgreement.getInstance("ECDH").apply { init(encryption.private); doPhase(peer, true) }.generateSecret()
        }
        override fun sign(message: ByteArray): ByteArray {
            signatures++
            signingEntered?.countDown()
            signingResume?.await()
            check(!fail) { "Synthetic sensitive exception must not escape JNI" }
            return Signature.getInstance("SHA256withECDSA").apply { initSign(signing.private); update(message) }.sign()
        }
    }
    @Test fun callbackDecryptsSignsIndexesAndClosedHandleCannotBeReused() {
        val phone = SyntheticPhone()
        val info = phone.open()
        val handle = info.getString("identity")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val path = File(context.cacheDir, "phone-interop-${java.util.UUID.randomUUID()}")
        try {
            val created = NativeBridge.call("store_create", json("identity" to handle, "path" to path.absolutePath))
            val item = WalletItem.create("Phone test", WalletItem.password("alice", "synthetic"), "https://example.test")
            val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(), "recipients" to JSONArray().put(info.getString("participantPem"))))
            fun decrypt() = NativeBridge.call("entry_decrypt", json("identity" to handle, "primary" to encrypted.getString("primary"), "grant" to encrypted.getJSONObject("grants").getString(info.getString("participantId"))))
            assertEquals("Phone test", JSONObject(decrypt().getString("payload")).getJSONObject("entity").getString("title"))
            val saved = NativeBridge.call("store_save", JSONObject(encrypted.toString()).put("identity", handle).put("path", path.absolutePath).put("root", created.getString("root")).put("checkpoint", created.getString("head")).put("entryId", item.id))
            fun catalog(head: String) = NativeBridge.call("store_catalog", json("identity" to handle, "path" to path.absolutePath, "root" to created.getString("root"), "checkpoint" to head))
            val index = catalog(saved.getString("head"))
            assertEquals("Phone test", index.getJSONArray("rows").getJSONObject(0).getString("title"))
            val calls = phone.agreements
            val signs = phone.signatures
            val cached = catalog(index.getString("head"))
            assertEquals(index.getString("head"), cached.getString("head"))
            assertEquals(calls + 1, phone.agreements)
            assertEquals(signs, phone.signatures)
            phone.fail = true
            try { decrypt(); fail("callback exception accepted") } catch (e: IllegalStateException) { assertEquals(PhoneIdentity.ERROR, e.message) }
            phone.fail = false; phone.shortResult = true
            try { decrypt(); fail("short ECDH accepted") } catch (e: IllegalStateException) { assertEquals(PhoneIdentity.ERROR, e.message) }
            phone.shortResult = false
            assertTrue(decrypt().has("payload")) // Java exception was cleared; session is still usable.
            NativeBridge.call("phone_close", json("identity" to handle))
            val before = phone.agreements
            try { decrypt(); fail("closed handle accepted") } catch (e: IllegalStateException) { assertEquals(PhoneIdentity.ERROR, e.message) }
            assertEquals(before, phone.agreements)
        } finally {
            NativeBridge.call("phone_close", json("identity" to handle))
            path.deleteRecursively()
        }
    }
    @Test fun closingDuringSigningRejectsLateResultWithoutPublishingCommit() {
        val phone = SyntheticPhone()
        val info = phone.open()
        val handle = info.getString("identity")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val path = File(context.cacheDir, "phone-cancel-${java.util.UUID.randomUUID()}")
        val entered = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        val finished = java.util.concurrent.CountDownLatch(1)
        var caught: Throwable? = null
        try {
            val created = NativeBridge.call("store_create", json("identity" to handle, "path" to path.absolutePath))
            val item = WalletItem.create("Cancelled write", WalletItem.password("alice", "synthetic"), "https://example.test")
            val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(), "recipients" to JSONArray().put(info.getString("participantPem"))))
            phone.signingEntered = entered; phone.signingResume = resume
            Thread {
                try { NativeBridge.call("store_save", encrypted.put("identity", handle).put("path", path.absolutePath).put("root", created.getString("root")).put("checkpoint", created.getString("head")).put("entryId", item.id)) }
                catch (e: Throwable) { caught = e }
                finally { finished.countDown() }
            }.start()
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            NativeBridge.call("phone_close", json("identity" to handle))
            resume.countDown()
            assertTrue(finished.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertNotNull(caught)
            val reopened = NativeBridge.call("store_open", json("path" to path.absolutePath, "root" to created.getString("root"), "checkpoint" to created.getString("head")))
            assertEquals(created.getString("head"), reopened.getString("head"))
        } finally {
            resume.countDown()
            NativeBridge.call("phone_close", json("identity" to handle))
            finished.await(5, java.util.concurrent.TimeUnit.SECONDS)
            path.deleteRecursively()
        }
    }

}

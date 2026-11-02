package org.kagitaba.android

import android.content.Intent
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyAgreement

/** Disposable emulator only, PIN 123456. Tests real auth policy, not StrongBox. */
@RunWith(AndroidJUnit4::class)
class PhoneAuthenticationTest {
    @Test fun keystoreSigningHandleSelectsAndroidSignatureProvider() {
        assumeTrue(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val alias = "kagitaba-test-sign-${java.util.UUID.randomUUID()}"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias + ".signing", KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).build())
        }.generateKeyPair()
        val ops = PhoneIdentity(context).Operations(PhoneIdentity.Key(alias, JSONObject(), 60), context.vault)
        try {
            val message = "Synthetic provider selection".toByteArray()
            val signature = ops.sign(message)
            assertTrue(Signature.getInstance("SHA256withECDSA").apply {
                initVerify(key.public); update(message)
            }.verify(signature))
        } finally { ops.close(); ks.deleteEntry(alias + ".signing") }
    }
    @Test fun timedOperationReauthenticatesAndClosingCancelsPendingPrompt() {
        assumeTrue(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val ui = UiDevice.getInstance(instrumentation)
        val host = instrumentation.startActivitySync(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)) as MainActivity
        val phone = PhoneIdentity(context)
        instrumentation.runOnMainSync { phone.attach(host) }
        val alias = "kagitaba-test-auth-${java.util.UUID.randomUUID()}"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        // Test fixture explicitly uses emulator Keystore. Production generation
        // always requests StrongBox and verifies its security level.
        val key = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias + ".agreement", KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(true).setUnlockedDeviceRequired(true)
                .setUserAuthenticationParameters(2, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL).build())
        }.generateKeyPair()
        val signing = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias + ".signing", KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true).setUnlockedDeviceRequired(true)
                .setUserAuthenticationParameters(2, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL).build())
        }.generateKeyPair()
        val message = "Synthetic wallet signature".toByteArray()
        val ops = phone.Operations(PhoneIdentity.Key(alias, JSONObject(), 2), context.vault)
        val peer = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val public = peer.public as ECPublicKey
        fun coordinate(value: java.math.BigInteger): ByteArray {
            val raw = value.toByteArray()
            return ByteArray(32).also { raw.takeLast(32).toByteArray().copyInto(it, 32 - minOf(raw.size, 32)) }
        }
        val point = byteArrayOf(4) + coordinate(public.w.affineX) + coordinate(public.w.affineY)
        val expected = KeyAgreement.getInstance("ECDH").apply { init(peer.private); doPhase(key.public, true) }.generateSecret()
        try {
            repeat(3) { attempt ->
                Thread.sleep(3000) // Deliberately expire the synthetic 2-second window.
                val done = CountDownLatch(1)
                var result: ByteArray? = null
                var error: Throwable? = null
                Thread {
                    try { result = if (attempt == 0) ops.agree(point) else ops.sign(message) } catch (e: Throwable) { error = e } finally { done.countDown() }
                }.start()
                val prompted = ui.wait(Until.hasObject(By.clazz("android.widget.EditText")), 30000)
                if (!prompted) throw AssertionError("Device-credential prompt on attempt $attempt", error)
                if (attempt < 2) {
                    ui.findObject(By.clazz("android.widget.EditText")).text = "123456"
                    ui.pressEnter()
                    assertTrue(done.await(30, TimeUnit.SECONDS))
                    assertNull(error)
                    if (attempt == 0) assertArrayEquals(expected, result)
                    else assertTrue(Signature.getInstance("SHA256withECDSA").apply {
                        initVerify(signing.public); update(message)
                    }.verify(result))
                    result?.fill(0)
                } else {
                    ops.close()
                    assertTrue(done.await(5, TimeUnit.SECONDS))
                    assertNotNull(error)
                    assertNull(result)
                }
            }
        } finally {
            ops.close(); expected.fill(0)
            ks.deleteEntry(alias + ".agreement")
            ks.deleteEntry(alias + ".signing")
            instrumentation.runOnMainSync { host.finish() }
        }
    }
}

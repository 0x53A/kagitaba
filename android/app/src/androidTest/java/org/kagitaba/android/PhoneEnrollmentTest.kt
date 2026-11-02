package org.kagitaba.android

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.*
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class PhoneEnrollmentTest {
    @Test fun enrollmentDefaultsToSixtySecondsAndNeverFallsBackWithoutStrongBox() {
        assumeTrue(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assumeFalse(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        fun aliases() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().asSequence().filter { it.startsWith(PhoneIdentity.PREFIX) }.toSet()
        val before = aliases()
        val device = UiDevice.getInstance(instrumentation)
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        fun click(text: String) {
            assertTrue("Missing screen control: $text", device.wait(Until.hasObject(By.text(text)), 5000))
            device.findObject(By.text(text)).click()
        }
        click("Create enrollment request")
        click("Choose phone or YubiKey")
        click("Phone · StrongBox")
        click("Create phone key…")
        assertTrue(device.wait(Until.hasObject(By.text("60")), 5000))
        device.findObject(By.res("android", "button1")).click()
        assertTrue(device.wait(Until.hasObject(By.text("StrongBox key creation failed. Check device support and screen lock. No software fallback was used.")), 5000))
        assertEquals(before, aliases())
        device.pressBack()
    }
}

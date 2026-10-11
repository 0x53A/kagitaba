package org.kagitaba.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@org.junit.Ignore("Legacy software-participant UI is disabled; retain coverage for that backend.")
class AutofillFlowTest {
    @Test fun platformAutofillSavesAndFillsNativeLoginWithVerifiedAppBinding() {
        assumeTrue("Disposable emulator only", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val ui = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        assumeTrue("Install the separate autofill-probe APK", context.packageManager.getLaunchIntentForPackage("org.kagitaba.autofillprobe") != null)
        fun click(text: String, button: Boolean = true) {
            val matchingText = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(text), java.util.regex.Pattern.CASE_INSENSITIVE)
            val query = if (button) By.text(matchingText).clazz("android.widget.Button") else By.text(matchingText)
            val found = ui.wait(Until.hasObject(query), 15000)
            assertTrue("Missing: $text; labels: ${ui.findObjects(By.clazz("android.widget.TextView")).map { it.text }}", found)
            ui.findObject(query).click()
        }
        fun pin() {
            assertTrue(ui.wait(Until.hasObject(By.clazz("android.widget.EditText")), 15000))
            ui.findObject(By.clazz("android.widget.EditText")).text = "123456"; ui.pressEnter()
        }
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        if (!DeviceIdentity(context).enrolled) { click("Set up this installation"); pin() }
        else if (!context.vault.unlocked) { click("Unlock wallet"); pin() }
        if (!context.vault.connected) click("Create a new wallet")
        assertTrue(ui.wait(Until.hasObject(By.text("Your wallet")), 15000))
        ui.executeShellCommand("settings put secure autofill_service org.kagitaba.android/.PasswordAutofillService")
        val launch = context.packageManager.getLaunchIntentForPackage("org.kagitaba.autofillprobe")!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        context.startActivity(launch)
        val input = By.pkg("org.kagitaba.autofillprobe").clazz("android.widget.EditText")
        assertTrue(ui.wait(Until.hasObject(input), 15000))
        var fields = ui.findObjects(input)
        fields[0].text = "autofill-alice"; fields[1].text = "autofill-test-only"
        click("Submit synthetic login")
        click("Save", false)
        click("Unlock to continue"); pin()
        click("Save password")
        val deadline = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < deadline && runBlocking { context.vault.entries() }.none { it.title == "org.kagitaba.autofillprobe" }) Thread.sleep(100)
        val saved = runBlocking { context.vault.entries() }.first { it.title == "org.kagitaba.autofillprobe" }
        assertTrue(saved.matchesApp("org.kagitaba.autofillprobe", CallerPolicy(context).packageCertificates("org.kagitaba.autofillprobe")))
        assertTrue(ui.wait(Until.gone(By.text("Save password").clazz("android.widget.Button")), 15000))
        ui.executeShellCommand("am force-stop org.kagitaba.autofillprobe")
        ui.executeShellCommand("am start -n org.kagitaba.autofillprobe/.LoginActivity")
        assertTrue(ui.wait(Until.hasObject(input), 15000))
        ui.findObjects(input)[0].click()
        click("Unlock Kagitaba", false)
        click("Unlock to continue"); pin()
        click("org.kagitaba.autofillprobe")
        // A response-level authentication may ask the user to pick its dataset.
        if (ui.wait(Until.hasObject(By.text("org.kagitaba.autofillprobe")), 2500)) click("org.kagitaba.autofillprobe", false)
        assertTrue(ui.wait(Until.hasObject(By.text("autofill-alice")), 15000))
        fields = ui.findObjects(input)
        assertEquals("autofill-alice", fields[0].text)
    }
}

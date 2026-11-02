package org.kagitaba.android

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PendingIntentHandler
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real provider activities/PendingIntents, synthetic wallet and successful-auth boundary.
 * Does not provision StrongBox or bypass authentication in production code.
 */
@RunWith(AndroidJUnit4::class)
@android.annotation.SuppressLint("RestrictedApi")
class PhoneProviderHandoffTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val app get() = instrumentation.targetContext.applicationContext as KagitabaApp
    private val ui = UiDevice.getInstance(instrumentation)
    private fun set(target: Any, name: String, value: Any?) {
        target.javaClass.getDeclaredField(name).apply { isAccessible = true }.set(target, value)
    }
    private fun get(target: Any, name: String): Any? = target.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(target)
    private fun waitUntil(message: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + 15_000_000_000L
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(50)
        assertTrue(message, condition())
    }
    private fun destroyed(activity: Activity) {
        waitUntil("Activity destroyed") { activity.isDestroyed }
        // isDestroyed may become true before the application's onDestroy has
        // finished. Wait for that main-thread transaction before inspecting state.
        instrumentation.waitForIdleSync()
    }
    private fun result(): Intent {
        waitUntil("Provider result") { ProviderProbeActivity.result != null }
        assertEquals(Activity.RESULT_OK, ProviderProbeActivity.result)
        return ProviderProbeActivity.response ?: error("Missing provider response")
    }
    private fun launch(pending: PendingIntent, request: Intent): ProviderActivity {
        val monitor = instrumentation.addMonitor(ProviderActivity::class.java.name, null, false)
        try {
            ProviderProbeActivity.result = null; ProviderProbeActivity.response = null
            app.startActivity(Intent(app, ProviderProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra("pending", pending).putExtra("request", request))
            return (instrumentation.waitForMonitorWithTimeout(monitor, 15000) as? ProviderActivity
                ?: error("Provider activity did not open")).also { instrumentation.waitForIdleSync() }
        } finally { instrumentation.removeMonitor(monitor) }
    }
    private inner class Fixture {
        val directory = File(app.cacheDir, "phone-handoff-${java.util.UUID.randomUUID()}").apply { mkdirs() }
        val phone = PhoneInteropTest.SyntheticPhone()
        val caller = android.service.credentials.CallingAppInfo(app.packageName,
            app.packageManager.getPackageInfo(app.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())).signingInfo!!, null)
        val option = GetPasswordOption()
        val wallet: Vault
        val original = app.vault
        init {
            val info = phone.open()
            try {
                val path = File(directory, "wallet").absolutePath
                val created = NativeBridge.call("store_create", json("path" to path, "identity" to info.getString("identity")))
                val item = WalletItem.create("Handoff fixture", WalletItem.password("alice", "synthetic-password"), null)
                item.bindApp(app.packageName, CallerPolicy(app).certificates(caller.signingInfo))
                val encrypted = NativeBridge.call("entry_encrypt", json("entryId" to item.id, "payload" to item.payload.toString(),
                    "recipients" to JSONArray().put(info.getString("participantPem"))))
                val saved = NativeBridge.call("store_save", encrypted.put("identity", info.getString("identity")).put("path", path)
                    .put("root", created.getString("root")).put("checkpoint", created.getString("head")).put("entryId", item.id))
                File(directory, "wallet-state.json").writeText(json("root" to saved.getString("root"), "head" to saved.getString("head")).toString())
            } finally { NativeBridge.call("phone_close", json("identity" to info.getString("identity"))) }
            wallet = Vault(app, directory, "synthetic-handoff")
            instrumentation.runOnMainSync { original.lock(); app.vault = wallet }
        }
        fun begin(): ProviderActivity {
            val request = android.service.credentials.BeginGetCredentialRequest.Builder().setCallingAppInfo(caller)
                .addBeginGetCredentialOption(android.service.credentials.BeginGetCredentialOption("password", PasswordCredential.TYPE_PASSWORD_CREDENTIAL, option.candidateQueryData)).build()
            return launch(RequestTickets.issue(app, RequestTickets.Ticket("unlock")),
                Intent().putExtra("android.service.credentials.extra.BEGIN_GET_CREDENTIAL_REQUEST", request))
        }
        fun authenticate(activity: ProviderActivity) {
            // Model completion of phone authentication, using the real JNI callback backend.
            // Reflection stays in instrumentation; no release/debug auth bypass is added.
            val info = phone.open()
            instrumentation.runOnMainSync {
                wallet.device.close()
                set(wallet.device, "usingPhone", true)
                val identity = get(wallet.device, "phone") as PhoneIdentity
                set(identity, "info", info.put("backend", "strongbox"))
                set(identity, "handle", info.getString("identity"))
                identity.attach(activity)
                wallet.unlock(info.getString("identity").toByteArray())
                set(activity, "approvedEpoch", wallet.epoch)
            }
            runBlocking { wallet.finishUnlock() }
        }
        fun process(activity: ProviderActivity) = instrumentation.runOnMainSync {
            ProviderActivity::class.java.getDeclaredMethod("process").apply { isAccessible = true }.invoke(activity)
        }
        fun handoff(): PendingIntent {
            val first = begin()
            assertFalse(wallet.unlocked)
            authenticate(first)
            val epoch = wallet.epoch
            process(first)
            val response = result().getParcelableExtra("android.service.credentials.extra.BEGIN_GET_CREDENTIAL_RESPONSE",
                android.service.credentials.BeginGetCredentialResponse::class.java) ?: error("Missing candidate response")
            destroyed(first)
            assertTrue("Successful handoff must keep its session", wallet.unlocked)
            assertEquals(epoch, wallet.epoch)
            val entry = PasswordCredentialEntry.fromCredentialEntry(response.credentialEntries.single()) ?: error("Missing password choice")
            return entry.pendingIntent
        }
        fun select(pending: PendingIntent): ProviderActivity {
            val frameworkOption = android.credentials.CredentialOption.Builder(option.type, option.requestData, option.candidateQueryData).build()
            val request = android.service.credentials.GetCredentialRequest(caller, listOf(frameworkOption))
            return launch(pending, Intent().putExtra("android.service.credentials.extra.GET_CREDENTIAL_REQUEST", request))
        }
        fun close() {
            instrumentation.runOnMainSync { wallet.lock(); app.vault = original }
            directory.deleteRecursively()
        }
    }
    private fun withFixture(block: (Fixture) -> Unit) {
        assumeTrue("Disposable emulator only", Build.HARDWARE in setOf("ranchu", "goldfish"))
        ui.wakeUp()
        val fixture = Fixture()
        try { block(fixture) } finally { fixture.close() }
    }
    @Test fun successfulUnlockReturnsUsableChoiceAfterActivityDestruction() = withFixture { fixture ->
        val choice = fixture.handoff()
        val selection = fixture.select(choice)
        assertNotNull("Returned ticket survives handoff", get(selection, "ticket"))
        fixture.authenticate(selection)
        fixture.process(selection)
        assertTrue(ui.wait(Until.hasObject(By.text("Fill password").clazz("android.widget.Button")), 15000))
        ui.findObject(By.text("Fill password").clazz("android.widget.Button")).click()
        val credential = PendingIntentHandler.retrieveGetCredentialResponse(result())!!.credential as PasswordCredential
        assertEquals("alice", credential.id)
        assertEquals("synthetic-password", credential.password)
        destroyed(selection)
        assertFalse("Final credential result must not retain the phone session", fixture.wallet.unlocked)
    }
    @Test fun explicitLockIdleExpiryAndScreenOffStillInvalidateReturnedChoices() {
        for (mode in listOf("explicit", "idle", "screen")) withFixture { fixture ->
            val choice = fixture.handoff()
            if (mode == "screen") {
                ui.sleep()
                waitUntil("Screen-off revokes session") { !fixture.wallet.unlocked }
                ui.wakeUp()
                ui.executeShellCommand("wm dismiss-keyguard")
            } else instrumentation.runOnMainSync {
                if (mode == "idle") (get(app, "idleLock") as Runnable).run() else fixture.wallet.lock()
            }
            assertFalse(fixture.wallet.unlocked)
            val selection = fixture.select(choice)
            assertNull("Lock must invalidate the picker ticket", get(selection, "ticket"))
            instrumentation.runOnMainSync { selection.finish() }
            destroyed(selection)
        }
    }
    @Test fun abandonedAuthenticationStillLocksAndClearsTickets() = withFixture { fixture ->
        val first = fixture.begin()
        fixture.authenticate(first)
        val pending = RequestTickets.issue(app, RequestTickets.Ticket("password", "unused"))
        instrumentation.runOnMainSync { first.finish() }
        destroyed(first)
        assertFalse(fixture.wallet.unlocked)
        val selection = fixture.select(pending)
        assertNull(get(selection, "ticket"))
        instrumentation.runOnMainSync { selection.finish() }
        destroyed(selection)
    }
}

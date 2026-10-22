package org.kagitaba.android

import android.content.ContextWrapper
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import kotlinx.coroutines.runBlocking
import org.eclipse.jgit.api.Git
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class WalletWorkflowTest {
    @Test fun enrollmentSessionDoesNotChangeSavedWalletCatalogOrSelection() {
        assumeTrue("Session test is for disposable emulators only", android.os.Build.MODEL.contains("sdk"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val app = instrumentation.targetContext.applicationContext as KagitabaApp
        val catalog = File(app.noBackupFilesDir, "wallets.json")
        val before = catalog.takeIf { it.exists() }?.readBytes()
        val selected = app.wallets.selected()
        val original = app.vault.walletId
        instrumentation.runOnMainSync {
            try {
                repeat(2) {
                    app.beginEnrollment()
                    assertEquals("", app.vault.walletId)
                    assertFalse(app.vault.connected)
                    assertEquals(selected, app.wallets.selected())
                    app.endEnrollment()
                    assertEquals(original, app.vault.walletId)
                }
            } finally { app.endEnrollment() }
        }
        assertArrayEquals(before, catalog.takeIf { it.exists() }?.readBytes())
    }

    @Test fun clonedWalletsExposeVerifiedParticipantsBeforeUnlockAndKeepSeparateTrust(): Unit = runBlocking {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KagitabaApp
        val fixture = File(app.cacheDir, "wallet-workflows-${System.nanoTime()}").apply { mkdirs() }
        val isolated = object : ContextWrapper(app) { override fun getNoBackupFilesDir(): File = fixture }
        try {
            val catalog = WalletCatalog(isolated)
            val heads = mutableSetOf<String>()
            val epochs = mutableSetOf<Long>()
            for (name in listOf("Personal test", "Work test")) {
                val identity = NativeBridge.call("identity_generate")
                val source = File(fixture, "source-$name")
                val hint = json("version" to 1, "serial" to "42", "encryptionSlot" to 0x88, "signingSlot" to 0x91)
                val initial = NativeBridge.call("store_create", json("identity" to identity.getString("identity"), "path" to source.absolutePath, "device" to hint))
                val id = catalog.add(name)
                val root = catalog.root(id)
                val repository = File(root, "wallet")
                Git.cloneRepository().setURI(source.toURI().toString()).setDirectory(repository).setBranch("wallet").call().close()
                // No identity, PIN, or hardware operation is needed for clone verification.
                val verified = NativeBridge.call("store_connect", json("path" to repository.absolutePath))
                assertEquals(initial.getString("head"), verified.getString("head"))
                File(root, "wallet-state.json").writeText(json("root" to verified.getString("root"), "head" to verified.getString("head")).toString())
                val wallet = Vault(app, root, id)
                assertFalse(wallet.unlocked)
                val candidate = wallet.unlockCandidates().getJSONObject(0)
                assertEquals(identity.getString("participantPem"), candidate.getString("participantPem"))
                assertEquals(identity.getString("signingPem"), candidate.getString("signingPem"))
                assertEquals(0x88, candidate.getJSONObject("device").getInt("encryptionSlot"))
                heads.add(wallet.settings().getString("head")); epochs.add(wallet.epoch)
            }
            assertEquals(2, heads.size); assertEquals(2, epochs.size)
            assertEquals(listOf("Personal test", "Work test"), WalletCatalog(isolated).all().map { it.name })
            assertThrows(IllegalArgumentException::class.java) { catalog.root("../../outside") }
            Unit
        } finally { fixture.deleteRecursively() }
    }
    @Test fun homeListsWalletsAndAddExistingStartsWithRepositoryNotPin() {
        assumeTrue("UI test is for disposable emulators only", android.os.Build.MODEL.contains("sdk"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val ui = UiDevice.getInstance(instrumentation)
        ui.wakeUp()
        if (context.getSystemService(android.app.KeyguardManager::class.java).isKeyguardLocked) {
            ui.swipe(540, 1800, 540, 400, 30)
            assertTrue("Disposable emulator PIN screen", ui.wait(Until.hasObject(By.res("com.android.systemui", "pinEntry")), 10000))
            ui.executeShellCommand("input text 123456"); ui.pressEnter()
            assertTrue(ui.wait(Until.gone(By.res("com.android.systemui", "pinEntry")), 10000))
        }
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        assertTrue(ui.wait(Until.hasObject(By.text("Your wallets")), 10000))
        captureScreen("review-home.png")
        assertTrue(ui.hasObject(By.text("Create new")))
        ui.findObject(By.text("Add existing")).click()
        assertTrue(ui.wait(Until.hasObject(By.text("Wallet name")), 5000))
        ui.findObject(By.clazz("android.widget.EditText")).text = "Synthetic clone workflow"
        ui.findObject(By.text("Continue")).click()
        assertTrue(ui.wait(Until.hasObject(By.text("Git repository HTTPS URL")), 5000))
        assertFalse(ui.hasObject(By.text("YubiKey PIV PIN")))
        assertFalse(ui.hasObject(By.text("Generate keys")))
        captureScreen("review-connection.png")
        ui.pressBack() // Hide the name field's keyboard if it remained open.
        if (ui.hasObject(By.text("Git repository HTTPS URL"))) {
            ui.findObject(By.text("← Back")).click()
        }
        assertTrue(ui.wait(Until.hasObject(By.text("Your wallets")), 5000))
    }

    /** Draw synthetic test screens without changing the app's FLAG_SECURE policy. */
    private fun captureScreen(name: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.waitForIdleSync()
        instrumentation.runOnMainSync {
            val activity = androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry.getInstance()
                .getActivitiesInStage(androidx.test.runner.lifecycle.Stage.RESUMED).filterIsInstance<MainActivity>().single()
            val root = activity.window.decorView
            val bitmap = android.graphics.Bitmap.createBitmap(root.width, root.height, android.graphics.Bitmap.Config.ARGB_8888)
            root.draw(android.graphics.Canvas(bitmap))
            File(activity.cacheDir, name).outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
            bitmap.recycle()
        }
    }
}

package org.kagitaba.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class EditorSyncTest {
    @Test fun entryEditorDisablesSyncUntilReturningHome() {
        assumeTrue("Disposable emulator only", android.os.Build.MODEL.contains("sdk"))
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KagitabaApp
        val directory = File(app.cacheDir, "editor-sync-${System.nanoTime()}").apply { mkdirs() }
        // Public synthetic connection metadata only; clicking disabled Sync must
        // never attempt to open this nonexistent repository or contact a remote.
        File(directory, "wallet-state.json").writeText(json("head" to "synthetic", "url" to "https://example.test/wallet").toString())
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val vault = Vault(app, directory, "synthetic")
                    SecureActivity::class.java.getDeclaredMethod("bindVault", Vault::class.java).apply { isAccessible = true }.invoke(activity, vault)
                    MainActivity::class.java.getDeclaredField("opened").apply { isAccessible = true }.setBoolean(activity, true)
                    MainActivity::class.java.getDeclaredMethod("edit", WalletItem::class.java).apply { isAccessible = true }.invoke(activity, null)
                    fun views(view: android.view.View): List<android.view.View> = listOf(view) +
                        if (view is android.view.ViewGroup) (0 until view.childCount).flatMap { views(view.getChildAt(it)) } else emptyList()
                    val controls = views(activity.window.decorView)
                    val sync = controls.single { it.contentDescription == "Synchronize" }
                    val title = controls.filterIsInstance<android.widget.EditText>().first()
                    title.setText("Unsaved synthetic title")
                    assertFalse(sync.isEnabled)
                    // A real touch cannot dispatch a disabled button.
                    assertEquals("Unsaved synthetic title", title.text.toString())
                    MainActivity::class.java.getDeclaredMethod("home", String::class.java).apply { isAccessible = true }.invoke(activity, null)
                    assertTrue(views(activity.window.decorView).single { it.contentDescription == "Synchronize" }.isEnabled)
                }
            }
        } finally { directory.deleteRecursively() }
    }
}

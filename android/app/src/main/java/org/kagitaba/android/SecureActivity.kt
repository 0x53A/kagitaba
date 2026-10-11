package org.kagitaba.android

import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.*
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.activity.OnBackPressedCallback
import kotlinx.coroutines.launch

open class SecureActivity : FragmentActivity() {
    protected lateinit var vault: Vault
    protected lateinit var panel: LinearLayout
    protected lateinit var notice: TextView
    protected var busy = false
    private var backAction: (() -> Unit)? = null
    private val activeWork = mutableSetOf<kotlinx.coroutines.Job>()
    private val onLock: () -> Unit = {
        activeWork.toList().forEach { it.cancel() }
        if (!isFinishing) locked()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        bindVault((application as KagitabaApp).vault)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { if (!busy) backAction?.invoke() ?: finish() }
        })
    }
    protected fun bindVault(value: Vault) {
        if (::vault.isInitialized) vault.lockListeners.remove(onLock)
        vault = value; vault.lockListeners.add(onLock)
    }
    override fun onDestroy() { vault.lockListeners.remove(onLock); super.onDestroy() }
    override fun onUserInteraction() { super.onUserInteraction(); (application as KagitabaApp).touch() }
    protected open fun locked() { screen("Wallet locked"); button("Unlock", primary = true) { authenticate { recreate() } } }
    protected fun screen(title: String, back: (() -> Unit)? = null) {
        backAction = back
        val spacing = (20 * resources.displayMetrics.density).toInt()
        panel = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(spacing, spacing, spacing, spacing) }
        val scroll = ScrollView(this).apply { isFillViewport = true; addView(panel) }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(WalletTheme.background) }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(spacing, 8, spacing, 8); setBackgroundColor(WalletTheme.surface)
        }
        header.addView(TextView(this).apply {
            text = "KAGITABA"; textSize = 14f; letterSpacing = .16f; gravity = android.view.Gravity.CENTER_VERTICAL
            typeface = android.graphics.Typeface.MONOSPACE; setTextColor(WalletTheme.accent)
        }, LinearLayout.LayoutParams(0, WalletTheme.dp(this, 56), 1f))
        if (vault.unlocked) header.addView(Button(this).apply {
            text = "Lock"; WalletTheme.button(this); setOnClickListener { vault.lock() }
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, WalletTheme.dp(context, 48))
        })
        root.addView(header)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(root)
        if (back != null) button("← Back") { back() }
        label(title, 27)
        notice = label("")
        notice.setTextColor(WalletTheme.accent)
        notice.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
    }
    protected fun label(text: String, size: Int = 16): TextView = TextView(this).also {
        it.text = text; it.textSize = size.toFloat(); it.setTextColor(if (size < 16) WalletTheme.muted else WalletTheme.ink)
        it.setPadding(0, WalletTheme.dp(this, 8), 0, WalletTheme.dp(this, 8)); panel.addView(it)
    }
    protected fun field(title: String, value: String = "", secret: Boolean = false): EditText {
        val heading = label(title, 14)
        return EditText(this).also {
            it.id = View.generateViewId(); heading.labelFor = it.id
            it.setText(value); it.isSingleLine = true; it.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            it.inputType = if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_CLASS_TEXT
            WalletTheme.field(it)
            it.isSaveEnabled = false; panel.addView(it)
        }
    }
    protected fun button(title: String, primary: Boolean = false, action: () -> Unit): Button = Button(this).also {
        it.text = title; WalletTheme.button(it, primary); it.setOnClickListener { if (!busy) action() }; panel.addView(it)
    }
    protected fun check(title: String, checked: Boolean): CheckBox = CheckBox(this).also { it.text = title; it.setTextColor(WalletTheme.ink); it.buttonTintList = android.content.res.ColorStateList.valueOf(WalletTheme.accent); it.isChecked = checked; panel.addView(it) }
    protected fun work(progress: String, block: suspend () -> Unit) {
        busy = true; notice.text = progress
        val job = lifecycleScope.launch {
            try { block() } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                notice.text = friendlyError(e)
            }
        }
        activeWork.add(job)
        job.invokeOnCompletion { activeWork.remove(job); busy = activeWork.isNotEmpty() }
    }
    protected fun authenticate(provision: Boolean = false, done: () -> Unit) {
        val target = vault
        work("Reading wallet participants…") {
            val candidates = if (target.connected) target.unlockCandidates() else null
            check((application as KagitabaApp).vault === target) { "Authentication expired" }
            target.device.authenticate(this@SecureActivity, candidates, provision, target, { bytes ->
                if ((application as KagitabaApp).vault !== target) { bytes.fill(0); target.device.close() }
                else { target.unlock(bytes); work("Opening wallet…") { target.finishUnlock(); done() } }
            }, { notice.text = it })
        }
    }
    protected suspend fun autoSync(): String? {
        if (vault.settings().optBoolean("autoSync") && vault.settings().has("url")) {
            notice.text = "Saved on this device. Synchronizing…"
            val result = try { vault.sync() } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                runCatching { vault.recordSyncFailure() }
                "Saved on this device. ${friendlyError(e)}"
            }
            notice.text = result
            return result
        }
        return null
    }
    private fun friendlyError(e: Exception): String = when (e) {
        is PasskeyExtensionException -> e.userMessage
        is org.eclipse.jgit.api.errors.TransportException -> "Connection failed. Check the HTTPS URL, username/token, network and repository access. Your fields are preserved."
        else -> {
            val message = e.message.orEmpty()
            // Only fixed application-owned messages; never expose native/Git/HTTP input.
            val safe = setOf("Wallet validation or storage failed", "Unlock your wallet first", "Remote wallet branch is missing",
                "Wallet histories diverged. No changes were discarded; resolve this on your computer.", "Only ES256 passkeys are supported",
                "This passkey extension is not supported yet", "This passkey already exists", "This app is not associated with the passkey website",
                "Use an HTTPS Git URL without embedded credentials", "An HTTPS website is required", "Invalid or unsupported cryptographic operation",
                "Authentication expired", "Wallet locked before upload",
                "The passkey changed while this request was open. Restart the request.",
                "Upload rejected. Synchronize again; remote history may have changed.",
                "A wallet is already connected", "Use synchronization for your connected wallet")
            PivErrors.message(message) ?: WalletErrors.nativeMessage(message) ?: if (message in safe) message else "Operation failed. Check unlock, enrollment, access grants and wallet trust; your inputs have been kept."
        }
    }
}

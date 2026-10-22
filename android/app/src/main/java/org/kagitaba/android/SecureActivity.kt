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
    private var touchNotice: TextView? = null
    private val onTouch: () -> Unit = { runOnUiThread { showTouchProgress() } }
    private fun showTouchProgress() {
        val policy = vault.device.touchPolicy
        touchNotice?.apply {
            visibility = if (policy < 0) View.GONE else View.VISIBLE
            text = when (policy) {
                1 -> "Waiting for the YubiKey — this slot requires no touch."
                2 -> "Waiting for YubiKey confirmation — touch the key when it flashes. Keep it connected or in NFC range."
                3 -> "YubiKey operation pending — touch if it flashes; a recent touch may still be cached. Keep it connected or in NFC range."
                else -> "YubiKey operation pending — touch if it flashes. Keep it connected or in NFC range."
            }
        }
    }
    protected var busy = false
    private var backAction: (() -> Unit)? = null
    private val activeWork = mutableSetOf<kotlinx.coroutines.Job>()
    private val onLock: () -> Unit = {
        CredentialTools.close()
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
        if (::vault.isInitialized) { vault.lockListeners.remove(onLock); vault.device.touchListeners.remove(onTouch) }
        vault = value; vault.lockListeners.add(onLock)
        vault.device.touchListeners.add(onTouch)
    }
    override fun onDestroy() { CredentialTools.close(); vault.lockListeners.remove(onLock); vault.device.touchListeners.remove(onTouch); super.onDestroy() }
    override fun onUserInteraction() { super.onUserInteraction(); (application as KagitabaApp).touch() }
    protected open fun locked() { screen("Wallet locked"); button("Unlock", primary = true) { authenticate { recreate() } } }
    protected open fun walletShown() = vault.connected
    protected open fun closeWallet() { vault.lock(); finish() }
    protected open fun refreshWallet() { work("Synchronizing…") { notice.text = vault.sync() } }
    protected open fun walletSettings() {}
    protected open fun hasWalletSettings() = false
    protected fun screen(title: String, allowSync: Boolean = true, back: (() -> Unit)? = null) {
        backAction = back
        val spacing = (20 * resources.displayMetrics.density).toInt()
        panel = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(spacing, spacing, spacing, spacing) }
        val scroll = ScrollView(this).apply { isFillViewport = true; WalletTheme.persistentScrollbar(this); addView(panel) }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(WalletTheme.background) }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(spacing, 8, spacing, 8); setBackgroundColor(WalletTheme.surface)
        }
        header.addView(TextView(this).apply {
            text = "KAGITABA"; textSize = 14f; letterSpacing = .16f; gravity = android.view.Gravity.CENTER_VERTICAL
            typeface = android.graphics.Typeface.MONOSPACE; setTextColor(WalletTheme.accent)
        }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, WalletTheme.dp(this, 56)))
        val summary = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(WalletTheme.dp(context, 8), 0, 0, 0) }
        if (walletShown()) {
            summary.addView(TextView(this).apply {
                text = (application as KagitabaApp).wallets.name(vault.walletId); textSize = 12f; setTextColor(WalletTheme.ink)
                maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END
            })
            summary.addView(TextView(this).apply {
                text = if (vault.connected) vault.settings().optString("syncStatus", "Local") else "New wallet"
                textSize = 10f; setTextColor(WalletTheme.muted); maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END
            })
        }
        header.addView(summary, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        fun headerButton(text: String, description: String, allowBusy: Boolean = false, action: (Button) -> Unit) = Button(this).also {
            it.text = text; it.contentDescription = description; WalletTheme.button(it)
            it.gravity = android.view.Gravity.CENTER; it.setPadding(0, 0, 0, 0)
            it.minWidth = 0; it.minimumWidth = 0
            header.addView(it, LinearLayout.LayoutParams(WalletTheme.dp(this, 48), WalletTheme.dp(this, 48)))
            it.setOnClickListener { _ -> if (!busy || allowBusy) action(it) }
        }
        if (walletShown() && hasWalletSettings() && vault.connected && vault.settings().has("url"))
            headerButton("↻", "Synchronize") { refreshWallet() }.isEnabled = allowSync
        headerButton("⋮", "Tools", allowBusy = true) { anchor ->
            PopupMenu(this, anchor).apply {
                menu.add("Password generator").apply { isEnabled = !busy }.setOnMenuItemClickListener { CredentialTools.generator(this@SecureActivity); true }
                if (walletShown() && hasWalletSettings()) menu.add("Settings").apply { isEnabled = !busy }.setOnMenuItemClickListener { walletSettings(); true }
                if (vault.unlocked) menu.add("Lock").setOnMenuItemClickListener { vault.lock(); true }
                show()
            }
        }
        if (walletShown()) headerButton("×", "Close wallet", allowBusy = true) { closeWallet() }.setTextColor(android.graphics.Color.rgb(255, 118, 93))
        root.addView(header)
        touchNotice = TextView(this).also {
            it.setTextColor(WalletTheme.accent); it.setTypeface(it.typeface, android.graphics.Typeface.BOLD)
            it.setPadding(spacing, 8, spacing, 8); it.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
            root.addView(it)
        }
        showTouchProgress()
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(root)
        if (back != null) button("← Back") { back() }
        label(title, 27).also { WalletTheme.heading(it, 27f); it.setPadding(0, WalletTheme.dp(this, 12), 0, WalletTheme.dp(this, 20)) }
        notice = label("", 14)
        notice.setTextColor(WalletTheme.accent)
        notice.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
    }
    protected fun label(text: String, size: Int = 16): TextView = TextView(this).also {
        it.typeface = if (size < 16 || size >= 19) android.graphics.Typeface.create("sans-serif", android.graphics.Typeface.NORMAL) else WalletTheme.dataFont(this)
        it.text = text; it.textSize = size.toFloat(); it.setTextColor(if (size < 16) WalletTheme.muted else WalletTheme.ink)
        it.setPadding(0, WalletTheme.dp(this, 8), 0, WalletTheme.dp(this, 8)); panel.addView(it)
    }
    protected fun group(title: String) {
        panel.addView(View(this).apply { setBackgroundColor(WalletTheme.line) }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, WalletTheme.dp(this, 1)).apply { topMargin = WalletTheme.dp(this@SecureActivity, 24); bottomMargin = WalletTheme.dp(this@SecureActivity, 8) })
        label(title, 19).also { WalletTheme.heading(it) }
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
    protected suspend fun autoSync(afterSave: Boolean = true): String? {
        if (vault.settings().optBoolean("autoSync") && vault.settings().has("url")) {
            val prefix = if (afterSave) "Saved on this device. " else ""
            notice.text = "${prefix}Synchronizing…"
            val result = try { vault.sync() } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                runCatching { vault.recordSyncFailure() }
                "${prefix}${friendlyError(e)}"
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
            val safe = setOf(DeviceToken.ERROR, "Wallet validation or storage failed", "Unlock your wallet first", "Remote wallet branch is missing",
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

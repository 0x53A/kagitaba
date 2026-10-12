package org.kagitaba.android

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.widget.LinearLayout
import androidx.credentials.CredentialManager

class MainActivity : SecureActivity() {
    private var documentAction: String? = null
    private var exportBytes: ByteArray? = null
    private var opened = false
    private var creating = false
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); home() }
    override fun locked() { home() }
    private fun home(status: String? = null) {
        val app = application as KagitabaApp
        if (!opened) {
            screen("Your wallets")
            val wallets = app.wallets.all()
            if (wallets.isEmpty()) label("No wallets yet.")
            for (wallet in wallets) button(wallet.name) {
                app.selectWallet(wallet.id); bindVault(app.vault); opened = true; creating = false; home()
            }
            button("Add existing", primary = true) { addWallet(false) }
            button("Create new") { addWallet(true) }
        } else if (!vault.connected) {
            screen(if (creating) "2 · Choose a key" else "2 · Connect repository") { opened = false; vault.lock(); home() }
            label(app.wallets.name(vault.walletId), 14)
            if (creating) {
                if (vault.unlocked) {
                    label("Key ready. Touch it to sign the wallet.")
                    button("Create wallet with selected pair", primary = true) { work("Creating signed wallet…") { vault.create(); home() } }
                } else {
                    button("Use existing PIV slot pair", primary = true) { authenticate { home() } }
                    button("Generate new PIV slot pair") { authenticate(provision = true) { home() } }
                }
            } else {
                label("Connect first, then unlock with an enrolled key.")
                connectionForm(false)
            }
        } else if (!vault.unlocked) {
            screen(app.wallets.name(vault.walletId)) { opened = false; vault.lock(); home() }
            label("Connect your YubiKey, then enter its PIN.")
            button("Unlock wallet", primary = true) { authenticate {
                work("Opening wallet…") { home(autoSync()) }
            } }
            button("Connection settings") { screen("Connection settings") { home() }; connectionForm(true) }
            button("Provider settings") { providerSettings() }
        } else {
            screen(app.wallets.name(vault.walletId)) { opened = false; vault.lock(); home() }
            button("Connection & settings") { settings() }
            button("Add password", primary = true) { edit(null) }
            button("Synchronize") { work("Synchronizing…") { val result = vault.sync(); home(result) } }
            work("Opening wallet…") { showEntries(); if (status != null) notice.text = status }
        }
    }
    private fun addWallet(create: Boolean) {
        screen(if (create) "1 · Name new wallet" else "1 · Name wallet") { opened = false; home() }
        val name = field("Wallet name")
        button("Continue", primary = true) {
            val app = application as KagitabaApp
            app.selectWallet(app.wallets.add(name.text.toString())); bindVault(app.vault)
            opened = true; creating = create; home()
        }
        button("Cancel") { opened = false; home() }
    }
    private suspend fun showEntries() {
        val items = vault.entries().filter { it.payload.optString("kind") == "item" }.sortedBy { it.title.lowercase() }
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val search = field("Search your wallet")
        panel.addView(container)
        fun render(query: String) {
            container.removeAllViews()
            for (item in items.filter { it.title.contains(query, ignoreCase = true) }) {
                val type = if (item.credentials("passkey").isNotEmpty()) "Passkey" else "Password / item"
                container.addView(android.widget.Button(this).apply { text = "${item.title}\n$type"; WalletTheme.button(this); setOnClickListener { if (!busy) details(item) } })
            }
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { render(s.toString()) }
            override fun afterTextChanged(s: Editable?) {}
        })
        render("")
        notice.text = if (items.isEmpty()) "No accessible entries. Grant access on your computer, then sync." else "${items.size} entries"
        label(if (vault.settings().has("url")) vault.settings().optString("syncStatus", "Ready to synchronize") else "Stored on this device · connect Git in settings to synchronize")
    }
    private fun details(item: WalletItem) {
        screen(item.title) { home() }
        for (passkey in item.credentials("passkey")) { label("Passkey · ${passkey.optString("rpId")}"); label(passkey.optString("username")) }
        item.credentials("basic-auth").firstOrNull()?.let { credential ->
            label(credential.optJSONObject("username")?.optString("value").orEmpty())
            button("Copy username") { copyCredential(credential.optJSONObject("username")?.optString("value").orEmpty(), false) }
            val value = label("••••••••")
            button("Show / hide password") {
                if (vault.unlocked) value.text = if (value.text == "••••••••") credential.optJSONObject("password")?.optString("value").orEmpty() else "••••••••"
            }
            button("Copy password") { copyCredential(credential.optJSONObject("password")?.optString("value").orEmpty(), true) }
            button("Edit password") { edit(item) }
        }
        button("Delete entry") { AlertDialog.Builder(this).setTitle("Delete this entry?")
            .setMessage("The deletion is saved as a signed wallet update. Previous Git history still contains the encrypted entry.")
            .setNegativeButton("Cancel", null).setPositiveButton("Delete") { _, _ -> work("Deleting…") { vault.delete(item.id); home(autoSync()) } }.show() }
    }
    private fun copyCredential(value: String, secret: Boolean) {
        if (!vault.unlocked) return
        val clipboard = getSystemService(android.content.ClipboardManager::class.java)
        val marker = java.util.UUID.randomUUID().toString()
        val clip = android.content.ClipData.newPlainText("Kagitaba", value)
        clip.description.extras = android.os.PersistableBundle().apply {
            putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, secret)
            putString("kagitaba.clip", marker)
        }
        clipboard.setPrimaryClip(clip)
        notice.text = "Copied"
        android.os.Handler(mainLooper).postDelayed({
            if (clipboard.primaryClipDescription?.extras?.getString("kagitaba.clip") == marker) clipboard.clearPrimaryClip()
        }, 30_000)
    }
    private fun edit(existing: WalletItem?) {
        fun cancel() { AlertDialog.Builder(this).setMessage("Discard these edits?").setNegativeButton("Keep editing", null).setPositiveButton("Discard") { _, _ -> home() }.show() }
        screen(if (existing == null) "Add password" else "Edit password") { cancel() }
        val credential = existing?.credentials("basic-auth")?.firstOrNull()
        val title = field("Title", existing?.title.orEmpty())
        val website = field("Primary website (HTTPS)", existing?.entity?.optJSONObject("scope")?.optJSONArray("urls").strings().firstOrNull().orEmpty())
        val username = field("Username", credential?.optJSONObject("username")?.optString("value").orEmpty())
        val password = field("Password", credential?.optJSONObject("password")?.optString("value").orEmpty(), true)
        button("Generate password") { password.setText(b64(NativeBridge.random(24))) }
        button("Save password", primary = true) { work("Saving…") {
            val origin = website.text.toString().takeIf { it.isNotBlank() }?.let(::exactOrigin)
            val updated = if (existing == null) WalletItem.create(title.text.toString(), WalletItem.password(username.text.toString(), password.text.toString()), origin)
            else WalletItem(existing.id, org.json.JSONObject(existing.payload.toString())).apply {
                entity.put("title", title.text.toString())
                updateLogin(username.text.toString(), password.text.toString())
                val scope = entity.optJSONObject("scope") ?: org.json.JSONObject().also { entity.put("scope", it) }
                val otherUrls = scope.optJSONArray("urls").strings().drop(1)
                scope.put("urls", org.json.JSONArray(listOfNotNull(origin) + otherUrls))
            }
            vault.save(updated); password.text.clear(); home(autoSync())
        } }
        button("Cancel") { cancel() }
    }
    private fun settings() {
        screen("Settings") { home() }
        if (vault.unlocked) {
            val info = vault.device.publicInfo()
            label("Current YubiKey policies (read-only)")
            label(policyDescription("Encryption", info.optJSONObject("encryptionPolicy")))
            label(policyDescription("Signing", info.optJSONObject("signingPolicy")))
        }
        button("Repository connection") { screen("Repository connection") { settings() }; connectionForm(true) }
        button("Participant names") { participants() }
        button("Backups & updates") { backups() }
        button("Passwords & autofill") { screen("Passwords & autofill") { settings() }; providerOptions() }
    }
    private fun providerOptions() {
        button("Enable passwords & passkeys") { providerSettings() }
        button("Enable autofill") { startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:$packageName"))) }
    }
    private fun backups() {
        screen("Backups & updates") { settings() }
        button("Export encrypted wallet backup") { work("Preparing encrypted backup…") { exportDocument("kagitaba-wallet.json", vault.export()) } }
        button("Import signed wallet updates") { documentAction = "import"; startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE), 7) }
        label("Backups contain encrypted history. Keep another enrolled key for recovery.", 14)
    }
    private fun connectionForm(connected: Boolean) {
        val settings = vault.settings()
        val url = field("Git repository HTTPS URL", settings.optString("url"))
        val username = field("Git username", settings.optString("username"))
        val token = field("Password / access token${if (settings.has("url")) " · leave blank to keep" else ""}", secret = true)
        val auto = check("Synchronize after unlocking and saving", settings.optBoolean("autoSync", true))
        label(if (connected) "Unlock to store the token encrypted." else "The first connection trusts this repository. Unlock afterward to keep the token encrypted.", 14)
        button(if (connected) "Save connection" else "Connect wallet", primary = true) { work("Connecting…") {
            if (connected) vault.saveConnection(url.text.toString(), username.text.toString(), token.text.toString(), auto.isChecked)
            else vault.connect(url.text.toString(), username.text.toString(), token.text.toString(), auto.isChecked)
            token.text.clear(); home()
        } }
        if (connected) {
            label(settings.optString("syncStatus", "Not synchronized yet"))
            val last = settings.optLong("lastSync")
            if (last > 0) label("Last sync: ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(last))}")
        }
    }
    private fun participants(status: String? = null) {
        screen("Participant names") { settings() }
        label("Encrypted names are shared with all participants.", 14)
        work("Loading participants…") {
            for ((id, name) in vault.participants()) {
                label("${name.ifEmpty { "Unnamed participant" }} · ${id.take(16)}…")
                label("Fingerprint: $id")
                val draft = field("Friendly name · leave empty to remove", name)
                draft.filters = arrayOf(android.text.InputFilter.LengthFilter(128))
                button("Save name") { work("Saving participant name…") {
                    vault.nameParticipant(id, draft.text.toString().trim())
                    participants(autoSync() ?: "Participant name saved and signed")
                } }
            }
            notice.text = status ?: "Names are shared through wallet synchronization."
        }
    }
    private fun providerSettings() { CredentialManager.create(this).createSettingsPendingIntent().send() }
    private fun exportDocument(name: String, data: String) {
        exportBytes = data.toByteArray(); documentAction = "export"
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE, name), 7)
    }
    @Deprecated("Activity result compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 7) return
        val uri = data?.data
        if (resultCode == RESULT_OK && uri != null) work("Processing file…") {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                if (documentAction == "export") contentResolver.openOutputStream(uri, "wt")!!.use { it.write(exportBytes ?: error("Export expired")) }
                else {
                    val bytes = contentResolver.openInputStream(uri)!!.use { it.readNBytes(64 * 1024 * 1024 + 1) }
                    require(bytes.size <= 64 * 1024 * 1024); vault.importUpdate(String(bytes))
                }
            }
            exportBytes?.fill(0); exportBytes = null; notice.text = "File processed successfully"
        } else { exportBytes?.fill(0); exportBytes = null }
    }
}

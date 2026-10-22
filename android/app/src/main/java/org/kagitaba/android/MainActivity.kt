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
    private val totpImport=TotpImport(this)
    override fun onStop() { totpImport.stopCamera();CredentialTools.closeGenerators();super.onStop() }
    override fun onDestroy() { totpImport.close();super.onDestroy();if(enrollment)(application as KagitabaApp).endEnrollment() }
    private var documentAction: String? = null
    private var exportBytes: ByteArray? = null
    private var opened = false
    private var creating = false
    private var enrollment = false
    override fun walletShown() = opened
    override fun closeWallet() {
        opened = false; enrollment = false; vault.lock()
        val app = application as KagitabaApp
        app.endEnrollment(); bindVault(app.vault); home()
    }
    override fun walletSettings() { settings() }
    override fun hasWalletSettings() = true
    override fun refreshWallet() {
        fun sync() { work("Synchronizing…") { val result = vault.sync(); home(result) } }
        if (vault.unlocked) sync() else authenticate { sync() }
    }
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); home() }
    override fun locked() { selectedCollection=null;totpImport.close();home() }
    private fun home(status: String? = null) {
        val app = application as KagitabaApp
        if (!opened) {
            screen("Your wallets")
            val wallets = app.wallets.all()
            if (wallets.isEmpty()) label("No wallets yet.", 14)
            for (wallet in wallets) button(wallet.name) {
                app.selectWallet(wallet.id); bindVault(app.vault); opened = true; creating = false; enrollment = false; home()
            }
            button("Add existing", primary = true) { addWallet(false) }
            button("Create new") { addWallet(true) }
            button("Create enrollment request") {
                app.beginEnrollment(); bindVault(app.vault)
                opened = true; creating = true; enrollment = true; home()
            }
        } else if (!vault.connected) {
            screen(if (enrollment) "Create enrollment request" else if (creating) "Create wallet" else "Open wallet") { closeWallet() }
            if (creating) {
                if (vault.unlocked) {
                    label("Key ready", 14)
                    if (enrollment) button("Export participant request", primary = true) {
                        val info = vault.device.publicInfo()
                        exportDocument("kagitaba-participant.json", json("format" to "kagitaba-participant-1",
                            "encryption" to info.getString("participantPem"), "signing" to info.getString("signingPem")).toString())
                    }
                    else button("Create wallet", primary = true) { work("Creating signed wallet…") { vault.create(); home() } }
                } else {
                    button("Choose PIV key", primary = true) { authenticate { home() } }
                }
            } else {
                connectionForm(false)
            }
        } else if (!vault.unlocked) {
            screen(app.wallets.name(vault.walletId)) { opened = false; vault.lock(); home() }
            button("Unlock wallet", primary = true) { authenticate {
                work("Opening wallet…") { home(autoSync(afterSave = false)) }
            } }
            button("Connection settings") { screen("Connection settings") { home() }; connectionForm(true) }
            button("Provider settings") { providerSettings() }
        } else {
            screen(app.wallets.name(vault.walletId)) { opened = false; vault.lock(); home() }
            button("Add password", primary = true) { edit(null) }
            work("Opening wallet…") { showEntries(); if (status != null) notice.text = status }
        }
    }
    private fun addWallet(create: Boolean) {
        enrollment = false
        screen(if (create) "Create wallet" else "Open wallet") { opened = false; home() }
        val name = field("Wallet name")
        button("Continue", primary = true) {
            val app = application as KagitabaApp
            app.selectWallet(app.wallets.add(name.text.toString())); bindVault(app.vault)
            opened = true; creating = create; home()
        }
        button("Cancel") { opened = false; home() }
    }
    private var selectedCollection: String? = null
    private suspend fun showEntries() {
        val index=vault.catalogue()
        val items=index.entries.filter { it.kind=="item" }.sortedBy { it.title.lowercase() }
        val nodes=index.collections
        val filed=nodes.flatMap { it.items }.toSet()
        if(selectedCollection!="unfiled"&&nodes.none { it.key==selectedCollection })selectedCollection=null
        label("Collection",14)
        val picker=android.widget.Spinner(this)
        val choices=listOf("All entries","Entries not in a collection")+nodes.map { "  ".repeat(it.depth)+it.title }
        picker.adapter=android.widget.ArrayAdapter(this,android.R.layout.simple_spinner_dropdown_item,choices)
        panel.addView(picker)
        val initial=if(selectedCollection=="unfiled")1 else nodes.indexOfFirst { it.key==selectedCollection }.let { if(it<0)0 else it+2 }
        picker.setSelection(initial)
        val search=field("Search your wallet")
        val container=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL;panel.addView(this) }
        fun render(query: String) {
            container.removeAllViews()
            val node=nodes.find { it.key==selectedCollection }
            if(node!=null&&node.unavailable>0)container.addView(android.widget.TextView(this).apply { text="${node.unavailable} unavailable or external links";WalletTheme.caption(this) })
            val matches=items.filter { item ->
                (if(selectedCollection=="unfiled")item.id !in filed else node==null||item.id in node.items)&&
                (listOf(item.title,item.id)+item.usernames).any { it.contains(query,ignoreCase=true) }
            }
            for(item in matches) {
                val usernames=item.usernames.joinToString(" · ")
                val value=listOf(item.title,usernames,item.id.take(8)).filter { it.isNotEmpty() }.joinToString("\n")
                container.addView(android.widget.Button(this).apply {
                    WalletTheme.button(this)
                    contentDescription="${item.title}. $usernames. Entry ID ${item.id}"
                    text=android.text.SpannableString(value).apply {
                        val start=item.title.length+1
                        setSpan(android.text.style.RelativeSizeSpan(.85f),start,length,0)
                        val idStart=value.lastIndexOf(item.id.take(8))
                        setSpan(android.text.style.ForegroundColorSpan(WalletTheme.muted),idStart,length,0)
                        setSpan(android.text.style.TypefaceSpan("monospace"),idStart,length,0)
                    }
                    setOnClickListener { if(!busy)indexedDetails(item, index.collectionPaths(item.id)) }
                })
            }
            if(matches.isEmpty())container.addView(android.widget.TextView(this).apply { text=if(query.isNotEmpty())"No matching entries." else "No accessible entries.";WalletTheme.caption(this) })
        }
        picker.onItemSelectedListener=object:android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent:android.widget.AdapterView<*>?,view:android.view.View?,position:Int,id:Long) {
                selectedCollection=when(position){0->null;1->"unfiled";else->nodes[position-2].key};render(search.text.toString())
            }
            override fun onNothingSelected(parent:android.widget.AdapterView<*>?) {}
        }
        search.addTextChangedListener(object:TextWatcher {
            override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int) {}
            override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int) { render(s.toString()) }
            override fun afterTextChanged(s:Editable?) {}
        })
        render("")
        notice.text=if(items.isEmpty())"No accessible entries. Grant access on your computer, then sync." else "${items.size} entries"
    }

    private fun indexedDetails(item: WalletIndexRow, collectionPaths: List<String>) {
        screen(item.title) { home() }
        entryCollections(collectionPaths)
        if(item.usernames.isNotEmpty()) { label("Accounts",14); label(item.usernames.joinToString(" · ")) }
        if(item.scopes.isNotEmpty()) { label("URLs / scopes",14); item.scopes.forEach { label(it) } }
        val kinds=listOfNotNull(if(item.password) "Password" else null, if(item.totp) "TOTP" else null, if(item.passkey) "Passkey" else null)
        if(kinds.isNotEmpty()) { label("Credentials",14); label(kinds.joinToString(" · ")) }
        label("Entry ID",14); label(item.id)
        button("Show more",primary=true) { work("Opening entry…") { details(vault.entry(item.id), collectionPaths) } }
    }
    private fun entryCollections(paths: List<String>) {
        if (paths.isNotEmpty()) { label("Collections", 14); paths.forEach { label(it) } }
    }
    private fun details(item: WalletItem, collectionPaths: List<String>) {
        screen(item.title) { home() }
        entryCollections(collectionPaths)
        for (passkey in item.credentials("passkey")) {
            group("Passkey")
            for ((title,key) in listOf("Relying party" to "rpId", "Username" to "username", "Display name" to "userDisplayName", "Credential ID" to "credentialId", "User handle" to "userHandle")) {
                val text=passkey.optString(key); if(text.isEmpty()) continue
                label(title,14); val secret=key=="userHandle"
                val value=label(if(secret) "••••••••" else text)
                if(secret) button("Show / hide") { if(vault.unlocked) value.text=if(value.text=="••••••••") text else "••••••••" }
                button("Copy ${title.lowercase()}") { copyCredential(text,secret) }
            }
            for ((title,key) in listOf("Backup eligible" to "eligible", "Backed up" to "state")) {
                label(title,14)
                val flag=passkey.optJSONObject("kagitabaBackupFlags")?.opt(key)
                label(when(flag) { null -> "Not recorded"; true -> "Yes"; false -> "No"; else -> "Invalid" })
            }
        }
        item.credentials("basic-auth").firstOrNull()?.let { credential ->
            group("Login"); label("Username", 14)
            label(credential.optJSONObject("username")?.optString("value").orEmpty())
            button("Copy username") { copyCredential(credential.optJSONObject("username")?.optString("value").orEmpty(), false) }
            label("Password", 14)
            val value = label("••••••••")
            button("Show / hide password") {
                if (vault.unlocked) value.text = if (value.text == "••••••••") credential.optJSONObject("password")?.optString("value").orEmpty() else "••••••••"
            }
            button("Copy password") { copyCredential(credential.optJSONObject("password")?.optString("value").orEmpty(), true) }

        }
        for(c in item.credentials("totp")) {
            group("TOTP"); label(c.optString("issuer"), 20); label(c.optString("username"))
            button("Show current code") { CredentialTools.totpCode(this,c) }
        }
        for(c in item.credentials("note")){
            group("Note")
            val text=label("••••••••");var revealed=false
            button("Show / hide note"){revealed=!revealed;text.text=if(revealed)c.optJSONObject("content")?.optString("value").orEmpty() else "••••••••"}
        }
        group("Entry")
        button("Edit entry") { edit(item) }
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
        screen(if (existing == null) "Add password" else "Edit password", allowSync = false) { cancel() }
        val draft=if(existing==null)WalletItem.create("",WalletItem.password("","")) else WalletItem(existing.id,org.json.JSONObject(existing.payload.toString()))
        val title=CredentialTools.field(panel,"Title",draft.title)
        group("URLs")
        val urlPanel=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;panel.addView(this)}
        val urlRows=mutableListOf<android.widget.EditText>()
        val originalUrls=draft.entity.optJSONObject("scope")?.optJSONArray("urls").strings()
        fun addUrl(value:String){
            val row=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL};urlPanel.addView(row)
            val input=android.widget.EditText(this).apply{
                setText(value);contentDescription="URL";isSaveEnabled=false;importantForAutofill=android.view.View.IMPORTANT_FOR_AUTOFILL_NO
                inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                setSingleLine(true);WalletTheme.field(this)
                layoutParams=LinearLayout.LayoutParams(0,WalletTheme.dp(context,48),1f)
            }
            row.addView(input);urlRows.add(input)
            fun action(text:String,width:Int,description:String,run:()->Unit){
                row.addView(android.widget.Button(this).apply{
                    this.text=text;contentDescription=description;WalletTheme.button(this)
                    minWidth=0;minimumWidth=0;setPadding(0,0,0,0);gravity=android.view.Gravity.CENTER
                    layoutParams=LinearLayout.LayoutParams(WalletTheme.dp(context,width),WalletTheme.dp(context,48))
                    setOnClickListener{run()}
                })
            }
            action("Copy",64,"Copy URL"){copyCredential(input.text.toString(),false)}
            action("×",48,"Remove URL"){urlRows.remove(input);urlPanel.removeView(row)}
        }
        originalUrls.forEach(::addUrl)
        button("+ URL"){addUrl("")}.apply{
            background=android.graphics.drawable.StateListDrawable().apply{
                for(pressed in listOf(true,false))addState(if(pressed)intArrayOf(android.R.attr.state_pressed) else intArrayOf(),android.graphics.drawable.GradientDrawable().apply{
                    shape=android.graphics.drawable.GradientDrawable.RECTANGLE;setColor(if(pressed)WalletTheme.line else WalletTheme.background)
                    setStroke(WalletTheme.dp(context,1).coerceAtLeast(1),WalletTheme.line,WalletTheme.dp(context,5).toFloat(),WalletTheme.dp(context,3).toFloat())
                })
            }
        }
        val updates=mutableListOf<()->Unit>()
        fun login(c:org.json.JSONObject){
            group("Login")
            val username=CredentialTools.field(panel,"Username",c.optJSONObject("username")?.optString("value").orEmpty())
            val password=CredentialTools.field(panel,"Password",c.optJSONObject("password")?.optString("value").orEmpty()).apply{transformationMethod=android.text.method.PasswordTransformationMethod.getInstance()}
            button("Show / hide password"){password.transformationMethod=if(password.transformationMethod==null)android.text.method.PasswordTransformationMethod.getInstance() else null;WalletTheme.field(password)}
            button("Generate…"){CredentialTools.generator(this){password.setText(it)}}
            updates.add {
                for((name,type,value) in listOf(Triple("username","string",username.text.toString()),Triple("password","concealed-string",password.text.toString()))){
                    val old=c.optJSONObject(name)
                    if(value!=old?.optString("value").orEmpty() || old==null&&value.isNotEmpty()){
                        val f=old?:json("fieldType" to type).also{c.put(name,it)};f.put("value",value)
                    }
                }
            }
        }
        draft.credentials("basic-auth").forEach(::login)
        button("Add login"){val c=WalletItem.password("","");draft.entity.getJSONArray("credentials").put(c);login(c)}
        fun note(c:org.json.JSONObject){
            group("Note")
            val input=CredentialTools.field(panel,"Note",c.optJSONObject("content")?.optString("value").orEmpty()).apply{transformationMethod=android.text.method.PasswordTransformationMethod.getInstance()}
            button("Show / hide note"){input.transformationMethod=if(input.transformationMethod==null)android.text.method.PasswordTransformationMethod.getInstance() else null}
            updates.add{val old=c.optJSONObject("content");if(input.text.toString()!=old?.optString("value").orEmpty()){val content=old?:json("fieldType" to "string").also{c.put("content",it)};content.put("value",input.text.toString())}}
        }
        draft.credentials("note").forEach(::note)
        button("Add note"){val c=json("type" to "note","content" to json("fieldType" to "string","value" to ""));draft.entity.getJSONArray("credentials").put(c);note(c)}
        for(c in draft.credentials("custom-fields")) {
            group("Custom fields")
            val fields=c.optJSONArray("fields") ?: continue
            for(i in 0 until fields.length()) {
                val f=fields.optJSONObject(i) ?: continue
                val name=f.optString("label","Unnamed field")
                val kind=f.optString("fieldType")
                val value=f.opt("value") as? String ?: continue
                if(kind=="boolean" && value in listOf("true","false")) {
                    val input=android.widget.CheckBox(this).apply{text=name;isChecked=value=="true";panel.addView(this)}
                    updates.add{f.put("value",input.isChecked.toString())}
                } else if(kind in listOf("string","concealed-string")) {
                    val concealed=kind=="concealed-string" || name.trim().equals("pin",ignoreCase=true)
                    val input=CredentialTools.field(panel,name,value).apply{if(concealed)transformationMethod=android.text.method.PasswordTransformationMethod.getInstance()}
                    if(concealed)button("Show / hide"){input.transformationMethod=if(input.transformationMethod==null)android.text.method.PasswordTransformationMethod.getInstance() else null;WalletTheme.field(input)}
                    updates.add{if(input.text.toString()!=value)f.put("value",input.text.toString())}
                } else label("$name · $kind")
            }
        }
        for(c in draft.credentials("totp")){
            group("TOTP")
            val fields=linkedMapOf<String,android.widget.EditText>()
            for(name in listOf("secret","algorithm","period","digits","issuer","username"))fields[name]=CredentialTools.field(panel,"TOTP $name",c.optString(name)).apply{if(name=="secret")transformationMethod=android.text.method.PasswordTransformationMethod.getInstance()}
            updates.add { for((name,input) in fields){val value=input.text.toString();if(value!=c.optString(name)){
                c.put(name,if(name=="period"||name=="digits")java.math.BigInteger(value) else value)
            }} }
        }
        button("Import TOTP (camera / picture / URI)"){totpImport.show { c->draft.entity.getJSONArray("credentials").put(c);label("TOTP ready to save · ${c.optString("issuer")} · ${c.optString("username")}") }}
        button("Save entry",primary=true){work("Saving…"){
            draft.entity.put("title",title.text.toString());updates.forEach{it()}
            val urls=urlRows.map{it.text.toString()}
            if(urls!=originalUrls){val scope=draft.entity.optJSONObject("scope")?:org.json.JSONObject().also{draft.entity.put("scope",it)};if(!scope.has("androidApps"))scope.put("androidApps",org.json.JSONArray());scope.put("urls",org.json.JSONArray(urls))}
            vault.save(draft);home(autoSync())
        }}
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
        val token = field("Password / access token${if (settings.optBoolean("hasDeviceToken")) " · leave blank to keep" else ""}", secret = true)
        val auto = check("Synchronize after unlocking and saving", settings.optBoolean("autoSync", true))
        label("Token saved on this device.", 14)
        button(if (connected) "Save connection" else "Connect wallet", primary = true) { work("Connecting…") {
            if (connected) vault.saveConnection(url.text.toString(), username.text.toString(), token.text.toString(), auto.isChecked)
            else vault.connect(url.text.toString(), username.text.toString(), token.text.toString(), auto.isChecked)
            token.text.clear(); home()
        } }
        if (connected) {
            label(settings.optString("syncStatus", "Not synchronized yet"), 14)
            val last = settings.optLong("lastSync")
            if (last > 0) label("Last sync: ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(last))}", 14)
        }
    }
    private fun participants(status: String? = null) {
        screen("Participant names") { settings() }
        label("Encrypted names are shared with all participants.", 14)
        work("Loading participants…") {
            for ((id, name) in vault.participants()) {
                label("${name.ifEmpty { "Unnamed participant" }} · ${id.take(16)}…")
                label("Fingerprint", 14); label(id, 14)
                val draft = field("Friendly name · leave empty to remove", name)

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

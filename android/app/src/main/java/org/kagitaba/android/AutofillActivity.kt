package org.kagitaba.android

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

class AutofillActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState); setResult(RESULT_CANCELED)
        val ticket = RequestTickets.take(intent)
        val form = ticket?.entryId?.let { AutofillRequests.take(it) }
        screen("Password autofill")
        label((application as KagitabaApp).wallets.name(vault.walletId))
        if (form == null) { label("Request expired. Return to the login form and try again.", 14); button("Close") { finish() }; return }
        label(form.origin ?: form.packageName, 22)
        button("Unlock to continue", primary = true) { authenticate { work("Opening wallet…") {
            require(CallerPolicy(this).packageCertificates(form.packageName) == form.certificates)
            if (ticket.kind == "save") {
                screen("Save password"); label(form.origin ?: form.packageName, 22)
                val title = field("Title", form.origin ?: form.packageName)
                val username = field("Username", form.username)
                label("The password from the login form will be encrypted in your wallet.", 14)
                button("Save password", primary = true) { work("Saving…") {
                    val item = WalletItem.create(title.text.toString(), WalletItem.password(username.text.toString(), form.password), form.origin)
                    if (form.origin == null) item.bindApp(form.packageName, form.certificates)
                    vault.save(item); autoSync(); setResult(RESULT_OK); finish()
                } }
            } else {
                val passwords = vault.entries().filter { it.credentials("basic-auth").isNotEmpty() }
                val matches = passwords.filter { if (form.origin != null) it.matches(form.origin) else it.matchesApp(form.packageName, form.certificates) }
                screen("Choose a password"); label(form.origin ?: form.packageName, 22)
                for (item in matches) button(item.title) { fill(form, item) }
                if (matches.isEmpty()) label("No matching passwords. Save a login for this website or link an entry to this app.", 14)
                if (form.origin == null) button("Link an existing password to this app") {
                    screen("Link a password"); label("Only choose an account you intend to share with ${form.packageName}.", 14)
                    for (item in passwords) button(item.title) {
                        AlertDialog.Builder(this).setTitle("Allow ${form.packageName}?")
                            .setMessage("Share ${item.title} with this app and remember its signing certificate?")
                            .setNegativeButton("Cancel", null).setPositiveButton("Link and fill") { _, _ -> work("Saving app association…") {
                                item.bindApp(form.packageName, form.certificates); vault.save(item); fill(form, item)
                            } }.show()
                    }
                    button("Cancel") { finish() }
                }
            }
            button("Cancel") { finish() }
        } } }
        button("Cancel") { finish() }
    }
    override fun locked() { setResult(RESULT_CANCELED); finish() }
    private fun fill(form: LoginForm, item: WalletItem) {
        if (!vault.unlocked) { finish(); return }
        require(if (form.origin != null) item.matches(form.origin) else item.matchesApp(form.packageName, form.certificates))
        val credential = item.credentials("basic-auth").first()
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply { setTextViewText(android.R.id.text1, item.title) }
        val dataset = Dataset.Builder(presentation)
            .setValue(form.passwordId, AutofillValue.forText(credential.getJSONObject("password").getString("value")))
        form.usernameId?.let { dataset.setValue(it, AutofillValue.forText(credential.optJSONObject("username")?.optString("value").orEmpty())) }
        val saveInfo = android.service.autofill.SaveInfo.Builder(android.service.autofill.SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(form.passwordId))
            .apply { form.usernameId?.let { setOptionalIds(arrayOf(it)) } }.build()
        val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, FillResponse.Builder().addDataset(dataset.build()).setSaveInfo(saveInfo).build())
        setResult(RESULT_OK, result); finish()
    }
}

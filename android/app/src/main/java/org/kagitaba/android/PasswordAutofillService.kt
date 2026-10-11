package org.kagitaba.android

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.View
import android.view.autofill.AutofillId
import android.widget.RemoteViews

data class LoginForm(val packageName: String, val certificates: Set<String>, val origin: String?,
    val usernameId: AutofillId?, val passwordId: AutofillId, val username: String, val password: String)

object AutofillRequests {
    private val pending = mutableMapOf<String, Pair<Long, LoginForm>>()
    @Synchronized fun clear() { pending.clear() }
    @Synchronized fun put(id: String, form: LoginForm) {
        pending.entries.removeAll { it.value.first < android.os.SystemClock.elapsedRealtime() }
        require(pending.size < 128)
        pending[id] = (android.os.SystemClock.elapsedRealtime() + 120_000) to form
    }
    @Synchronized fun take(id: String): LoginForm? = pending.remove(id)?.takeIf { it.first >= android.os.SystemClock.elapsedRealtime() }?.second
}

class PasswordAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        if (cancellationSignal.isCanceled || !vault.connected) { callback.onSuccess(null); return }
        try {
            val form = parse(request.fillContexts.last().structure) ?: run { callback.onSuccess(null); return }
            val id = java.util.UUID.randomUUID().toString()
            AutofillRequests.put(id, form.copy(username = "", password = ""))
            val pending = RequestTickets.issue(this, RequestTickets.Ticket("fill", entryId = id), AutofillActivity::class.java)
            val ids = listOfNotNull(form.usernameId, form.passwordId).toTypedArray()
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply { setTextViewText(android.R.id.text1, "Unlock Kagitaba") }
            val response = FillResponse.Builder().setAuthentication(ids, pending.intentSender, presentation)
                .setSaveInfo(SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(form.passwordId))
                    .apply { form.usernameId?.let { setOptionalIds(arrayOf(it)) } }.build()).build()
            if (!cancellationSignal.isCanceled) callback.onSuccess(response)
        } catch (_: Exception) { callback.onSuccess(null) }
    }
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        try {
            val form = parse(request.fillContexts.last().structure) ?: error("No password form")
            require(form.password.isNotEmpty())
            val id = java.util.UUID.randomUUID().toString()
            AutofillRequests.put(id, form)
            val pending = RequestTickets.issue(this, RequestTickets.Ticket("save", entryId = id), AutofillActivity::class.java)
            callback.onSuccess(pending.intentSender)
        } catch (_: Exception) { callback.onFailure("Could not save this login. Open Kagitaba and add it manually.") }
    }
    private fun parse(structure: AssistStructure): LoginForm? {
        val packageName = structure.activityComponent.packageName
        if (packageName == this.packageName) return null
        val policy = CallerPolicy(this)
        val certificates = policy.packageCertificates(packageName)
        var username: AssistStructure.ViewNode? = null
        var password: AssistStructure.ViewNode? = null
        val domains = mutableSetOf<String>()
        var visited = 0
        fun walk(node: AssistStructure.ViewNode, depth: Int) {
            require(++visited <= 5000 && depth <= 64)
            node.webDomain?.let {
                require(node.webScheme == "https")
                domains.add(exactOrigin("https://$it"))
            }
            val hints = node.autofillHints?.map(String::lowercase).orEmpty()
            val name = node.idEntry.orEmpty().lowercase()
            val variation = node.inputType and android.text.InputType.TYPE_MASK_VARIATION
            if (node.autofillId != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                if (hints.any { it in setOf("password", "newpassword") } || variation in setOf(android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD, android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)) password = node
                else if (hints.any { it in setOf("username", "emailaddress", "newusername") } || name in setOf("username", "email", "login")) username = node
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode, 0)
        require(domains.size <= 1)
        val domain = domains.singleOrNull()
        if (domain != null) require(policy.trustedBrowser(packageName, certificates))
        val pass = password ?: return null
        return LoginForm(packageName, certificates, domain, username?.autofillId, pass.autofillId!!,
            username?.autofillValue?.takeIf { it.isText }?.textValue?.toString().orEmpty(),
            pass.autofillValue?.takeIf { it.isText }?.textValue?.toString().orEmpty())
    }
}

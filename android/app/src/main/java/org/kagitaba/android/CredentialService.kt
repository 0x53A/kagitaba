package org.kagitaba.android

import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.provider.*
import androidx.credentials.exceptions.*
import kotlinx.coroutines.*
import org.json.JSONObject

class CredentialService : CredentialProviderService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
    override fun onBeginCreateCredentialRequest(request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>) {
        if (cancellationSignal.isCanceled) return
        if (!vault.connected || (request !is BeginCreatePublicKeyCredentialRequest && request !is BeginCreatePasswordCredentialRequest)) {
            callback.onError(CreateCredentialUnknownException("Connect your YubiKey wallet in Kagitaba first")); return
        }
        callback.onResult(BeginCreateCredentialResponse(listOf(CreateEntry((application as KagitabaApp).wallets.name(vault.walletId),
            RequestTickets.issue(this, RequestTickets.Ticket("create")), description = "Unlock and save to your encrypted wallet"))))
    }
    override fun onBeginGetCredentialRequest(request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>) {
        val job = scope.launch {
            try { val result = query(this@CredentialService, request); ensureActive(); callback.onResult(result) }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { if (!cancellationSignal.isCanceled) callback.onError(GetCredentialUnknownException("Could not read Kagitaba credentials")) }
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }
    override fun onClearCredentialStateRequest(request: ProviderClearCredentialStateRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>) {
        vault.lock(); if (!cancellationSignal.isCanceled) callback.onResult(null)
    }
    companion object {
        suspend fun query(context: android.content.Context, request: BeginGetCredentialRequest, interactive: Boolean = false): BeginGetCredentialResponse {
            if (!context.vault.connected) return BeginGetCredentialResponse()
            // A background provider query must never initiate PIV touch/private
            // operations. Only the foreground approval activity may do so.
            val walletName = (context.applicationContext as KagitabaApp).wallets.name(context.vault.walletId)
            if (!context.vault.unlocked || !interactive) return BeginGetCredentialResponse(authenticationActions = listOf(AuthenticationAction("Unlock $walletName with YubiKey",
                RequestTickets.issue(context, RequestTickets.Ticket("unlock")))))
            val items = context.vault.entries()
            val policy = CallerPolicy(context)
            val app = request.callingAppInfo ?: return BeginGetCredentialResponse()
            val origin = policy.origin(app)
            val entries = mutableListOf<CredentialEntry>()
            for (option in request.beginGetCredentialOptions.take(32)) {
                when (option) {
                    is BeginGetPublicKeyCredentialOption -> {
                        val opts = JSONObject(option.requestJson)
                        withContext(Dispatchers.IO) { policy.authorizeRp(app, opts.getString("rpId")) }
                        for (match in Passkeys(policy).matches(items, opts).take(100)) {
                            val credential = match.credential
                            entries.add(PublicKeyCredentialEntry(context, credential.optString("username", match.item.title),
                                RequestTickets.issue(context, RequestTickets.Ticket("passkey", match.item.id, credential.getString("credentialId"), option.id)), option,
                                displayName = match.item.title))
                        }
                    }
                    is BeginGetPasswordOption -> {
                        for (item in items.filter { if (origin.startsWith("https://")) it.matches(origin) else it.matchesApp(app.packageName, policy.certificates(app.signingInfo)) }.take(100)) {
                            val credential = item.credentials("basic-auth").firstOrNull() ?: continue
                            val username = credential.optJSONObject("username")?.optString("value").orEmpty()
                            if (option.allowedUserIds.isNotEmpty() && username !in option.allowedUserIds) continue
                            entries.add(PasswordCredentialEntry(context, username.ifBlank { "Account" },
                                RequestTickets.issue(context, RequestTickets.Ticket("password", item.id, optionId = option.id)), option, displayName = item.title))
                        }
                    }
                }
            }
            return BeginGetCredentialResponse(entries)
        }
    }
}

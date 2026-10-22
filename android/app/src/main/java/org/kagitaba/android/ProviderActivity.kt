package org.kagitaba.android

import android.content.Intent
import android.os.Bundle
import androidx.credentials.*
import androidx.credentials.provider.PendingIntentHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

class ProviderActivity : SecureActivity() {
    private var ticket: RequestTickets.Ticket? = null
    private var approvedEpoch = -1L
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        ticket = RequestTickets.take(intent)
        screen("Use your wallet")
        label((application as KagitabaApp).wallets.name(vault.walletId))
        if (ticket == null) { label("This request expired. Return to the requesting app and try again.", 14); button("Close") { finish() }; return }
        label("Unlock to review this request.", 14)
        button("Unlock and continue", primary = true) { authenticate { approvedEpoch = vault.epoch; process() } }
        button("Cancel") { finish() }
    }
    override fun locked() { setResult(RESULT_CANCELED); finish() }
    private fun authorized() {
        check(vault.unlocked && vault.epoch == approvedEpoch && (ticket?.expires ?: 0) >= android.os.SystemClock.elapsedRealtime()) { "Authentication expired" }
    }
    private fun process() = work("Checking request…") {
        val ticket = ticket ?: error("Expired request")
        authorized()
        if (ticket.kind == "unlock") {
            val begin = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent) ?: error("Missing query")
            val response = CredentialService.query(this, begin, interactive = true)
            authorized()
            val result = Intent(); PendingIntentHandler.setBeginGetCredentialResponse(result, response)
            setResult(RESULT_OK, result); finish(); return@work
        }
        val policy = CallerPolicy(this)
        if (ticket.kind == "create") {
            val provider = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: error("Missing creation request")
            val request = provider.callingRequest
            when (request) {
                is CreatePublicKeyCredentialRequest -> {
                    val opts = JSONObject(request.requestJson)
                    Passkeys.validateOptions(opts, true)
                    val rp = opts.getJSONObject("rp").getString("id")
                    withContext(Dispatchers.IO) { policy.authorizeRp(provider.callingAppInfo, rp) }
                    screen("Create passkey")
                    label(rp, 22); label(opts.getJSONObject("user").getString("name"))
                    button("Save passkey", primary = true) { work("Saving passkey…") {
                        authorized()
                        val response = withContext(Dispatchers.IO) { Passkeys(policy).create(opts, provider.callingAppInfo, request.clientDataHash, vault) }
                        authorized()
                        val result = Intent(); PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(response))
                        autoSync(); setResult(RESULT_OK, result); finish()
                    } }
                }
                is CreatePasswordRequest -> {
                    val origin = policy.origin(provider.callingAppInfo)
                    screen("Save password"); label(if (origin.startsWith("https://")) origin else provider.callingAppInfo.packageName, 21); label(request.id)
                    button("Save password", primary = true) { work("Saving password…") {
                        authorized()
                        val item = WalletItem.create(request.id, WalletItem.password(request.id, request.password), if (origin.startsWith("https://")) origin else null)
                        if (!origin.startsWith("https://")) item.bindApp(provider.callingAppInfo.packageName, policy.certificates(provider.callingAppInfo.signingInfo))
                        vault.save(item, approvedEpoch)
                        authorized()
                        val result = Intent(); PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
                        autoSync(); setResult(RESULT_OK, result); finish()
                    } }
                }
                else -> error("Unsupported request")
            }
        } else {
            val provider = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: error("Missing sign-in request")
            val item = vault.entry(ticket.entryId ?: error("Missing entry"))
            val option = provider.credentialOptions.singleOrNull() ?: error("Ambiguous request")
            when (option) {
                is GetPublicKeyCredentialOption -> {
                    val opts = JSONObject(option.requestJson)
                    Passkeys.validateOptions(opts, false)
                    val writesBlob = PasskeyExtensions.parse(opts, false).writesBlob
                    val match = Passkeys(policy).matches(listOf(item), opts).firstOrNull { it.credential.getString("credentialId") == ticket.credentialId } ?: error("Passkey does not match")
                    withContext(Dispatchers.IO) { policy.authorizeRp(provider.callingAppInfo, opts.getString("rpId")) }
                    screen("Sign in with passkey"); label(opts.getString("rpId"), 22); label(match.credential.optString("username", item.title))
                    if (writesBlob) label("This app also wants to save data with this passkey. Saving may require another security-key touch.", 14)
                    button("Sign in", primary = true) { work("Signing in…") {
                        authorized()
                        val response = withContext(Dispatchers.IO) { Passkeys(policy).assert(opts, provider.callingAppInfo, option.clientDataHash, match, vault) }
                        authorized()
                        val result = Intent(); PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(response)))
                        if (writesBlob) autoSync()
                        setResult(RESULT_OK, result); finish()
                    } }
                }
                is GetPasswordOption -> {
                    val origin = policy.origin(provider.callingAppInfo)
                    require(if (origin.startsWith("https://")) item.matches(origin) else item.matchesApp(provider.callingAppInfo.packageName, policy.certificates(provider.callingAppInfo.signingInfo)))
                    val credential = item.credentials("basic-auth").first()
                    val username = credential.getJSONObject("username").getString("value")
                    require(option.allowedUserIds.isEmpty() || username in option.allowedUserIds)
                    screen("Fill password"); label(if (origin.startsWith("https://")) origin else provider.callingAppInfo.packageName, 21); label(username)
                    button("Fill password", primary = true) {
                        if (!vault.unlocked || vault.epoch != approvedEpoch) { finish(); return@button }
                        val result = Intent(); PendingIntentHandler.setGetCredentialResponse(result,
                            GetCredentialResponse(PasswordCredential(username, credential.getJSONObject("password").getString("value"))))
                        setResult(RESULT_OK, result); finish()
                    }
                }
                else -> error("Unsupported request")
            }
        }
        button("Cancel") { finish() }
    }
}

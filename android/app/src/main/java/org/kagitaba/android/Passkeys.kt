package org.kagitaba.android

import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import org.json.JSONObject

/** Called only after fresh device authentication and explicit provider approval. */
class Passkeys(private val policy: CallerPolicy) {
    data class Account(val item: WalletItem, val credential: JSONObject)
    fun matches(items: List<WalletItem>, options: JSONObject): List<Account> {
        val rp = options.getString("rpId")
        require(CallerPolicy.validRp(rp)) { "Invalid relying party" }
        val allowed = descriptorIds(options.optJSONArray("allowCredentials"))
        return items.flatMap { item -> item.credentials("passkey").filter {
            it.optString("rpId") == rp && (allowed.isEmpty() || it.optString("credentialId") in allowed) &&
                runCatching { NativeBridge.call("passkey_validate", json("privateKey" to it.getString("key"))); true }.getOrDefault(false)
        }.map { Account(item, it) } }
    }
    private fun clientData(options: JSONObject, origin: String, type: String): String {
        val challenge = options.getString("challenge")
        require(unb64(challenge).size in 1..1024) { "Invalid challenge" }
        return b64(json("type" to type, "challenge" to challenge, "origin" to origin, "crossOrigin" to false).toString().toByteArray())
    }
    suspend fun create(options: JSONObject, info: CallingAppInfo, clientHash: ByteArray?, vault: Vault): String {
        val epoch = vault.epoch
        validateOptions(options, true)
        val extensions = PasskeyExtensions.parse(options, true)
        val rp = options.getJSONObject("rp").getString("id")
        val origin = policy.authorizeRp(info, rp)
        require(clientHash == null || origin.startsWith("https://") && clientHash.size == 32) { "Invalid browser client data" }
        val excluded = descriptorIds(options.optJSONArray("excludeCredentials"))
        require(vault.entries().none { item -> item.credentials("passkey").any { it.optString("rpId") == rp && it.optString("credentialId") in excluded } }) { "This passkey already exists" }
        val user = options.getJSONObject("user")
        val data = clientData(options, origin, "webauthn.create")
        val args = json("rpId" to rp, "userHandle" to user.getString("id"), "clientDataJSON" to data, "uv" to true)
        extensions.creationRequest(args)
        val result = NativeBridge.call("passkey_create", args)
        val credential = json("type" to "passkey", "credentialId" to result.getString("credentialId"), "rpId" to rp,
            "userHandle" to user.getString("id"), "username" to user.getString("name"), "userDisplayName" to user.optString("displayName", user.getString("name")), "key" to result.getString("privateKey"))
        extensions.creationState(result)?.let { credential.put(PasskeyExtensions.STATE, it) }
        val item = WalletItem.create("$rp — ${user.getString("name")}", credential, if (origin.startsWith("https://")) origin else "https://$rp")
        vault.save(item, epoch) // Durable signed commit BEFORE a successful registration response.
        val response = json("attestationObject" to result.getString("attestationObject"), "authenticatorData" to result.getString("authenticatorData"),
            "publicKey" to result.getString("publicKey"), "publicKeyAlgorithm" to -7, "transports" to JSONArray(listOf("internal")))
        if (clientHash == null) response.put("clientDataJSON", data)
        return json("id" to result.getString("credentialId"), "rawId" to result.getString("credentialId"), "type" to "public-key",
            "authenticatorAttachment" to "platform", "response" to response,
            "clientExtensionResults" to extensions.creationResults(result)).toString()
    }
    suspend fun assert(options: JSONObject, info: CallingAppInfo, clientHash: ByteArray?, selected: Account, vault: Vault): String {
        val epoch = vault.epoch
        validateOptions(options, false)
        val extensions = PasskeyExtensions.parse(options, false)
        val rp = options.getString("rpId")
        val origin = policy.authorizeRp(info, rp)
        require(matches(listOf(selected.item), options).any { it.credential.getString("credentialId") == selected.credential.getString("credentialId") }) { "Selected passkey does not match the request" }
        val data = clientData(options, origin, "webauthn.get")
        val args = json("rpId" to rp, "privateKey" to selected.credential.getString("key"), "clientDataJSON" to data, "uv" to true)
        if (clientHash != null) {
            require(origin.startsWith("https://") && clientHash.size == 32) { "Invalid browser client data" }
            args.put("clientDataHash", b64(clientHash))
        }
        extensions.assertionRequest(args, selected.credential)
        val signed = NativeBridge.call("passkey_assert", args)
        val extensionResults = extensions.assertionResults(signed, selected) { updated ->
            vault.save(updated, epoch, selected.item.payload.toString())
        }
        val response = json("authenticatorData" to signed.getString("authenticatorData"), "signature" to signed.getString("signature"), "userHandle" to selected.credential.getString("userHandle"))
        if (clientHash == null) response.put("clientDataJSON", data)
        val id = selected.credential.getString("credentialId")
        return json("id" to id, "rawId" to id, "type" to "public-key", "authenticatorAttachment" to "platform", "response" to response, "clientExtensionResults" to extensionResults).toString()
    }
    companion object {
        fun descriptorIds(list: JSONArray?): Set<String> {
            require(list == null || list.length() <= 256) { "Too many credential descriptors" }
            if (list == null) return emptySet()
            return (0 until list.length()).map { index ->
                val it = list.getJSONObject(index)
                require(it.getString("type") == "public-key") { "Unsupported credential type" }
                val bytes = unb64(it.getString("id")); require(bytes.size in 1..1024) { "Invalid credential ID" }; b64(bytes)
            }.toSet()
        }
        fun validateOptions(options: JSONObject, create: Boolean) {
            require(options.toString().length <= 65536) { "Request exceeds limits" }
            for (name in listOf("allowCredentials", "excludeCredentials")) {
                if (options.has(name)) descriptorIds(options.getJSONArray(name))
            }
            PasskeyExtensions.parse(options, create)
            if (create) {
                require(options.getJSONArray("pubKeyCredParams").objects().any { it.optString("type") == "public-key" && it.optInt("alg") == -7 }) { "Only ES256 passkeys are supported" }
                require(options.optString("attestation", "none") != "enterprise") { "Enterprise attestation is not supported" }
            }
        }
    }
}

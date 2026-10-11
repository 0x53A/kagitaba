package org.kagitaba.android

import org.json.JSONObject

/** Only this type may carry rendered extension diagnostics to the UI. No input values. */
class PasskeyExtensionException private constructor(val userMessage: String) : IllegalArgumentException(userMessage) {
    companion object {
        private fun label(name: String): String =
            if (name.matches(Regex("[A-Za-z][A-Za-z0-9_-]{0,63}"))) name else "[invalid identifier]"
        fun unsupported(names: List<String>): Nothing = throw PasskeyExtensionException(
            "Unsupported passkey extensions: ${names.take(8).joinToString(", ") { label(it) }}" +
                (if (names.size > 8) " (and ${names.size - 8} more)" else "") +
                ". Supported: credProps, prf, largeBlob. No passkey was saved or used."
        )
        fun invalid(name: String): Nothing = throw PasskeyExtensionException(
            "Invalid passkey extension options: ${label(name)}. No passkey was saved or used."
        )
        fun state(): Nothing = throw PasskeyExtensionException("Unsupported or damaged stored passkey extension data. No passkey was used.")
        fun tooLarge(): Nothing = throw PasskeyExtensionException("The largeBlob extension exceeds this wallet's 32 KiB storage limit. No passkey was used.")
    }
}

/** Application-owned WebAuthn extensions. Secret state lives inside the encrypted CXF credential. */
class PasskeyExtensions private constructor(
    private val extensions: JSONObject,
    private val evaluations: Map<String, JSONObject>
) {
    private val prf get() = extensions.optJSONObject("prf")
    private val blob get() = extensions.optJSONObject("largeBlob")
    val writesBlob get() = blob?.has("write") == true

    fun creationRequest(args: JSONObject) {
        if (prf != null) {
            args.put("prf", true)
            prf?.optJSONObject("eval")?.let { args.put("prfEval", it) }
        }
    }

    fun creationState(result: JSONObject): JSONObject? = if (prf != null)
        json("version" to 1, "prfKey" to result.getString("prfKey")) else null

    fun creationResults(result: JSONObject): JSONObject = JSONObject().apply {
        if (extensions.opt("credProps") == true) put("credProps", json("rk" to true))
        if (prf != null) put("prf", json("enabled" to true).apply {
            result.optJSONObject("prfResults")?.let { put("results", it) }
        })
        if (blob?.has("support") == true) put("largeBlob", json("supported" to true))
    }

    fun assertionRequest(args: JSONObject, credential: JSONObject) {
        val state = state(credential)
        if (prf != null && state.has("prfKey")) {
            args.put("prfKey", state.getString("prfKey"))
            val id = canonical(credential.getString("credentialId"), "prf")
            val eval = evaluations[id] ?: prf?.optJSONObject("eval")
            eval?.let { args.put("prfEval", it) }
        }
    }

    suspend fun assertionResults(
        result: JSONObject,
        selected: Passkeys.Account,
        persist: suspend (WalletItem) -> Unit
    ): JSONObject = JSONObject().apply {
        val state = state(selected.credential)
        if (prf != null) put("prf", JSONObject().apply {
            // Old/imported credentials without our PRF secret have no results.
            if (state.has("prfKey")) result.optJSONObject("prfResults")?.let { put("results", it) }
        })
        if (blob?.opt("read") == true) put("largeBlob", JSONObject().apply {
            if (state.has("largeBlob")) put("blob", state.getString("largeBlob"))
        })
        if (writesBlob) {
            // Copy before mutation: a failed signed save must not change cached plaintext.
            val updated = WalletItem(selected.item.id, JSONObject(selected.item.payload.toString()))
            val credential = updated.credentials("passkey").single {
                it.getString("credentialId") == selected.credential.getString("credentialId")
            }
            val updatedState = JSONObject(state.toString()).put("version", 1)
                .put("largeBlob", canonical(blob!!.getString("write"), "largeBlob"))
            credential.put(STATE, updatedState)
            persist(updated)
            put("largeBlob", json("written" to true)) // Only after the signed commit succeeds.
        }
    }

    companion object {
        const val STATE = "kagitabaPasskey"
        private const val MAX_BYTES = 32768
        private val supported = setOf("credProps", "prf", "largeBlob")

        private fun canonical(value: Any?, name: String): String {
            if (value !is String || !value.matches(Regex("[A-Za-z0-9_-]*={0,2}"))) PasskeyExtensionException.invalid(name)
            val bytes = try { unb64(value) } catch (_: IllegalArgumentException) { PasskeyExtensionException.invalid(name) }
            return try {
                if (bytes.size > MAX_BYTES) {
                    if (name == "largeBlob") PasskeyExtensionException.tooLarge()
                    PasskeyExtensionException.invalid(name)
                }
                b64(bytes)
            } finally { bytes.fill(0) }
        }

        private fun values(value: Any?): JSONObject {
            if (value !is JSONObject || !value.has("first")) PasskeyExtensionException.invalid("prf")
            return json("first" to canonical(value.opt("first"), "prf")).apply {
                if (value.has("second")) put("second", canonical(value.opt("second"), "prf"))
            }
        }

        private fun state(credential: JSONObject): JSONObject {
            if (!credential.has(STATE)) return JSONObject()
            val state = credential.optJSONObject(STATE) ?: PasskeyExtensionException.state()
            if (state.opt("version") != 1) PasskeyExtensionException.state()
            if (state.has("prfKey")) {
                val bytes = try { unb64(state.getString("prfKey")) } catch (_: Exception) { PasskeyExtensionException.state() }
                val valid = bytes.size == 32
                bytes.fill(0)
                if (!valid) PasskeyExtensionException.state()
            }
            if (state.has("largeBlob")) canonical(state.opt("largeBlob"), "largeBlob")
            return state
        }

        fun parse(options: JSONObject, create: Boolean): PasskeyExtensions {
            val raw = if (options.has("extensions")) options.optJSONObject("extensions")
                ?: PasskeyExtensionException.invalid("extensions") else JSONObject()
            val unsupported = raw.keys().asSequence().filter { it !in supported }.sorted().toList()
            if (unsupported.isNotEmpty()) PasskeyExtensionException.unsupported(unsupported)
            // Own a normalized copy; never alter platform request JSON.
            val extensions = JSONObject(raw.toString())
            if (extensions.has("credProps") && extensions.opt("credProps") !is Boolean) PasskeyExtensionException.invalid("credProps")
            val evaluations = mutableMapOf<String, JSONObject>()
            if (extensions.has("prf")) {
                val prf = extensions.optJSONObject("prf") ?: PasskeyExtensionException.invalid("prf")
                if (prf.has("eval")) prf.put("eval", values(prf.opt("eval")))
                if (prf.has("evalByCredential")) {
                    if (create) PasskeyExtensionException.invalid("prf")
                    val byCredential = prf.optJSONObject("evalByCredential") ?: PasskeyExtensionException.invalid("prf")
                    val allowed = Passkeys.descriptorIds(options.optJSONArray("allowCredentials"))
                    byCredential.keys().forEach { key ->
                        val id = canonical(key, "prf")
                        if (id.isEmpty() || id !in allowed || id in evaluations) PasskeyExtensionException.invalid("prf")
                        evaluations[id] = values(byCredential.opt(key))
                    }
                }
            }
            if (extensions.has("largeBlob")) {
                val blob = extensions.optJSONObject("largeBlob") ?: PasskeyExtensionException.invalid("largeBlob")
                if (create) {
                    if (blob.has("read") || blob.has("write")) PasskeyExtensionException.invalid("largeBlob")
                    if (blob.has("support") && blob.opt("support") !in setOf("preferred", "required")) PasskeyExtensionException.invalid("largeBlob")
                } else {
                    if (blob.has("support") || blob.has("read") && blob.has("write")) PasskeyExtensionException.invalid("largeBlob")
                    if (blob.has("read") && blob.opt("read") !is Boolean) PasskeyExtensionException.invalid("largeBlob")
                    if (blob.has("write")) {
                        if (options.optJSONArray("allowCredentials")?.length() != 1) PasskeyExtensionException.invalid("largeBlob")
                        Passkeys.descriptorIds(options.getJSONArray("allowCredentials"))
                        blob.put("write", canonical(blob.opt("write"), "largeBlob"))
                    }
                }
            }
            return PasskeyExtensions(extensions, evaluations)
        }
    }
}

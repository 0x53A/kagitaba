package org.kagitaba.android

import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

object NativeBridge {
    init { System.loadLibrary("kagitaba_android") }
    @JvmStatic external fun execute(request: ByteArray, random: ByteArray): ByteArray
    @JvmStatic external fun openPiv(request: ByteArray, connection: PivTransport): ByteArray
    private val rng = SecureRandom()
    fun random(count: Int): ByteArray = ByteArray(count).also(rng::nextBytes)
    fun call(op: String, fields: JSONObject = JSONObject()): JSONObject {
        fields.put("op", op)
        val request = fields.toString().toByteArray()
        val random = random(65536)
        var response: ByteArray? = null
        try {
            response = execute(request, random)
            return JSONObject(String(response, Charsets.UTF_8))
        } finally { request.fill(0); random.fill(0); response?.fill(0) }
    }
}
fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
fun unb64(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
fun json(vararg fields: Pair<String, Any?>): JSONObject = JSONObject().apply { fields.forEach { put(it.first, it.second) } }

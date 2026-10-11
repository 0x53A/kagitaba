package org.kagitaba.android

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import androidx.credentials.*
import androidx.credentials.provider.PendingIntentHandler
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

@RunWith(AndroidJUnit4::class)
// AndroidX exposes its response decoders as library-only test helpers; the
// production provider uses only the public request/response APIs.
@android.annotation.SuppressLint("RestrictedApi")
@org.junit.Ignore("Legacy software-participant UI is disabled; retain coverage for that backend.")
class ProviderFlowTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val ui = UiDevice.getInstance(instrumentation)
    private fun click(text: String) {
        val selector = By.text(text).clazz("android.widget.Button")
        assertTrue("Missing button: $text", ui.wait(Until.hasObject(selector), 15000))
        ui.findObject(selector).click()
    }
    private fun pin() {
        assertTrue("No device-PIN prompt", ui.wait(Until.hasObject(By.clazz("android.widget.EditText")), 15000))
        ui.findObject(By.clazz("android.widget.EditText")).text = "123456"
        ui.pressEnter()
    }
    private fun waitResult(): Intent {
        val deadline = System.currentTimeMillis() + 20000
        while (ProviderProbeActivity.result == null && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertEquals(Activity.RESULT_OK, ProviderProbeActivity.result)
        return ProviderProbeActivity.response ?: error("Missing provider response")
    }
    private fun launch(ticket: RequestTickets.Ticket, request: Intent) {
        ProviderProbeActivity.result = null; ProviderProbeActivity.response = null
        val pending = RequestTickets.issue(context, ticket)
        context.startActivity(Intent(context, ProviderProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra("pending", pending).putExtra("request", request))
        click("Unlock and continue"); pin()
    }
    @Test fun realPinProtectedProviderCreatesAndUsesSyncedPasskeysAndPasswords() {
        assumeTrue("Requires a disposable emulator with PIN 123456", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        if (!DeviceIdentity(context).enrolled) { click("Set up this installation"); pin() }
        else if (!context.vault.unlocked) { click("Unlock wallet"); pin() }
        if (!context.vault.connected) click("Create a new wallet")
        assertTrue(ui.wait(Until.hasObject(By.text("Your wallet")), 15000))
        val chrome = context.packageManager.getPackageInfo("com.android.chrome", PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        val caller = android.service.credentials.CallingAppInfo("com.android.chrome", chrome.signingInfo!!, "https://example.test")
        val options = """{"rp":{"id":"example.test","name":"Synthetic RP"},"user":{"id":"AQIDBA","name":"alice","displayName":"Alice"},"challenge":"AQIDBA","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"}}"""
        val creation = CreatePublicKeyCredentialRequest(options)
        val createRequest = android.service.credentials.CreateCredentialRequest(caller, creation.type, creation.credentialData)
        launch(RequestTickets.Ticket("create"), Intent().putExtra("android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST", createRequest))
        click("Save passkey")
        val registration = PendingIntentHandler.retrieveCreateCredentialResponse(PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL, waitResult()) as CreatePublicKeyCredentialResponse
        val response = JSONObject(registration.registrationResponseJson)
        val credentialId = response.getString("id")
        val item = runBlocking { context.vault.entries() }.single { entry -> entry.credentials("passkey").any { it.getString("credentialId") == credentialId } }
        val clientHash = ByteArray(32) { 7 }
        val get = GetPublicKeyCredentialOption("""{"rpId":"example.test","challenge":"AQIDBA","allowCredentials":[{"type":"public-key","id":"$credentialId"}]}""", clientHash)
        val frameworkOption = android.credentials.CredentialOption.Builder(get.type, get.requestData, get.candidateQueryData).build()
        val getRequest = android.service.credentials.GetCredentialRequest(caller, listOf(frameworkOption))
        launch(RequestTickets.Ticket("passkey", item.id, credentialId), Intent().putExtra("android.service.credentials.extra.GET_CREDENTIAL_REQUEST", getRequest))
        click("Sign in")
        val assertion = PendingIntentHandler.retrieveGetCredentialResponse(waitResult())!!.credential as PublicKeyCredential
        val signed = JSONObject(assertion.authenticationResponseJson).getJSONObject("response")
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(unb64(response.getJSONObject("response").getString("publicKey"))))
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(publicKey); update(unb64(signed.getString("authenticatorData"))); update(clientHash); verify(unb64(signed.getString("signature"))) })

        val password = CreatePasswordRequest("alice", "synthetic-only-password")
        launch(RequestTickets.Ticket("create"), Intent().putExtra("android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST",
            android.service.credentials.CreateCredentialRequest(caller, password.type, password.credentialData)))
        click("Save password")
        assertNotNull(PendingIntentHandler.retrieveCreateCredentialResponse(PasswordCredential.TYPE_PASSWORD_CREDENTIAL, waitResult()))
        val login = runBlocking { context.vault.entries() }.last { it.title == "alice" && it.credentials("basic-auth").isNotEmpty() }
        val getPassword = GetPasswordOption()
        launch(RequestTickets.Ticket("password", login.id), Intent().putExtra("android.service.credentials.extra.GET_CREDENTIAL_REQUEST",
            android.service.credentials.GetCredentialRequest(caller, listOf(android.credentials.CredentialOption.Builder(getPassword.type, getPassword.requestData, getPassword.candidateQueryData).build()))))
        click("Fill password")
        val filled = PendingIntentHandler.retrieveGetCredentialResponse(waitResult())!!.credential as PasswordCredential
        assertEquals("alice", filled.id); assertEquals("synthetic-only-password", filled.password)
    }
}

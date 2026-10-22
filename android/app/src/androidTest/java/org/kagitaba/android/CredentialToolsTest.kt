package org.kagitaba.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic images and padded camera planes, no physical camera or credentials. */
@RunWith(AndroidJUnit4::class)
class CredentialToolsTest {
    @Test fun globalGeneratorAndCameraLifecycleOnDisposableEmulator() {
        require(android.os.Build.FINGERPRINT.contains("generic")||android.os.Build.MODEL.contains("sdk"))
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        instrumentation.uiAutomation.grantRuntimePermission(instrumentation.targetContext.packageName,android.Manifest.permission.CAMERA)
        androidx.test.core.app.ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val device=androidx.test.uiautomator.UiDevice.getInstance(instrumentation)
            scenario.onActivity { CredentialTools.generator(it) }
            assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.text("Password generator")),5000))
            device.findObject(androidx.test.uiautomator.By.desc("Tools")).click()
            device.findObject(androidx.test.uiautomator.By.text("Password generator")).click()
            val deadline=System.currentTimeMillis()+10000
            var generated=""
            while(System.currentTimeMillis()<deadline){generated=device.findObjects(androidx.test.uiautomator.By.clazz(android.widget.EditText::class.java)).lastOrNull()?.text.orEmpty();if(generated.length==12)break;Thread.sleep(100)}
            assertEquals(12,generated.length)
            scenario.onActivity { activity ->
                CredentialTools.close()
                val field=MainActivity::class.java.getDeclaredField("totpImport").apply{isAccessible=true}
                (field.get(activity) as TotpImport).show { error("Synthetic emulator camera must not save an entry") }
            }
            device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.text("Scan camera")),5000)
            if(!device.hasObject(androidx.test.uiautomator.By.text("Scan camera"))) androidx.test.uiautomator.UiScrollable(androidx.test.uiautomator.UiSelector().scrollable(true)).scrollTextIntoView("Scan camera")
            device.findObject(androidx.test.uiautomator.By.text("Scan camera")).click()
            assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.desc("Camera preview")),5000))
            Thread.sleep(2500)
            assertFalse(device.hasObject(androidx.test.uiautomator.By.textContains("Camera unavailable")))
            if(!device.hasObject(androidx.test.uiautomator.By.text("Stop camera"))) androidx.test.uiautomator.UiScrollable(androidx.test.uiautomator.UiSelector().scrollable(true)).scrollTextIntoView("Stop camera")
            device.findObject(androidx.test.uiautomator.By.text("Stop camera")).click()
            assertTrue(device.wait(androidx.test.uiautomator.Until.gone(androidx.test.uiautomator.By.desc("Camera preview")),5000))
            scenario.onActivity { CredentialTools.close() }
        }
    }

    @Test fun pictureAndCameraPlaneUseRealPackagedDecoder() {
        val context=InstrumentationRegistry.getInstrumentation().context
        val bytes=context.assets.open("totp-qr.png").use{it.readBytes()}
        val picture=QrPixels.encoded(bytes).getJSONArray("uris").getString(0)
        val bitmap=android.graphics.BitmapFactory.decodeByteArray(bytes,0,bytes.size)
        val stride=bitmap.width+16;val plane=java.nio.ByteBuffer.allocate(stride*bitmap.height+7);plane.position(7)
        for(y in 0 until bitmap.height)for(x in 0 until bitmap.width)plane.put(7+y*stride+x,(bitmap.getPixel(x,y) and 255).toByte())
        val camera=QrPixels.plane(bitmap.width,bitmap.height,stride,1,plane).getJSONArray("uris").getString(0)
        assertEquals(picture,camera)
        val credential=NativeBridge.call("totp_parse",json("uri" to picture)).getJSONObject("credential")
        assertEquals(300,credential.getInt("period"))
        assertEquals(6,NativeBridge.call("totp_code",json("credential" to credential,"now" to 59)).getString("code").length)
        bitmap.recycle();bytes.fill(0);plane.clear()
    }
    @Test fun generatorAndMultilineValuesRoundTripThroughJni() {
        val fixed=org.json.JSONObject(String(NativeBridge.execute(json("op" to "password_generate","rules" to org.json.JSONObject()).toString().toByteArray(),ByteArray(65536))))
        assertEquals("aaaaaaaaaaa3",fixed.getString("password"))
        val generated=NativeBridge.call("password_generate",json("rules" to org.json.JSONObject())).getString("password")
        assertTrue(generated.matches(Regex("[acdefhjkmnprtuvwxy347]{12}")))
        assertTrue(generated.any{it.isDigit()})
        val item=WalletItem.create("Test",WalletItem.password("", "old"),"http://localhost/path?q=1#fragment")
        val result=NativeBridge.call("payload_edit",json("entryId" to item.id,"payload" to item.payload.toString(),"changes" to json("logins" to org.json.JSONArray().put(json("index" to 0,"password" to "\n 密码 \t")))))
        val changed=org.json.JSONObject(result.getString("payload")).getJSONObject("entity")
        assertEquals("http://localhost/path?q=1#fragment",changed.getJSONObject("scope").getJSONArray("urls").getString(0))
        assertEquals("\n 密码 \t",changed.getJSONArray("credentials").getJSONObject(0).getJSONObject("password").getString("value"))
    }
}

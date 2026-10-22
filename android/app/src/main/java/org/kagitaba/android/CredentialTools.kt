package org.kagitaba.android

import android.app.AlertDialog
import android.text.InputType
import android.widget.*
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object CredentialTools {
    private val generators = mutableSetOf<AlertDialog>()
    fun closeGenerators(){generators.toList().forEach{it.dismiss()}}
    fun forget(dialog:AlertDialog){dialogs.remove(dialog);generators.remove(dialog)}
    private val dialogs = mutableSetOf<AlertDialog>()
    fun close() { dialogs.toList().forEach { it.dismiss() } }
    fun dialog(activity: FragmentActivity, title: String): Pair<AlertDialog, LinearLayout> {
        val panel = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 16, 24, 16); setBackgroundColor(WalletTheme.background) }
        val dialog = AlertDialog.Builder(activity).setTitle(title).setView(ScrollView(activity).apply { WalletTheme.persistentScrollbar(this); addView(panel) }).setNegativeButton("Close", null).create()
        dialogs.add(dialog); dialog.setOnDismissListener { forget(dialog); clear(panel) }
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        return dialog to panel
    }
    private fun clear(view: android.view.View) { if (view is EditText) view.text.clear(); if (view is android.view.ViewGroup) for(i in 0 until view.childCount) clear(view.getChildAt(i)) }
    fun field(panel: LinearLayout, title: String, value: String = ""): EditText {
        panel.addView(TextView(panel.context).apply { text=title; WalletTheme.caption(this) })
        return EditText(panel.context).apply { setText(value); isSaveEnabled=false; importantForAutofill=android.view.View.IMPORTANT_FOR_AUTOFILL_NO; inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS; WalletTheme.field(this); panel.addView(this) }
    }
    fun button(panel: LinearLayout, text: String, action: () -> Unit): Button = Button(panel.context).apply { this.text=text; WalletTheme.button(this); setOnClickListener { action() }; panel.addView(this) }
    fun generator(activity: FragmentActivity, apply: ((String) -> Unit)? = null) {
        val (dialog,panel)=dialog(activity,"Password generator");generators.add(dialog)
        val length=field(panel,"Length","12").apply { inputType=InputType.TYPE_CLASS_NUMBER }
        val checks=linkedMapOf<String,CheckBox>()
        for ((key,label,checked) in listOf(Triple("lowercase","Lowercase",true),Triple("uppercase","Uppercase",false),Triple("digits","Digits",true),Triple("symbols","Symbols",false),Triple("lookalikes","Exclude lookalikes",true),Triple("requireEach","Require every enabled class",true))) {
            checks[key]=CheckBox(activity).apply { text=label; isChecked=checked; setTextColor(WalletTheme.ink); panel.addView(this) }
        }
        val symbols=field(panel,"Allowed symbols","!@#$%^&*()-_=+[]{}:,.?"); val exclusions=field(panel,"Additional exclusions")
        val output=field(panel,"Generated password").apply { inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; WalletTheme.field(this); keyListener=null }
        val status=TextView(activity).apply { WalletTheme.caption(this); panel.addView(this) }
        var epoch=0
        fun invalidate() { epoch++; output.text.clear() }
        val watcher=object:android.text.TextWatcher { override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){}; override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){invalidate()};override fun afterTextChanged(s:android.text.Editable?){} }
        listOf(length,symbols,exclusions).forEach { it.addTextChangedListener(watcher) };checks.values.forEach { it.setOnCheckedChangeListener { _,_ -> invalidate() } }
        button(panel,"Generate") {
            invalidate();val token=epoch
            val rules=json("length" to (length.text.toString().toIntOrNull()?:0),"symbolSet" to symbols.text.toString(),"exclusions" to exclusions.text.toString());checks.forEach { (key,value)->rules.put(key,value.isChecked) }
            activity.lifecycleScope.launch { try { val result=withContext(Dispatchers.Default){NativeBridge.call("password_generate",json("rules" to rules))};if(dialog.isShowing&&epoch==token){output.setText(result.getString("password"));status.text="Alphabet: ${result.getString("alphabet")}"} }catch(_:Exception){if(dialog.isShowing)status.text="Check length, enabled classes and exclusions."} }
        }
        button(panel,"Show / hide") { output.transformationMethod=if(output.transformationMethod==null)android.text.method.PasswordTransformationMethod.getInstance() else null; WalletTheme.field(output) }
        button(panel,"Copy") { if(output.text.isNotEmpty()) copy(activity,output.text.toString()) }
        if(apply!=null)button(panel,"Use password") { if(output.text.isNotEmpty()){apply(output.text.toString());dialog.dismiss()} }
        dialog.show();dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({if(dialog.isShowing)dialog.dismiss()},120_000)
    }
    fun totpCode(activity:FragmentActivity,credential:org.json.JSONObject){
        val(dialog,panel)=dialog(activity,"TOTP code")
        val output=field(panel,"Code").apply{keyListener=null}
        val status=TextView(activity).apply{WalletTheme.caption(this);panel.addView(this)}
        button(panel,"Copy"){if(output.text.isNotEmpty())copy(activity,output.text.toString())}
        dialog.show()
        activity.lifecycleScope.launch{while(dialog.isShowing){try{val result=withContext(Dispatchers.Default){NativeBridge.call("totp_code",json("credential" to credential,"now" to System.currentTimeMillis()/1000))};if(dialog.isShowing){output.setText(result.getString("code"));status.text="${result.getLong("remaining")}s remaining"}}catch(_:Exception){output.text.clear();status.text="Unsupported TOTP parameters. Stored data is preserved."};kotlinx.coroutines.delay(1000)}}
    }
    fun copy(context:android.content.Context,value:String) {
        val clipboard=context.getSystemService(android.content.ClipboardManager::class.java)
        val marker=java.util.UUID.randomUUID().toString();val clip=android.content.ClipData.newPlainText("Kagitaba",value)
        clip.description.extras=android.os.PersistableBundle().apply { putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE,true);putString("kagitaba.clip",marker) }
        clipboard.setPrimaryClip(clip)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({if(clipboard.primaryClipDescription?.extras?.getString("kagitaba.clip")==marker)clipboard.clearPrimaryClip()},30_000)
    }
}

class TotpImport(private val activity: FragmentActivity) {
    private var dialog:AlertDialog?=null
    private var panel:LinearLayout?=null
    private var status:TextView?=null
    private var choices:LinearLayout?=null
    private var apply:((org.json.JSONObject)->Unit)?=null
    private var camera:QrCamera?=null
    private var epoch=0
    private val image=activity.registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.GetContent()) { uri ->
        val token=epoch
        if(uri!=null&&dialog?.isShowing==true)activity.lifecycleScope.launch {
            try { val result=withContext(Dispatchers.IO) {
                val bytes=activity.contentResolver.openInputStream(uri)!!.use { it.readNBytes(16*1024*1024+1) }
                try {
                    QrPixels.encoded(bytes)
                }finally{bytes.fill(0)}
            };if(token==epoch&&dialog?.isShowing==true)found(result)
            }catch(_:Exception){if(token==epoch)status?.text="No supported TOTP QR code found, or image could not be read."}
        }
    }
    private val permission=activity.registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) { allowed -> if(dialog?.isShowing==true) {if(allowed)startCamera() else status?.text="Camera permission denied. You can import a picture."} }
    fun show(onApply:(org.json.JSONObject)->Unit) {
        close();apply=onApply
        val (d,p)=CredentialTools.dialog(activity,"Import TOTP");dialog=d;panel=p
        val uri=CredentialTools.field(p,"otpauth URI").apply { transformationMethod=android.text.method.PasswordTransformationMethod.getInstance() }
        status=TextView(activity).apply { WalletTheme.caption(this); p.addView(this) }
        choices=LinearLayout(activity).apply { orientation=LinearLayout.VERTICAL;p.addView(this) }
        CredentialTools.button(p,"Review URI") { review(uri.text.toString()) }
        CredentialTools.button(p,"Import picture (PNG / JPEG)") { camera?.close();camera=null;image.launch("image/*") }
        CredentialTools.button(p,"Scan camera") { permission.launch(android.Manifest.permission.CAMERA) }
        CredentialTools.button(p,"Stop camera") { camera?.close();camera=null }
        d.setOnDismissListener { close();uri.text.clear() }
        d.show();d.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({if(dialog===d)close()},60_000)
    }
    private fun startCamera() { camera?.close();val p=panel?:return;status?.text="Point the camera at a TOTP QR code.";val token=epoch;camera=QrCamera(activity,p,{result->if(token==epoch&&dialog?.isShowing==true)found(result)},{if(token==epoch)status?.text="Camera unavailable. You can import a picture."}).also { it.start() } }
    private fun found(result:org.json.JSONObject) { camera?.close();camera=null;choices?.removeAllViews();val values=result.getJSONArray("uris");for(i in 0 until values.length()){val uri=values.getString(i);choices?.let { CredentialTools.button(it,"Review TOTP ${i+1}"){review(uri)} }};if(values.length()==1)review(values.getString(0)) }
    private fun review(uri:String) { try { val c=NativeBridge.call("totp_parse",json("uri" to uri)).getJSONObject("credential");choices?.removeAllViews();status?.text="${c.optString("issuer")} · ${c.optString("username")} · ${c.getString("algorithm")}, ${c.get("digits")} digits, ${c.get("period")}s";choices?.let { CredentialTools.button(it,"Add to entry draft"){apply?.invoke(c);close()} } }catch(_:Exception){status?.text="Unsupported or invalid TOTP URI."} }
    fun stopCamera(){camera?.close();camera=null}
    fun close(){epoch++;camera?.close();camera=null;val d=dialog;dialog=null;d?.setOnDismissListener(null);d?.dismiss();if(d!=null)CredentialTools.forget(d);panel?.removeAllViews();panel=null;choices=null;status=null;apply=null}
}

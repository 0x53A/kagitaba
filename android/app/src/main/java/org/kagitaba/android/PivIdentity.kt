package org.kagitaba.android

import android.app.AlertDialog
import android.content.Context
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.*
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Transport only; the shared Rust adapter owns PIV, ECDH, and signatures. */
interface PivTransport { fun exchange(command: ByteArray): ByteArray }
fun policyDescription(label: String, policy: JSONObject?): String {
    if (policy == null) return "$label: policy unavailable from device"
    val pin = when (policy.optInt("pin")) { 1 -> "Never"; 2 -> "Once"; 3 -> "Always (per-operation PIN prompts are not supported)"; else -> "Unknown (${policy.optInt("pin")})" }
    val touch = when (policy.optInt("touch")) { 1 -> "Never"; 2 -> "Always"; 3 -> "Cached"; else -> "Unknown (${policy.optInt("touch")})" }
    return "$label: PIN $pin · touch $touch"
}
@androidx.annotation.Keep
class PivConnection(private val connection: SmartCardConnection, private val progress: (PivConnection, Int) -> Unit = { _, _ -> }) : java.io.Closeable, PivTransport {
    // Called by JNI only around an actual private command, never a PIN attempt.
    @Suppress("unused") fun setTouchPending(policy: Int) { progress(this, policy) }
    @Synchronized override fun exchange(command: ByteArray): ByteArray = connection.sendAndReceive(command)
    @Synchronized override fun close() { connection.close() }
}

class PivIdentity(private val context: Context) {
    val touchListeners = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()
    @Volatile var touchPolicy: Int = -1; private set
    private fun touchProgress(source: PivConnection, policy: Int) {
        synchronized(this) {
            if (connection !== source) return
            touchPolicy = policy
        }
        touchListeners.forEach { it() }
    }
    @Volatile private var info: JSONObject? = null
    private var connection: PivConnection? = null
    private var manager: YubiKitManager? = null
    private var nfcActivity: java.lang.ref.WeakReference<FragmentActivity>? = null
    private var handle: String? = null
    fun publicInfo(): JSONObject = info ?: error("Unlock your wallet first")
    private fun release(card: PivConnection?, discovery: YubiKitManager? = null) {
        java.util.concurrent.CompletableFuture.runAsync {
            runCatching { card?.close() }
            runCatching { discovery?.stopUsbDiscovery() }
        }
    }
    fun close() {
        val old = handle; handle = null; info = null
        val oldConnection = synchronized(this) { val oldCard = connection; connection = null; touchPolicy = -1; oldCard }
        touchListeners.forEach { it() }
        val oldManager = manager
        nfcActivity?.get()?.let { activity -> activity.runOnUiThread { runCatching { oldManager?.stopNfcDiscovery(activity) } } }
        nfcActivity = null; manager = null
        // APDU transport close may wait for a pending touch. Never wait on the UI thread.
        if (old != null) runCatching { NativeBridge.call("piv_close", json("identity" to old)) }
        release(oldConnection, oldManager)
    }
    /** null candidates is the explicit new-wallet workflow, never existing-wallet unlock. */
    fun authenticate(activity: FragmentActivity, candidates: JSONArray?, provision: Boolean = false, owner: Vault,
                     onSuccess: (ByteArray) -> Unit, onError: (String) -> Unit) {
        close()
        val layout = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; val pad = WalletTheme.dp(activity, 20); setPadding(pad, pad, pad, pad); setBackgroundColor(WalletTheme.surface) }
        fun label(value: String) = TextView(activity).also { it.text = value; it.setTextColor(WalletTheme.ink); layout.addView(it) }
        label(if (candidates != null) "Connect your YubiKey. Its public keys will be matched to the verified wallet before asking for its PIN."
            else if (provision) "Choose two empty slots after connecting your key. Generating keys requires your existing PIV PIN and management key."
            else "Choose an existing P-256 slot pair after connecting your YubiKey.")
        val status = label("Plug in the key or hold it against the NFC reader, then press Detect YubiKey.")
        val options = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE; layout.addView(this) }
        fun optionLabel(text: String) { options.addView(TextView(activity).apply { this.text = text; if (text == "YubiKey PIV PIN") setTypeface(typeface, android.graphics.Typeface.BOLD); setTextColor(WalletTheme.muted); setPadding(0, WalletTheme.dp(activity, 12), 0, WalletTheme.dp(activity, 8)) }) }
        fun field(title: String): EditText {
            optionLabel(title)
            return EditText(activity).also { it.isSingleLine = true; it.isSaveEnabled = false
                it.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                it.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; WalletTheme.field(it); options.addView(it) }
        }
        fun chooser(title: String): Spinner { optionLabel(title); return Spinner(activity).also { options.addView(it) } }
        val participants = if (candidates != null) chooser("Wallet participant") else null
        val encSlots = if (candidates == null) chooser("Encryption slot") else null
        val sigSlots = if (candidates == null) chooser("Signing slot") else null
        fun policyPicker(title: String, values: List<String>, selected: Int): Spinner = chooser(title).apply {
            adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, values); setSelection(selected)
        }
        val encPin = if (provision) policyPicker("Encryption PIN policy", listOf("Once per session (default)", "Never — no hardware PIN requirement"), 0) else null
        val encTouch = if (provision) policyPicker("Encryption touch policy", listOf("Never", "Always", "Cached (default)"), 2) else null
        val sigPin = if (provision) policyPicker("Signing PIN policy", listOf("Once per session (default)", "Never — no hardware PIN requirement"), 0) else null
        val sigTouch = if (provision) policyPicker("Signing touch policy", listOf("Never", "Always (default)", "Cached"), 1) else null
        if (provision) optionLabel("Policies are fixed at key creation. Cached touch lasts briefly. PIN Always needs per-operation PIN prompts, which are not supported. Kagitaba still asks for a PIV PIN when PIN Never is selected.")
        val currentPolicies = TextView(activity).also { it.setTextColor(WalletTheme.ink); options.addView(it) }
        var slotPolicies = JSONObject()
        var matches = emptyList<JSONObject>()
        var slots = emptyList<Int>()
        fun showPolicies() {
            if (provision) return
            val selected = if (candidates != null) matches.getOrNull(participants!!.selectedItemPosition) else null
            val encryption = selected?.optJSONObject("encryptionPolicy") ?: slots.getOrNull(encSlots?.selectedItemPosition ?: -1)?.let { slotPolicies.optJSONObject(it.toString()) }
            val signing = selected?.optJSONObject("signingPolicy") ?: slots.getOrNull(sigSlots?.selectedItemPosition ?: -1)?.let { slotPolicies.optJSONObject(it.toString()) }
            currentPolicies.text = "Current device policies (read-only)\n" + policyDescription("Encryption", encryption) + "\n" + policyDescription("Signing", signing)
        }
        val pin = field("YubiKey PIV PIN")
        val management = if (provision) field("Management key (hex)") else null
        if (provision) options.addView(Button(activity).apply { text = "Use factory management key"; isAllCaps = false
            setOnClickListener { management!!.setText("010203040506070801020304050607080102030405060708") } })
        val consent = if (provision) CheckBox(activity).also { it.text = "Generate keys in the two selected empty slots. This changes the YubiKey; existing keys will not be overwritten."; options.addView(it) } else null
        for (spinner in listOfNotNull(participants, encSlots, sigSlots, encPin, encTouch, sigPin, sigTouch)) {
            spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) { consent?.isChecked = false; showPolicies() }
                override fun onNothingSelected(parent: AdapterView<*>?) { showPolicies() }
            }
        }
        var serial = ""
        var finished = false
        var attempting = false
        var discovery: YubiKitManager? = null
        var detectedDevice: YubiKeyDevice? = null
        var pending: PivConnection? = null
        val dialog = AlertDialog.Builder(activity).setTitle(if (provision) "Create PIV participant" else "Use YubiKey")
            .setView(ScrollView(activity).apply { addView(layout) }).setPositiveButton("Detect YubiKey", null).setNegativeButton("Cancel", null).create()
        val onLock: () -> Unit = { dialog.dismiss() }
        owner.lockListeners.add(onLock)
        fun stopNfc() { runCatching { discovery?.stopNfcDiscovery(activity) } }
        val observer = object : DefaultLifecycleObserver {
            override fun onPause(owner: LifecycleOwner) { stopNfc() }
            override fun onDestroy(owner: LifecycleOwner) { dialog.dismiss(); owner.lifecycle.removeObserver(this) }
        }
        fun reset(message: String) {
            release(pending, discovery); pending = null; detectedDevice = null
            pin.text.clear(); management?.text?.clear(); consent?.isChecked = false
            attempting = false; stopNfc(); discovery = null
            options.visibility = View.GONE; status.text = message
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply { text = "Detect YubiKey"; isEnabled = true }
        }
        fun bridge(fields: JSONObject, card: PivConnection): JSONObject {
            val request = fields.toString().toByteArray()
            try { val response = NativeBridge.openPiv(request, card)
                try { return JSONObject(String(response)) } finally { response.fill(0) }
            } finally { request.fill(0) }
        }
        fun detected(device: YubiKeyDevice) { activity.runOnUiThread {
            if (finished || attempting || pending != null || !dialog.isShowing) return@runOnUiThread
            if (!activity.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) { reset("Return to Kagitaba and press Detect YubiKey."); return@runOnUiThread }
            attempting = true; status.text = "Reading public PIV metadata… No PIN is being sent."
            activity.lifecycleScope.launch {
                var opened: PivConnection? = null
                try {
                    val result = withContext(Dispatchers.IO) {
                        opened = PivConnection(device.openConnection(SmartCardConnection::class.java), ::touchProgress)
                        bridge(if (candidates != null) json("op" to "inspect", "candidates" to candidates) else json("op" to "inspect_slots"), opened!!)
                    }
                    if (!dialog.isShowing || finished) error("Authentication expired")
                    if (candidates != null) {
                        matches = result.getJSONArray("matches").objects()
                        check(matches.isNotEmpty()) { "No participant in this wallet matches the connected YubiKey. No PIN was sent." }
                        participants!!.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, matches.map {
                            "${it.optString("name").ifEmpty { it.getString("participantId").take(16) }} · ${it.getInt("encryptionSlot").toString(16)} / ${it.getInt("signingSlot").toString(16)}"
                        })
                    } else {
                        slotPolicies = result.optJSONObject("policies") ?: JSONObject()
                        serial = result.getString("serial")
                        val values = result.getJSONArray(if (provision) "emptySlots" else "occupiedSlots")
                        slots = (0 until values.length()).map { values.getInt(it) }
                        check(slots.size >= 2) { if (provision) "This YubiKey has fewer than two empty PIV slots." else "This YubiKey has fewer than two existing P-256 PIV slots." }
                        for (spinner in listOf(encSlots!!, sigSlots!!)) spinner.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, slots.map { it.toString(16).uppercase() })
                        sigSlots.setSelection(1)
                    }
                    pending = opened; opened = null; detectedDevice = device
                    showPolicies()
                    attempting = false; options.visibility = View.VISIBLE
                    status.text = if (candidates != null) "Matched ${matches.size} participant(s). Keep the key connected and enter its PIV PIN." else "YubiKey $serial. Select the slot pair and enter its PIV PIN."
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply { text = if (provision) "Generate keys" else "Unlock"; isEnabled = true }
                } catch (e: Exception) {
                    release(opened)
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    reset(PivErrors.message(e.message) ?: "Cannot read this YubiKey. Check USB permission or hold it against the NFC reader, then retry.")
                }
            }
        } }
        dialog.setOnDismissListener {
            owner.lockListeners.remove(onLock); pin.text.clear(); management?.text?.clear()
            if (!finished) { finished = true; release(pending, discovery); pending = null; stopNfc(); discovery = null; onError("YubiKey operation cancelled.") }
        }
        activity.lifecycle.addObserver(observer)
        dialog.show(); dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.window?.decorView?.filterTouchesWhenObscured = true
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if (attempting) return@setOnClickListener
            val card = pending
            if (card == null) {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
                discovery = YubiKitManager(context)
                try {
                    discovery!!.startUsbDiscovery(UsbConfiguration()) { detected(it) }
                    try { discovery!!.startNfcDiscovery(NfcConfiguration().timeout(15000), activity) { detected(it) } }
                    catch (_: Exception) { status.text = "Connect the key over USB and approve access. NFC is unavailable or disabled." }
                } catch (_: Exception) { reset("YubiKey discovery failed. Reconnect and retry.") }
                return@setOnClickListener
            }
            val enteredPin = pin.text.toString()
            if (enteredPin.length !in 6..8 || enteredPin.any { it.code > 127 }) { status.text = "PIV PIN must contain 6–8 ASCII characters."; return@setOnClickListener }
            val request = if (candidates != null) JSONObject(matches[participants!!.selectedItemPosition].toString())
                else json("encryptionSlot" to slots[encSlots!!.selectedItemPosition], "signingSlot" to slots[sigSlots!!.selectedItemPosition], "serial" to serial)
            if (request.getInt("encryptionSlot") == request.getInt("signingSlot")) { status.text = "Choose two different slots."; return@setOnClickListener }
            if (provision) {
                if (consent?.isChecked != true) { status.text = "Confirm generation in the selected empty PIV slots."; return@setOnClickListener }
                request.put("op", "provision").put("confirmed", true).put("managementKey", management!!.text.toString().trim())
                request.put("encryptionPolicy", json("pin" to if (encPin!!.selectedItemPosition == 0) 2 else 1, "touch" to encTouch!!.selectedItemPosition + 1))
                request.put("signingPolicy", json("pin" to if (sigPin!!.selectedItemPosition == 0) 2 else 1, "touch" to sigTouch!!.selectedItemPosition + 1))
            }
            request.put("pin", enteredPin); pin.text.clear(); management?.text?.clear()
            attempting = true; dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
            status.text = if (provision) "Generating keys. Keep the YubiKey connected and touch it when requested…" else "Unlocking. Touch the YubiKey if requested…"
            activity.lifecycleScope.launch {
                var result: JSONObject? = null
                try {
                    withContext(Dispatchers.IO) { result = bridge(request, card) }
                    if (!dialog.isShowing || finished) error("Authentication expired")
                    synchronized(this@PivIdentity) { connection = card; touchPolicy = -1 }
                    pending = null; info = result!!; handle = result!!.getString("identity")
                    manager = discovery; nfcActivity = java.lang.ref.WeakReference(activity)
                    val openedHandle = handle
                    (detectedDevice as? UsbYubiKeyDevice)?.setOnClosed { activity.runOnUiThread { if (handle == openedHandle) owner.lock() } }
                    finished = true; dialog.dismiss(); onSuccess(handle!!.toByteArray())
                } catch (e: Exception) {
                    result?.optString("identity")?.let { runCatching { NativeBridge.call("piv_close", json("identity" to it)) } }
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    reset(PivErrors.message(e.message) ?: "PIV operation failed. Reconnect your YubiKey and unlock again.")
                } finally { request.remove("pin"); request.remove("managementKey") }
            }
        }
    }
}

object PivErrors {
    private val messages = setOf(
        "PIV operation failed. Reconnect your YubiKey and unlock again.",
        "Unsupported PIV policy selection.",
        "PIV PIN is blocked. Use your recovery procedure on your computer.",
        "Incorrect PIV PIN. 1 attempt remains. No automatic retry.",
        "Incorrect PIV PIN. 2 attempts remain. No automatic retry.",
        "Incorrect PIV PIN. No automatic retry.", "PIV PIN must contain 6–8 ASCII characters.",
        "Cannot open these PIV slots. Check the selected slots, PIV interface and YubiKey firmware (5.3+).",
        "YubiKey session expired. Unlock again.", "Re-enter the Git token for your YubiKey participant.",
        "This YubiKey participant is not enrolled in this wallet. Select its existing slots or enroll it on your computer.",
        "No participant in this wallet matches the connected YubiKey. No PIN was sent.",
        "The connected YubiKey does not match the selected wallet participant. No PIN was sent.",
        "This YubiKey has fewer than two empty PIV slots.", "This YubiKey has fewer than two existing P-256 PIV slots.",
        "Confirm generation in the selected empty PIV slots.", "The YubiKey changed. Detect it again before generating keys.",
        "A selected PIV slot is occupied or cannot be verified empty. Nothing was changed.",
        "Management key must be 32, 48 or 64 hexadecimal characters.",
        "Management authentication failed. No keys were generated.",
        "Provisioning stopped. A slot may now contain a generated key. Inspect the slots on your computer before trying again.")
    fun message(value: String?): String? = value?.takeIf { it in messages }
}

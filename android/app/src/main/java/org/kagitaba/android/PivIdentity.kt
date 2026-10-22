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
        fun label(value: String) = TextView(activity).also { it.text = value; WalletTheme.caption(it); layout.addView(it) }
        val status = label("Connect a YubiKey over USB or NFC.")
        layout.removeView(status)
        val keyRow = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL; layout.addView(this) }
        keyRow.addView(status, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        val refresh = Button(activity).apply {
            text = "↻"; contentDescription = "Refresh YubiKey"; WalletTheme.button(this)
            keyRow.addView(this, LinearLayout.LayoutParams(WalletTheme.dp(activity, 48), WalletTheme.dp(activity, 48)))
        }
        var generate = provision
        val options = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE; layout.addView(this) }
        fun optionLabel(text: String) { options.addView(TextView(activity).apply { this.text = text; WalletTheme.caption(this); if (text == "YubiKey PIV PIN") setTypeface(typeface, android.graphics.Typeface.BOLD); setPadding(0, WalletTheme.dp(activity, 12), 0, WalletTheme.dp(activity, 8)) }) }
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
        val policyViews = mutableListOf<View>()
        fun policyPicker(title: String, values: List<String>, selected: Int): Spinner = chooser(title).apply {
            policyViews.add(options.getChildAt(options.childCount - 2)); policyViews.add(this)
            adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, values); setSelection(selected)
        }
        val encPin = if (candidates == null) policyPicker("Encryption PIN policy", listOf("Once per session (default)", "Never — no hardware PIN requirement"), 0) else null
        val encTouch = if (candidates == null) policyPicker("Encryption touch policy", listOf("Never", "Always", "Cached (default)"), 2) else null
        val sigPin = if (candidates == null) policyPicker("Signing PIN policy", listOf("Once per session (default)", "Never — no hardware PIN requirement"), 0) else null
        val sigTouch = if (candidates == null) policyPicker("Signing touch policy", listOf("Never", "Always (default)", "Cached"), 1) else null
        if (candidates == null) { optionLabel("Policies are fixed at key creation. Cached touch lasts briefly. PIN Always needs per-operation PIN prompts, which are not supported. Kagitaba still asks for a PIV PIN when PIN Never is selected."); policyViews.add(options.getChildAt(options.childCount - 1)) }
        val currentPolicies = TextView(activity).also { it.setTextColor(WalletTheme.ink); options.addView(it) }
        var slotPolicies = JSONObject()
        var matches = emptyList<JSONObject>()
        var slots = emptyList<Int>()
        fun showPolicies() {
            currentPolicies.visibility = if (generate) View.GONE else View.VISIBLE
            if (generate) return
            val selected = if (candidates != null) matches.getOrNull(participants!!.selectedItemPosition) else null
            val encryption = selected?.optJSONObject("encryptionPolicy") ?: slots.getOrNull(encSlots?.selectedItemPosition ?: -1)?.let { slotPolicies.optJSONObject(it.toString()) }
            val signing = selected?.optJSONObject("signingPolicy") ?: slots.getOrNull(sigSlots?.selectedItemPosition ?: -1)?.let { slotPolicies.optJSONObject(it.toString()) }
            currentPolicies.text = "Current device policies (read-only)\n" + policyDescription("Encryption", encryption) + "\n" + policyDescription("Signing", signing)
        }
        val pin = field("YubiKey PIV PIN")
        val slotMode = if (candidates == null) RadioGroup(activity).also { options.addView(it, 0) } else null
        val existingMode = slotMode?.let { RadioButton(activity).apply { id = View.generateViewId(); text = "Use existing slots"; it.addView(this) } }
        val newMode = slotMode?.let { RadioButton(activity).apply { id = View.generateViewId(); text = "Enroll new slots"; it.addView(this) } }
        val managementHeading = if (candidates == null) TextView(activity).also { it.text = "Management key"; WalletTheme.caption(it); options.addView(it) } else null
        val management = if (candidates == null) EditText(activity).also {
            it.isSingleLine = true; it.isSaveEnabled = false; it.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            it.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; WalletTheme.field(it); options.addView(it)
        } else null
        val factory = if (candidates == null) Button(activity).also {
            it.text = "Default"; WalletTheme.button(it); options.addView(it)
            it.setOnClickListener { management!!.setText("010203040506070801020304050607080102030405060708") }
        } else null
        val consent = if (candidates == null) CheckBox(activity).also { it.text = "Create keys in the selected empty slots"; it.setTextColor(WalletTheme.ink); options.addView(it) } else null
        var occupiedSlots = emptyList<Int>()
        var emptySlots = emptyList<Int>()
        var serial = ""
        var finished = false
        var attempting = false
        var discovery: YubiKitManager? = null
        var detectedDevice: YubiKeyDevice? = null
        var pending: PivConnection? = null
        val dialog = AlertDialog.Builder(activity).setTitle(if (candidates == null) "Choose PIV key" else "Unlock wallet")
            .setView(ScrollView(activity).apply { WalletTheme.persistentScrollbar(this); addView(layout) }).setPositiveButton("Detect YubiKey", null).setNegativeButton("Cancel", null).create()
        fun updateSlots() {
            if (candidates != null) return
            slots = if (generate) emptySlots else occupiedSlots
            for ((spinner, default) in listOf(encSlots!! to 0x82, sigSlots!! to 0x83)) {
                spinner.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, slots.map { "${it.toString(16).uppercase()}${if (it == default) " default" else ""}" })
                spinner.setSelection(slots.indexOf(default).takeIf { it >= 0 } ?: if (default == 0x83 && slots.size > 1) 1 else 0)
            }
            for (view in listOfNotNull(managementHeading, management, factory, consent)) view.visibility = if (generate) View.VISIBLE else View.GONE
            for (view in policyViews) view.visibility = if (generate) View.VISIBLE else View.GONE
            showPolicies()
            management?.text?.clear(); consent?.isChecked = false
            dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.text = if (generate) "Create keys" else "Unlock"
        }
        slotMode?.setOnCheckedChangeListener { _, selected -> generate = selected == newMode!!.id; updateSlots() }
        val slotSelection = object : AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: AdapterView<*>?) { showPolicies() }
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                consent?.isChecked = false
                showPolicies()
                val encryption = slots.getOrNull(encSlots?.selectedItemPosition ?: -1)
                val signing = slots.getOrNull(sigSlots?.selectedItemPosition ?: -1)
                if (encryption != null && signing != null)
                    consent?.text = "Yes, create keys in ${encryption.toString(16).uppercase()} and ${signing.toString(16).uppercase()}"
            }
        }
        encSlots?.onItemSelectedListener = slotSelection
        sigSlots?.onItemSelectedListener = slotSelection
        for (spinner in listOfNotNull(participants, encPin, encTouch, sigPin, sigTouch)) spinner.onItemSelectedListener = slotSelection
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
            attempting = true; status.text = "Reading PIV slots…"
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
                        occupiedSlots = result.getJSONArray("occupiedSlots").let { values -> (0 until values.length()).map { values.getInt(it) } }
                        emptySlots = result.getJSONArray("emptySlots").let { values -> (0 until values.length()).map { values.getInt(it) } }
                        check(occupiedSlots.size >= 2 || emptySlots.size >= 2) { "This YubiKey has fewer than two empty PIV slots." }
                        existingMode!!.isEnabled = occupiedSlots.size >= 2
                        newMode!!.isEnabled = emptySlots.size >= 2
                        generate = occupiedSlots.size < 2 || generate && emptySlots.size >= 2
                        slotMode!!.check(if (generate) newMode.id else existingMode.id)
                        updateSlots()
                    }
                    pending = opened; opened = null; detectedDevice = device
                    showPolicies()
                    attempting = false; options.visibility = View.VISIBLE
                    status.text = if (candidates != null) "${matches.size} matching participant(s)" else "YubiKey $serial"
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply { text = if (generate) "Create keys" else "Unlock"; isEnabled = true }
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
        refresh.setOnClickListener {
            if (!attempting) { reset("Detecting YubiKey…"); dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick() }
        }
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
            if (generate) {
                if (consent?.isChecked != true) { status.text = "Confirm generation in the selected empty PIV slots."; return@setOnClickListener }
                request.put("op", "provision").put("confirmed", true).put("managementKey", management!!.text.toString().trim())
                request.put("encryptionPolicy", json("pin" to if (encPin!!.selectedItemPosition == 0) 2 else 1, "touch" to encTouch!!.selectedItemPosition + 1))
                request.put("signingPolicy", json("pin" to if (sigPin!!.selectedItemPosition == 0) 2 else 1, "touch" to sigTouch!!.selectedItemPosition + 1))
            }
            request.put("pin", enteredPin); pin.text.clear(); management?.text?.clear()
            attempting = true; dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
            status.text = if (generate) "Generating keys. Keep the YubiKey connected and touch it when requested…" else "Unlocking. Touch the YubiKey if requested…"
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
        "Sync token belongs to another key. Unlock with that key or enter a Git token in Connection settings.",
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

package org.kagitaba.android

import android.app.AlertDialog
import android.content.Context
import androidx.fragment.app.FragmentActivity
import org.json.JSONArray
import org.json.JSONObject

/** Selects a private-operation backend; both expose the same participant format. */
class WalletIdentity(context: Context) {
    private val piv = PivIdentity(context)
    private val phone = PhoneIdentity(context)
    @Volatile private var usingPhone = false
    val touchListeners get() = piv.touchListeners
    val touchPolicy get() = if (usingPhone) -1 else piv.touchPolicy
    private var chooser: AlertDialog? = null
    fun publicInfo(): JSONObject = if (usingPhone) phone.publicInfo() else piv.publicInfo()
    fun attach(activity: FragmentActivity) = phone.attach(activity)
    fun detach(activity: FragmentActivity, owner: Vault, preserveSession: Boolean = false) {
        if (usingPhone) phone.detach(activity, owner, preserveSession)
    }
    fun close() { val old = chooser; chooser = null; android.os.Handler(android.os.Looper.getMainLooper()).post { old?.dismiss() }; phone.close(); piv.close() }
    fun authenticate(activity: FragmentActivity, candidates: JSONArray?, provision: Boolean = false, owner: Vault,
                     onSuccess: (ByteArray) -> Unit, onError: (String) -> Unit) {
        close()
        val epoch = owner.epoch
        chooser = AlertDialog.Builder(activity).setTitle("Unlock with")
            .setItems(arrayOf("Phone · StrongBox", "YubiKey · USB / NFC")) { _, index ->
                if (owner.epoch != epoch || activity.isFinishing) return@setItems
                usingPhone = index == 0
                if (usingPhone) phone.authenticate(activity, candidates, owner, onSuccess, onError)
                else piv.authenticate(activity, candidates, provision, owner, onSuccess, onError)
            }.setNegativeButton("Cancel", null).show()
    }
}

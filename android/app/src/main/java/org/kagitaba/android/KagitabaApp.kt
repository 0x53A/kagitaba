package org.kagitaba.android

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper

class KagitabaApp : Application() {
    lateinit var vault: Vault
    lateinit var wallets: WalletCatalog
    private val generations = java.util.concurrent.atomic.AtomicLong()
    fun nextEpoch(): Long = generations.incrementAndGet()
    fun selectWallet(id: String) {
        if (vault.walletId == id) return
        vault.lock()
        wallets.select(id)
        vault = Vault(this, wallets.root(id), id)
    }
    private val handler = Handler(Looper.getMainLooper())
    private val idleLock = Runnable { vault.lock() }
    override fun onCreate() {
        super.onCreate()
        wallets = WalletCatalog(this)
        val selected = wallets.selected()
        vault = if (selected != null) Vault(this, wallets.root(selected), selected) else Vault(this, java.io.File(noBackupFilesDir, "unselected"), "")
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) { vault.lock() }
        }, IntentFilter(Intent.ACTION_SCREEN_OFF), RECEIVER_NOT_EXPORTED)
    }
    fun touch() { handler.removeCallbacks(idleLock); handler.postDelayed(idleLock, 120_000) }
}
val Context.vault: Vault get() = (applicationContext as KagitabaApp).vault

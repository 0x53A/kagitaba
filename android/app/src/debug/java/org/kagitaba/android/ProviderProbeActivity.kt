package org.kagitaba.android

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle

/** Debug-only result collector for synthetic platform-request instrumentation. */
class ProviderProbeActivity : Activity() {
    companion object {
        @Volatile var response: Intent? = null
        @Volatile var result: Int? = null
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        response = null; result = null
        val pending = intent.getParcelableExtra("pending", PendingIntent::class.java) ?: error("Missing test request")
        startIntentSenderForResult(pending.intentSender, 1, intent.getParcelableExtra("request", Intent::class.java), 0, 0, 0)
    }
    @Deprecated("Debug-only test result receiver")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        response = data; result = resultCode; finish()
    }
}

package org.kagitaba.android

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock

/** No secrets in intents; selection bindings live only in this process. */
object RequestTickets {
    data class Ticket(val kind: String, val entryId: String? = null, val credentialId: String? = null,
        val optionId: String? = null, val expires: Long = SystemClock.elapsedRealtime() + 120_000)
    private val tickets = mutableMapOf<String, Ticket>()
    @Synchronized fun clear() { tickets.clear() }
    @Synchronized fun issue(context: Context, ticket: Ticket, activity: Class<*> = ProviderActivity::class.java): PendingIntent {
        tickets.entries.removeAll { it.value.expires < SystemClock.elapsedRealtime() }
        require(tickets.size < 1024) { "Too many pending requests" }
        val token = java.util.UUID.randomUUID().toString()
        tickets[token] = ticket
        val intent = Intent(context, activity).setData(Uri.parse("kagitaba://request/$token"))
        return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_ONE_SHOT)
    }
    @Synchronized fun take(intent: Intent): Ticket? = tickets.remove(intent.data?.lastPathSegment)?.takeIf { it.expires >= SystemClock.elapsedRealtime() }
}

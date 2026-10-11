package org.kagitaba.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class ReviewRegressionTest {
    @Test fun lockDoesNotWaitForPrivateWorkAndRejectsItsLateResult() {
        val counter = AtomicLong()
        val session = UnlockSession { counter.incrementAndGet() }
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val failure = AtomicReference<Throwable>()
        session.open(byteArrayOf(1, 2, 3))
        val worker = thread {
            try { session.use { entered.countDown(); release.await(); "late secret" } }
            catch (e: Throwable) { failure.set(e) }
        }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        val locker = thread { session.invalidate() }
        try {
            locker.join(1000)
            assertFalse("Lock must finish while the private operation is still pending", locker.isAlive)
            assertFalse(session.unlocked)
            session.open(byteArrayOf(4)) // A new unlock must not revive an old lease.
        } finally { release.countDown(); worker.join(2000); locker.join(2000) }
        assertEquals("Authentication expired", failure.get()?.message)
    }

    @Test fun loginEditsPreserveFieldExtensions() {
        val item = WalletItem("synthetic", JSONObject("""{"entity":{"credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":"old","label":"Account","vendor":{"id":7}},"password":{"fieldType":"concealed-string","value":"old","vendor":true}}]}}"""))
        item.updateLogin("new", "new secret")
        val basic = item.credentials("basic-auth").single()
        assertEquals("Account", basic.getJSONObject("username").getString("label"))
        assertEquals(7, basic.getJSONObject("username").getJSONObject("vendor").getInt("id"))
        assertTrue(basic.getJSONObject("password").getBoolean("vendor"))
        assertEquals("new secret", basic.getJSONObject("password").getString("value"))
    }
}

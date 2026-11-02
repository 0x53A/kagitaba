package org.kagitaba.android

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class PhoneSessionTest {
    @Test fun lockRejectsLateEnrollmentOrAuthenticationCallback() {
        val epochs = AtomicLong()
        val session = UnlockSession { epochs.incrementAndGet() }
        val expected = session.epoch
        session.invalidate()
        val handle = "phone:1".toByteArray()
        assertFalse(session.openIfCurrent(handle, expected))
        assertArrayEquals(ByteArray(handle.size), handle)
        assertFalse(session.unlocked)
        assertTrue(session.openIfCurrent("phone:2".toByteArray(), session.epoch))
    }
    @Test fun lockDoesNotWaitForPrivateWorkAndRejectsItsLateResult() {
        val epochs = AtomicLong()
        val session = UnlockSession { epochs.incrementAndGet() }
        session.open("phone:1".toByteArray())
        val started = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val finished = CountDownLatch(1)
        var error: Throwable? = null
        val worker = Thread {
            try { session.use { started.countDown(); resume.await(); "late plaintext" } }
            catch (e: Throwable) { error = e }
            finally { finished.countDown() }
        }
        worker.start()
        assertTrue(started.await(2, TimeUnit.SECONDS))
        session.invalidate()
        assertFalse(session.unlocked)
        resume.countDown()
        assertTrue(finished.await(2, TimeUnit.SECONDS))
        assertEquals("Authentication expired", error?.message)
    }
}

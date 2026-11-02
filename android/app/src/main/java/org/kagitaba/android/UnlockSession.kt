package org.kagitaba.android

/** Private work holds a lease, never the monitor needed to lock the UI. */
class UnlockSession(private val nextEpoch: () -> Long) {
    private val gate = Any()
    private var identity: ByteArray? = null
    private var generation = nextEpoch()
    val epoch get() = synchronized(gate) { generation }
    val unlocked get() = synchronized(gate) { identity != null }
    fun open(bytes: ByteArray) = synchronized(gate) {
        identity?.fill(0); identity = bytes; generation = nextEpoch()
    }
    fun openIfCurrent(bytes: ByteArray, expected: Long): Boolean = synchronized(gate) {
        if (generation != expected) { bytes.fill(0); false }
        else { identity?.fill(0); identity = bytes; generation = nextEpoch(); true }
    }
    fun invalidate() = synchronized(gate) {
        identity?.fill(0); identity = null; generation = nextEpoch()
    }
    fun <T> use(block: (ByteArray) -> T): T {
        val (bytes, captured) = synchronized(gate) {
            (identity ?: error("Unlock your wallet first")).copyOf() to generation
        }
        try {
            val result = block(bytes)
            check(epoch == captured) { "Authentication expired" }
            return result
        } finally { bytes.fill(0) }
    }
}

package org.kagitaba.android

import org.junit.Assert.*
import org.junit.Test

class WalletErrorsTest {
    @Test fun wrongSyncTokenKeyHasItsOwnSafeMessage() {
        val message = "Sync token belongs to another key. Unlock with that key or enter a Git token in Connection settings."
        assertEquals(message, PivErrors.message(message))
        assertNull(PivErrors.message("$message private-token"))
    }

    @Test fun nativeFailureCategoriesRemainActionableWithoutForwardingSecrets() {
        val history = "Unsupported wallet history. Update all clients to a version supporting signed merges."
        val storage = "Wallet storage could not be read or written. Check available device storage and retry."
        assertEquals(history, WalletErrors.nativeMessage(history))
        assertEquals(storage, WalletErrors.nativeMessage(storage))
        assertNull(WalletErrors.nativeMessage("$history private-token-value"))
        assertNull(WalletErrors.nativeMessage("https://user:private-token-value@example.test"))
        assertNull(WalletErrors.nativeMessage("Wallet validation or storage failed"))
    }
}

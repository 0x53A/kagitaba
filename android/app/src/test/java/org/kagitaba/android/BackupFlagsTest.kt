package org.kagitaba.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackupFlagsTest {
    @Test fun credentialStateOverridesRequestIncludingLegacyAbsenceAndMalformedNull() {
        fun attack() = JSONObject("""{"kagitabaBackupFlags":{"eligible":false,"state":false}}""")
        assertFalse(Passkeys.withBackupFlags(attack(), JSONObject()).has("kagitabaBackupFlags"))
        val stored=JSONObject("""{"kagitabaBackupFlags":{"eligible":true,"state":true}}""")
        assertTrue(Passkeys.withBackupFlags(attack(),stored).getJSONObject("kagitabaBackupFlags").getBoolean("state"))
        assertTrue(Passkeys.withBackupFlags(attack(),JSONObject().put("kagitabaBackupFlags",JSONObject.NULL)).isNull("kagitabaBackupFlags"))
    }
}

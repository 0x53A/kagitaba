use crate::{Error, Result};

/// Public routing metadata, never an authentication credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceHint {
    pub serial: String,
    pub encryption_slot: u8,
    pub signing_slot: u8,
}

impl DeviceHint {
    pub fn validate(&self) -> Result<()> {
        if self.serial.is_empty()
            || self.serial.len() > 32
            || !self.serial.bytes().all(|b| b.is_ascii_digit())
            || !(0x82..=0x95).contains(&self.encryption_slot)
            || !(0x82..=0x95).contains(&self.signing_slot)
            || self.encryption_slot == self.signing_slot
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "serial": self.serial,
            "encryptionSlot": self.encryption_slot,
            "signingSlot": self.signing_slot,
        }))
        .map_err(|_| Error::Invalid)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 {
            return Err(Error::Invalid);
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if value["version"].as_u64() != Some(1) {
            return Err(Error::Invalid);
        }
        let slot = |name: &str| -> Result<u8> {
            value[name]
                .as_u64()
                .and_then(|v| v.try_into().ok())
                .ok_or(Error::Invalid)
        };
        let hint = Self {
            serial: value["serial"].as_str().ok_or(Error::Invalid)?.to_owned(),
            encryption_slot: slot("encryptionSlot")?,
            signing_slot: slot("signingSlot")?,
        };
        hint.validate()?;
        Ok(hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_routing_metadata_is_rejected() {
        for json in [
            r#"{"version":2,"serial":"123","encryptionSlot":130,"signingSlot":131}"#,
            r#"{"version":1,"serial":"","encryptionSlot":130,"signingSlot":131}"#,
            r#"{"version":1,"serial":"123","encryptionSlot":130,"signingSlot":130}"#,
            r#"{"version":1,"serial":"123","encryptionSlot":249,"signingSlot":131}"#,
            r#"{"version":1,"serial":"123","encryptionSlot":386,"signingSlot":131}"#,
        ] {
            assert!(DeviceHint::from_json(json.as_bytes()).is_err());
        }
    }
}

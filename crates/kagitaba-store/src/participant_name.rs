use crate::{Error, Result};

/// Names are public display hints, not identities. Fingerprints remain visible.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.trim() != name
        || name.len() > 512
        || name.chars().count() > 128
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

pub(super) fn from_json(data: &[u8]) -> Result<String> {
    if data.len() > 1024 {
        return Err(Error::InvalidName);
    }
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|_| Error::InvalidName)?;
    if value.as_object().is_none_or(|o| o.len() != 2) || value["version"].as_u64() != Some(1) {
        return Err(Error::InvalidName);
    }
    let name = value["name"].as_str().ok_or(Error::InvalidName)?;
    validate_name(name)?;
    Ok(name.into())
}

pub(super) fn to_json(name: &str) -> Result<Vec<u8>> {
    validate_name(name)?;
    serde_json::to_vec(&serde_json::json!({"version":1,"name":name}))
        .map_err(|_| Error::InvalidName)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_names_are_bounded_and_cannot_hide_fingerprints_with_controls() {
        for invalid in [
            "",
            " leading",
            "trailing ",
            "line\nbreak",
            "bad\u{202e}name",
            "bad\u{2066}name",
        ] {
            assert!(validate_name(invalid).is_err());
        }
        assert!(validate_name(&"x".repeat(129)).is_err());
        for name in ["Lukas · Pixel", "Backup key", "鍵 🔑"] {
            assert_eq!(from_json(&to_json(name).unwrap()).unwrap(), name);
        }
        assert!(from_json(br#"{"version":2,"name":"Test"}"#).is_err());
        assert!(from_json(br#"{"version":1,"name":"Test","extra":true}"#).is_err());
    }
}

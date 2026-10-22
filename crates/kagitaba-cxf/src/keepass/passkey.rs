//! Conservative KeePassXC/KeePassDX KPEX passkey conversion.
use crate::WarningDetail;
use keepass::db::EntryRef;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;
type MappingResult = std::result::Result<Value, WarningDetail>;
fn problem(
    field: Option<&'static str>,
    reason: &'static str,
    action: &'static str,
) -> WarningDetail {
    WarningDetail {
        field,
        reason,
        action,
    }
}

pub(super) const FIELDS: &[&str] = &[
    "KPEX_PASSKEY_CREDENTIAL_ID",
    "KPEX_PASSKEY_FLAG_BE",
    "KPEX_PASSKEY_FLAG_BS",
    "KPEX_PASSKEY_PRIVATE_KEY_PEM",
    "KPEX_PASSKEY_RELYING_PARTY",
    "KPEX_PASSKEY_USERNAME",
    "KPEX_PASSKEY_USER_HANDLE",
];

pub(super) fn present(entry: &EntryRef<'_>) -> bool {
    entry
        .fields
        .keys()
        .any(|key| key.starts_with("KPEX_PASSKEY_") || key.starts_with("KPXC_PASSKEY_"))
}

pub(super) fn convert(entry: &EntryRef<'_>) -> MappingResult {
    if entry.fields.contains_key("KPEX_PASSKEY_PRF") {
        return Err(problem(
            Some("KPEX_PASSKEY_PRF"),
            "This passkey has a PRF secret; PRF is not supported.",
            "Keep using this passkey in the source app. Do not remove its PRF field; sites may depend on it.",
        ));
    }
    if entry.fields.keys().any(|key| {
        (key.starts_with("KPEX_PASSKEY_") || key.starts_with("KPXC_PASSKEY_"))
            && !FIELDS.contains(&key.as_str())
    }) {
        return Err(problem(
            Some("KPEX_PASSKEY_* / KPXC_PASSKEY_*"),
            "An additional passkey field has unsupported semantics.",
            "Keep using the source app. Inspect the retained field names before requesting support; do not discard counters or extensions.",
        ));
    }
    convert_fields(|name| entry.fields.get(name).map(|value| value.get().as_str()))
}

fn convert_fields<'a>(get: impl Fn(&str) -> Option<&'a str>) -> MappingResult {
    let required = |name: &'static str| {
        get(name).ok_or_else(|| problem(Some(name),
        "A required passkey field is missing.", "Re-export a complete passkey from the source app. Keep using the original until all required fields are available."))
    };
    let parse_bytes =
        |name: &'static str| -> std::result::Result<Zeroizing<Vec<u8>>, WarningDetail> {
            decode(required(name)?).ok_or_else(|| problem(Some(name), "The passkey identifier is not valid base64url.", "Re-export this passkey from the source app; do not generate a replacement identifier."))
        };
    let credential_id = parse_bytes("KPEX_PASSKEY_CREDENTIAL_ID")?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(problem(
            Some("KPEX_PASSKEY_CREDENTIAL_ID"),
            "The credential ID length is unsupported.",
            "Keep using this passkey in the source app and request support for its identifier format.",
        ));
    }
    let user_handle = parse_bytes("KPEX_PASSKEY_USER_HANDLE")?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(problem(
            Some("KPEX_PASSKEY_USER_HANDLE"),
            "The user handle must contain 1–64 bytes.",
            "Re-export this passkey; never substitute the username or a newly generated handle.",
        ));
    }
    let parse_flag = |name: &'static str| -> std::result::Result<bool, WarningDetail> {
        // Legacy KeePassXC omitted both flags and used false. Apply the chosen
        // compatibility policy only to absent fields; explicit values stay strict.
        let value = get(name).unwrap_or("0");
        flag(value).ok_or_else(|| problem(Some(name), "The backup flag is not 0, 1, true or false.", "Check the original flag in the source app and export its boolean value without changing its meaning."))
    };
    let eligible = parse_flag("KPEX_PASSKEY_FLAG_BE")?;
    let state = parse_flag("KPEX_PASSKEY_FLAG_BS")?;
    if state && !eligible {
        return Err(problem(
            Some("KPEX_PASSKEY_FLAG_BE / KPEX_PASSKEY_FLAG_BS"),
            "Backup state is true but backup eligibility is false.",
            "Resolve the inconsistent flags in the source app using the original registration settings; do not guess new values.",
        ));
    }
    let rp = required("KPEX_PASSKEY_RELYING_PARTY")?;
    if !valid_rp(rp) {
        return Err(problem(
            Some("KPEX_PASSKEY_RELYING_PARTY"),
            "The relying-party ID is not a supported canonical domain.",
            "Re-export the original relying-party domain. It must not be a URL, path, port or IP address.",
        ));
    }
    let username = required("KPEX_PASSKEY_USERNAME")?;
    let pem = required("KPEX_PASSKEY_PRIVATE_KEY_PEM")?.trim();
    let key_error = || {
        problem(
            Some("KPEX_PASSKEY_PRIVATE_KEY_PEM"),
            "The private key is not a valid supported P-256 PKCS#8 PEM key.",
            "Kagitaba currently supports ES256/P-256 only. Keep RSA/Ed25519 passkeys in the source app; re-export malformed keys without editing secret material.",
        )
    };
    if (!pem.starts_with("-----BEGIN PRIVATE KEY-----\n")
        && !pem.starts_with("-----BEGIN PRIVATE KEY-----\r\n"))
        || !pem.ends_with("-----END PRIVATE KEY-----")
    {
        return Err(key_error());
    }
    let key = p256::SecretKey::from_pkcs8_pem(pem).map_err(|_| key_error())?;
    let der = key.to_pkcs8_der().map_err(|_| key_error())?;
    Ok(
        json!({"type":"passkey", "credentialId":data_encoding::BASE64URL_NOPAD.encode(&credential_id),
        "rpId":rp,"username":username,"userDisplayName":username,
        "userHandle":data_encoding::BASE64URL_NOPAD.encode(&user_handle),"key":data_encoding::BASE64URL_NOPAD.encode(der.as_bytes()),
        "kagitabaBackupFlags":{"eligible":eligible,"state":state}}),
    )
}

fn flag(value: &str) -> Option<bool> {
    match value {
        "0" | "false" => Some(false),
        "1" | "true" => Some(true),
        _ => None,
    }
}

fn decode(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    // Accept canonical padded and unpadded URL-safe encodings, never mixed alphabets.
    let decoded = if value.contains('=') {
        data_encoding::BASE64URL.decode(value.as_bytes()).ok()?
    } else {
        data_encoding::BASE64URL_NOPAD
            .decode(value.as_bytes())
            .ok()?
    };
    Some(Zeroizing::new(decoded))
}

fn valid_rp(rp: &str) -> bool {
    if rp.is_empty()
        || rp.len() > 253
        || !rp.is_ascii()
        || rp.bytes().any(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    if !matches!(url::Host::parse(rp), Ok(url::Host::Domain(ref domain)) if domain == rp) {
        return false;
    }
    rp.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn fixture() -> BTreeMap<&'static str, Zeroizing<String>> {
        let key = p256::SecretKey::from_slice(&[7; 32]).unwrap();
        BTreeMap::from([
            (FIELDS[0], Zeroizing::new("AQIDBA".into())),
            (FIELDS[1], Zeroizing::new("1".into())),
            (FIELDS[2], Zeroizing::new("0".into())),
            (
                FIELDS[3],
                key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap(),
            ),
            (FIELDS[4], Zeroizing::new("example.test".into())),
            (FIELDS[5], Zeroizing::new("synthetic-user".into())),
            (FIELDS[6], Zeroizing::new("BQYHCA".into())),
        ])
    }
    #[test]
    fn p256_identity_and_explicit_backup_flags_are_preserved() {
        let mut source = fixture();
        for (be, bs) in [("0", "0"), ("1", "0"), ("true", "true")] {
            source.insert(FIELDS[1], Zeroizing::new(be.into()));
            source.insert(FIELDS[2], Zeroizing::new(bs.into()));
            let value = crate::json::SecretJson(
                convert_fields(|name| source.get(name).map(|s| s.as_str())).unwrap(),
            );
            assert_eq!(value.0["credentialId"], "AQIDBA");
            assert_eq!(value.0["userHandle"], "BQYHCA");
            assert_eq!(value.0["rpId"], "example.test");
            assert_eq!(
                value.0["kagitabaBackupFlags"]["eligible"],
                flag(be).unwrap()
            );
            assert_eq!(value.0["kagitabaBackupFlags"]["state"], flag(bs).unwrap());
            let der = decode(value.0["key"].as_str().unwrap()).unwrap();
            let key = p256::SecretKey::from_pkcs8_der(&der).unwrap();
            assert_eq!(key.to_bytes().as_slice(), &[7; 32]);
        }
    }
    #[test]
    fn absent_backup_flags_use_legacy_zero_without_overriding_explicit_values() {
        for (be,bs,eligible,state) in [
            (None,None,false,false), (None,Some("0"),false,false),
            (Some("1"),None,true,false), (Some("1"),Some("1"),true,true),
        ] {
            let mut source=fixture();
            source.remove(FIELDS[1]); source.remove(FIELDS[2]);
            if let Some(value)=be { source.insert(FIELDS[1],Zeroizing::new(value.into())); }
            if let Some(value)=bs { source.insert(FIELDS[2],Zeroizing::new(value.into())); }
            let value=crate::json::SecretJson(convert_fields(|name|source.get(name).map(|v|v.as_str())).unwrap());
            assert_eq!(value.0["kagitabaBackupFlags"]["eligible"],eligible);
            assert_eq!(value.0["kagitabaBackupFlags"]["state"],state);
        }
        for invalid in ["", "yes", "2"] {
            let mut source=fixture(); source.insert(FIELDS[1],Zeroizing::new(invalid.into()));
            assert!(convert_fields(|name|source.get(name).map(|v|v.as_str())).is_err());
        }
    }

    #[test]
    fn malformed_or_ambiguous_fields_never_activate() {
        for (name, invalid) in [
            (FIELDS[0], "%bad"),
            (FIELDS[6], ""),
            (FIELDS[1], "yes"),
            (FIELDS[4], "https://example.test"),
            (FIELDS[4], "example.test/"),
            (FIELDS[4], "127.0.0.1"),
            (FIELDS[4], "Example.test"),
            (
                FIELDS[3],
                "-----BEGIN EC PRIVATE KEY-----\nbad\n-----END EC PRIVATE KEY-----",
            ),
        ] {
            let mut source = fixture();
            source.insert(name, Zeroizing::new(invalid.into()));
            assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_err());
        }
        let mut source = fixture();
        source.remove(FIELDS[1]);
        source.insert(FIELDS[2], Zeroizing::new("1".into()));
        assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_err());
        source.insert(FIELDS[1], Zeroizing::new("0".into()));
        source.insert(FIELDS[2], Zeroizing::new("1".into()));
        assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_err());
    }
    #[test]
    fn other_pkcs8_algorithms_and_oversized_handles_are_rejected() {
        // Structurally valid RFC 8410 Ed25519 PKCS#8; current providers are ES256.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[9; 32]);
        let pem = Zeroizing::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            data_encoding::BASE64.encode(&der)
        ));
        let mut source = fixture();
        source.insert(FIELDS[3], pem);
        assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_err());
        let mut source = fixture();
        source.insert(
            FIELDS[6],
            Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&[3; 65])),
        );
        assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_err());
        let mut source = fixture();
        source.insert(FIELDS[0], Zeroizing::new("AQIDBA==".into()));
        assert!(convert_fields(|name| source.get(name).map(|s| s.as_str())).is_ok());
    }
    #[test]
    fn diagnostics_identify_safe_fields_and_never_suggest_guessing_flags() {
        let mut source = fixture();
        source.insert(
            "KPEX_PASSKEY_FLAG_BE",
            Zeroizing::new("private-invalid-value".into()),
        );
        let detail = convert_fields(|name| source.get(name).map(|v| v.as_str()))
            .err()
            .unwrap();
        assert_eq!(detail.field, Some("KPEX_PASSKEY_FLAG_BE"));
        assert!(!format!("{detail:?}").contains("private-invalid-value"));
        assert!(detail.reason.contains("not 0"));
        let mut source = fixture();
        source.insert(
            "KPEX_PASSKEY_CREDENTIAL_ID",
            Zeroizing::new("private-invalid-value%".into()),
        );
        let detail = convert_fields(|name| source.get(name).map(|v| v.as_str()))
            .err()
            .unwrap();
        assert_eq!(detail.field, Some("KPEX_PASSKEY_CREDENTIAL_ID"));
        assert!(detail.reason.contains("base64url"));
    }
}

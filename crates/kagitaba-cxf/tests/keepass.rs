#![cfg(feature = "keepass")]

use ::keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, KdfConfig},
    db::Value,
};
use kagitaba_cxf::{Error, WarningKind, keepass};

fn database() -> Database {
    let mut config = DatabaseConfig::default();
    config.kdf_config = KdfConfig::Aes { rounds: 10 };
    let mut db = Database::with_config(config);
    {
        let mut root = db.root_mut();
        root.name = "Root".into();
        let mut group = root.add_group();
        group.name = "Email".into();
        let mut entry = group.add_entry();
        entry.set_unprotected("Title", "Mail");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "test-secret");
        entry.set_unprotected("URL", "https://example.test");
        entry.set_unprotected("Notes", "remember this");
        entry.set_protected("Private custom", "custom-secret");
        entry.set_protected("otp", "otpauth://totp/Mail:alice?secret=JBSWY3DPEHPK3PXP");
        entry.tags.push("personal".into());
    }
    db
}

#[test]
fn empty_password_and_absent_password_are_distinct_components() {
    let db = database();
    let keyfile = [9u8; 32];
    for password in [None, Some("")] {
        let mut key = DatabaseKey::new()
            .with_keyfile(&mut std::io::Cursor::new(keyfile))
            .unwrap();
        if let Some(password) = password {
            key = key.with_password(password);
        }
        let mut bytes = Vec::new();
        db.save(&mut bytes, key).unwrap();
        assert!(keepass::from_bytes(&bytes, password, Some(&keyfile)).is_ok());
        let other = if password.is_some() { None } else { Some("") };
        assert!(keepass::from_bytes(&bytes, other, Some(&keyfile)).is_err());
    }
}

#[test]
fn encrypted_password_and_keyfile_import_preserves_group_tree_and_protected_fields() {
    let db = database();
    let keyfile = [7u8; 32];
    let key = DatabaseKey::new()
        .with_password("test-master")
        .with_keyfile(&mut std::io::Cursor::new(keyfile))
        .unwrap();
    let mut bytes = Vec::new();
    db.save(&mut bytes, key).unwrap();
    assert!(matches!(
        keepass::from_bytes(&bytes, Some("test-master"), None),
        Err(Error::KeePassUnlock)
    ));
    assert!(matches!(
        keepass::from_bytes(&bytes, Some("wrong"), Some(&keyfile)),
        Err(Error::KeePassUnlock)
    ));
    let converted = keepass::from_reader(
        std::io::Cursor::new(&bytes),
        Some("test-master"),
        Some(&keyfile),
    )
    .unwrap();
    assert_eq!(converted.report().items, 1);
    assert_eq!(converted.report().root_collections, 1);
    let account = &converted.document().as_json()["accounts"][0];
    let item = &account["items"][0];
    assert_eq!(
        account["collections"][0]["subCollections"][0]["title"],
        "Email"
    );
    assert_eq!(
        account["collections"][0]["subCollections"][0]["items"][0]["item"],
        item["id"]
    );
    let credentials = item["credentials"].as_array().unwrap();
    assert_eq!(
        credentials
            .iter()
            .find(|c| c["type"] == "basic-auth")
            .unwrap()["password"]["value"],
        "test-secret"
    );
    assert_eq!(
        credentials.iter().find(|c| c["type"] == "totp").unwrap()["secret"],
        "JBSWY3DPEHPK3PXP"
    );
    assert_eq!(
        credentials
            .iter()
            .find(|c| c["type"] == "custom-fields")
            .unwrap()["fields"][0]["fieldType"],
        "concealed-string"
    );
    assert_eq!(
        item["extensions"][0]["data"]["fields"]["Password"],
        "test-secret"
    );
    assert!(
        !String::from_utf8(converted.document().to_json().unwrap().to_vec())
            .unwrap()
            .contains("test-master")
    );
}

#[test]
fn recycle_bin_is_excluded_and_attachments_and_field_references_reported() {
    let mut db = database();
    let trash_id = {
        let mut root = db.root_mut();
        let mut trash = root.add_group();
        trash.name = "Trash".into();
        let mut deleted = trash.add_entry();
        deleted.set_protected("Password", "deleted-secret");
        deleted.add_attachment(
            "trash.txt",
            Value::unprotected(b"deleted attachment".to_vec()),
        );
        trash.id()
    };
    db.meta.recyclebin_uuid = Some(trash_id.uuid());
    db.meta.recyclebin_enabled = Some(true);
    {
        let entry_id = db
            .root()
            .groups()
            .find(|g| g.name == "Email")
            .unwrap()
            .entries()
            .next()
            .unwrap()
            .id();
        let mut entry = db.entry_mut(entry_id).unwrap();
        entry.add_attachment(
            "test.txt",
            Value::unprotected(b"attachment contents".to_vec()),
        );
        entry.set_unprotected("Reference", "{REF:P@T:Other}");
    }
    let converted = keepass::from_database(&db).unwrap();
    assert_eq!(converted.report().items, 1);
    for kind in [
        WarningKind::Deleted,
        WarningKind::Attachments,
        WarningKind::FieldReferences,
    ] {
        assert!(converted.report().warnings.iter().any(|w| w.kind == kind));
    }
    let text = String::from_utf8(converted.document().to_json().unwrap().to_vec()).unwrap();
    assert!(!text.contains("deleted-secret"));
    assert!(!text.contains("attachment contents"));
    assert_eq!(converted.attachments().len(), 1);
    assert_eq!(
        converted.attachments()[0].bytes.as_slice(),
        b"attachment contents"
    );
}

#[test]
fn malformed_databases_and_wrong_passwords_return_generic_errors() {
    assert!(matches!(
        keepass::from_bytes(b"not a database", Some("do-not-print"), None),
        Err(Error::KeePassUnlock)
    ));
    let db = database();
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password("correct"))
        .unwrap();
    let error = keepass::from_bytes(&bytes, Some("do-not-print"), None)
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("do-not-print"));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(keepass::from_bytes(&bytes, Some("correct"), None).is_err());
}

#[test]
fn attachments_are_separate_zeroizing_bytes_bound_to_planned_source_items() {
    use rand_core::SeedableRng;
    let mut db = database();
    {
        let mut root = db.root_mut();
        let mut first = root.add_entry();
        first.set_unprotected("Title", "same title");
        first.add_attachment("z.bin", Value::unprotected(vec![0, 255, 17, 42]));
        first.add_attachment("empty.txt", Value::unprotected(Vec::new()));
        let mut second = root.add_entry();
        second.set_unprotected("Title", "same title");
        second.add_attachment(
            "z.bin",
            Value::unprotected(b"different file bytes".to_vec()),
        );
    }
    let mut encrypted = Vec::new();
    db.save(
        &mut encrypted,
        DatabaseKey::new().with_password("synthetic"),
    )
    .unwrap();
    let converted = keepass::from_bytes(&encrypted, Some("synthetic"), None).unwrap();
    assert_eq!(converted.attachments().len(), 3);
    let (document, report, attachments) = converted.into_parts();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::Attachments)
    );
    assert!(
        !String::from_utf8(document.to_json().unwrap().to_vec())
            .unwrap()
            .contains("different file bytes")
    );
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([41; 32]);
    let planned = document
        .plan_import(&kagitaba_core::wallet::Wallet::default(), &mut rng)
        .unwrap()
        .into_entries();
    for file in &attachments {
        let owners: Vec<_> = planned
            .iter()
            .filter(|p| {
                p.source()
                    .is_some_and(|s| s["originalId"] == file.source_item_id)
            })
            .collect();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].entity()["title"], "same title");
    }
    let binary = attachments
        .iter()
        .find(|f| f.bytes.as_slice() == [0, 255, 17, 42])
        .unwrap();
    let empty = attachments.iter().find(|f| f.bytes.is_empty()).unwrap();
    let other = attachments
        .iter()
        .find(|f| f.bytes.as_slice() == b"different file bytes")
        .unwrap();
    assert_eq!(binary.source_item_id, empty.source_item_id);
    assert_ne!(binary.source_item_id, other.source_item_id);
    assert_eq!(binary.name.as_str(), "z.bin");
}

#[test]
fn too_many_or_oversized_attachments_fail_instead_of_partial_extraction() {
    let mut db = database();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        for n in 0..=kagitaba_cxf::attachments::MAX_ATTACHMENTS {
            entry.add_attachment(format!("file-{n}"), Value::unprotected(Vec::new()));
        }
    }
    assert!(matches!(keepass::from_database(&db), Err(Error::SizeLimit)));
    let mut db = database();
    db.root_mut().add_entry().add_attachment(
        "large.bin",
        Value::unprotected(vec![0; kagitaba_cxf::attachments::MAX_FILE_BYTES + 1]),
    );
    assert!(matches!(keepass::from_database(&db), Err(Error::SizeLimit)));
}

fn timeotp_conversion(fields: &[(&str, &str)]) -> kagitaba_cxf::Conversion {
    let mut db = Database::with_config(DatabaseConfig::default());
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Synthetic TOTP");
        for (name, value) in fields { entry.set_protected(*name, *value); }
    }
    keepass::from_database(&db).unwrap()
}

#[test]
fn keepass_timeotp_encodings_generate_rfc_code_and_preserve_source() {
    let bytes = b"12345678901234567890";
    for (name, secret) in [
        ("TimeOtp-Secret", String::from_utf8(bytes.to_vec()).unwrap()),
        ("TimeOtp-Secret-Hex", data_encoding::HEXUPPER.encode(bytes)),
        ("TimeOtp-Secret-Base32", data_encoding::BASE32_NOPAD.encode(bytes)),
        ("TimeOtp-Secret-Base64", data_encoding::BASE64.encode(bytes)),
    ] {
        let converted = timeotp_conversion(&[(name, &secret)]);
        let item = &converted.document().as_json()["accounts"][0]["items"][0];
        let credentials = item["credentials"].as_array().unwrap();
        let otp = credentials.iter().find(|c| c["type"] == "totp").unwrap();
        assert_eq!(kagitaba_cxf::otp::code(otp, 59).unwrap().0.as_str(), "287082");
        assert_eq!(otp["period"], 30);
        assert!(!credentials.iter().any(|c| c["type"] == "custom-fields"));
        assert_eq!(item["extensions"][0]["data"]["fields"][name], secret);
        assert!(!converted.report().warnings.iter().any(|w| w.kind == WarningKind::OpaqueOtp));
    }
}

#[test]
fn keepass_timeotp_algorithms_period_and_digits_match_reference_vectors() {
    for (algorithm, secret, expected) in [
        ("HMAC-SHA-1", "12345678901234567890", "94287082"),
        ("HMAC-SHA-256", "12345678901234567890123456789012", "46119246"),
        ("HMAC-SHA-512", "1234567890123456789012345678901234567890123456789012345678901234", "90693936"),
    ] {
        let converted = timeotp_conversion(&[("TimeOtp-Secret", secret), ("TimeOtp-Algorithm", algorithm), ("TimeOtp-Length", "8"), ("TimeOtp-Period", "60")]);
        let otp = converted.document().as_json()["accounts"][0]["items"][0]["credentials"].as_array().unwrap().iter().find(|c| c["type"] == "totp").unwrap();
        // Counter 1: RFC6238 timestamp59/period30 == timestamp119/period60.
        assert_eq!(kagitaba_cxf::otp::code(otp, 119).unwrap().0.as_str(), expected);
    }
}

#[test]
fn invalid_or_ambiguous_timeotp_is_preserved_and_warned_not_activated() {
    for extra in [
        ("TimeOtp-Secret", "second-secret"), ("TimeOtp-Length", "0"),
        ("TimeOtp-Length", "5"), ("TimeOtp-Length", "9"),
        ("TimeOtp-Period", "0"), ("TimeOtp-Period", "invalid"),
        ("TimeOtp-Algorithm", "HMAC-MD5"), ("TimeOtp-Offset", "15"),
    ] {
        let converted = timeotp_conversion(&[("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), extra]);
        let credentials = converted.document().as_json()["accounts"][0]["items"][0]["credentials"].as_array().unwrap();
        assert!(!credentials.iter().any(|c| c["type"] == "totp"));
        assert!(credentials.iter().any(|c| c["type"] == "custom-fields"));
        assert!(converted.report().warnings.iter().any(|w| w.kind == WarningKind::OpaqueOtp));
    }
    for fields in [vec![("TimeOtp-Secret-Base32", "not-a-seed!")], vec![("TimeOtp-Secret", "{REF:P@T:Other}")], vec![("TimeOtp-Period", "30")]] {
        let converted = timeotp_conversion(&fields);
        assert!(converted.report().warnings.iter().any(|w| w.kind == WarningKind::OpaqueOtp));
    }
}

#[test]
fn equivalent_legacy_and_timeotp_are_deduplicated_but_distinct_credentials_survive() {
    for (seed, expected) in [("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1), ("JBSWY3DPEHPK3PXP", 2)] {
        let converted = timeotp_conversion(&[("otp", seed), ("TimeOtp-Secret", "12345678901234567890")]);
        let credentials = converted.document().as_json()["accounts"][0]["items"][0]["credentials"].as_array().unwrap();
        assert_eq!(credentials.iter().filter(|c| c["type"] == "totp").count(), expected);
    }
}

#[test]
fn kp2a_additional_web_urls_map_to_scope_without_losing_unsupported_fields() {
    let converted = timeotp_conversion(&[
        ("URL", "https://primary.example.test"),
        ("KP2A_URL_1", "https://additional.example.test/login"),
        ("KP2A_URL_2", "https://primary.example.test"),
        ("KP2A_URL_3", "androidapp://example.app"),
        ("KP2A_URL_4", "https://user:password@example.test"),
        ("KP2A_URL_other", "https://not-a-number.example.test"),
    ]);
    let item = &converted.document().as_json()["accounts"][0]["items"][0];
    assert_eq!(item["scope"]["urls"], serde_json::json!(["https://primary.example.test", "https://additional.example.test/login", "androidapp://example.app"]));
    let custom = item["credentials"].as_array().unwrap().iter().find(|c| c["type"] == "custom-fields").unwrap();
    let labels: Vec<_> = custom["fields"].as_array().unwrap().iter().map(|f| f["label"].as_str().unwrap()).collect();
    assert_eq!(labels, vec!["KP2A_URL_4", "KP2A_URL_other"]);
    assert_eq!(item["extensions"][0]["data"]["fields"]["KP2A_URL_1"], "https://additional.example.test/login");
    assert_eq!(converted.report().warnings.iter().filter(|w| w.kind == WarningKind::UriPolicy).count(), 1);
}

#[test]
fn kpex_passkey_maps_only_complete_supported_credentials_and_keeps_source() {
    use p256::pkcs8::EncodePrivateKey;
    let key = p256::SecretKey::from_slice(&[7;32]).unwrap();
    let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
    for extra in [None, Some("KPEX_PASSKEY_PRF"), Some("KPEX_PASSKEY_COUNTER"), Some("KPEX_PASSKEY_UNKNOWN")] {
        let mut db = Database::with_config(DatabaseConfig::default());
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", "Synthetic passkey");
            for (name, value) in [
                ("KPEX_PASSKEY_CREDENTIAL_ID", "AQIDBA"), ("KPEX_PASSKEY_USER_HANDLE", "BQYHCA"),
                ("KPEX_PASSKEY_USERNAME", "synthetic-user"), ("KPEX_PASSKEY_RELYING_PARTY", "example.test"),
                ("KPEX_PASSKEY_FLAG_BE", "1"), ("KPEX_PASSKEY_FLAG_BS", "0"),
                ("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem.as_str()),
            ] { entry.set_protected(name, value); }
            if let Some(name) = extra { entry.set_protected(name, "synthetic-unsupported"); }
        }
        let converted = keepass::from_database(&db).unwrap();
        let item = &converted.document().as_json()["accounts"][0]["items"][0];
        let credentials = item["credentials"].as_array().unwrap();
        assert_eq!(credentials.iter().any(|v| v["type"] == "passkey"), extra.is_none());
        assert_eq!(credentials.iter().any(|v| v["type"] == "custom-fields"), extra.is_some());
        assert_eq!(converted.report().warnings.iter().any(|w| w.kind == WarningKind::OpaquePasskey), extra.is_some());
        assert!(item["extensions"][0]["data"]["fields"].get("KPEX_PASSKEY_PRIVATE_KEY_PEM").is_some());
    }
}

#[test]
fn ordinary_url_data_needs_no_policy_warning_but_real_limitations_are_actionable() {
    let converted = timeotp_conversion(&[("URL","plain.example.test"),("KP2A_URL_1","androidapp://org.example.app"),("KP2A_URL_2","file:///synthetic/local"),("KP2A_URL_3","{REF:A@I:synthetic-private-reference}")]);
    let item=&converted.document().as_json()["accounts"][0]["items"][0];
    assert_eq!(item["scope"]["urls"],serde_json::json!(["plain.example.test","androidapp://org.example.app","file:///synthetic/local"]));
    let warning=converted.report().warnings.iter().find(|w|w.kind==WarningKind::UriPolicy).unwrap();
    assert_eq!(warning.item_index,Some(0));
    let detail=warning.detail.unwrap();
    assert_eq!(detail.field,Some("KP2A_URL_*"));
    assert!(detail.reason.contains("reference") && detail.action.contains("literal"));
    assert!(!format!("{warning:?}").contains("synthetic-private-reference"));
}

#[test]
fn repeated_parse_of_identical_database_has_stable_import_payloads() {
    let db = database();
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password("synthetic")).unwrap();
    let first = keepass::from_bytes(&bytes, Some("synthetic"), None).unwrap();
    for _ in 0..12 {
        let next = keepass::from_bytes(&bytes, Some("synthetic"), None).unwrap();
        // Do not print document contents on failure.
        assert!(first.document().as_json() == next.document().as_json(), "Repeated import changed its payload");
    }
}

#[test]
fn legacy_kpex_without_backup_flags_imports_as_active_passkey() {
    use p256::pkcs8::EncodePrivateKey;
    let key=p256::SecretKey::from_slice(&[7;32]).unwrap();
    let pem=key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
    let mut db=Database::with_config(DatabaseConfig::default());
    {
        let mut root=db.root_mut(); let mut entry=root.add_entry();
        entry.set_unprotected("Title","Synthetic legacy passkey");
        for (name,value) in [
            ("KPEX_PASSKEY_CREDENTIAL_ID","AQIDBA"), ("KPEX_PASSKEY_USER_HANDLE","BQYHCA"),
            ("KPEX_PASSKEY_USERNAME","synthetic-user"), ("KPEX_PASSKEY_RELYING_PARTY","example.test"),
            ("KPEX_PASSKEY_PRIVATE_KEY_PEM",pem.as_str()),
        ] { entry.set_protected(name,value); }
    }
    let converted=keepass::from_database(&db).unwrap();
    let item=&converted.document().as_json()["accounts"][0]["items"][0];
    let credentials=item["credentials"].as_array().unwrap();
    let passkey=credentials.iter().find(|v|v["type"]=="passkey").unwrap();
    assert_eq!(passkey["kagitabaBackupFlags"],serde_json::json!({"eligible":false,"state":false}));
    assert!(!converted.report().warnings.iter().any(|w|w.kind==WarningKind::OpaquePasskey));
    assert!(item["extensions"][0]["data"]["fields"].get("KPEX_PASSKEY_PRIVATE_KEY_PEM").is_some());
    assert!(item["extensions"][0]["data"]["fields"].get("KPEX_PASSKEY_FLAG_BE").is_none());
}

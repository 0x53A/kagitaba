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
        trash
            .add_entry()
            .set_protected("Password", "deleted-secret");
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

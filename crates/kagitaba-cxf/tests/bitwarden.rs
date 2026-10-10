use futures::executor::block_on;
use kagitaba_core::{crypto::SoftwareIdentity, wallet::Wallet};
use kagitaba_cxf::{Error, Payload, WarningKind, bitwarden};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

fn export() -> Value {
    json!({"encrypted":false,"folders":[{"id":"folder-1","name":"Personal/Email"}],
      "items":[{"id":"item-1","type":1,"name":"Example","folderId":"folder-1","favorite":true,
        "creationDate":"2025-01-01T00:00:00Z","revisionDate":"2025-01-02T00:00:00Z",
        "login":{"username":"alice","password":"test-secret","totp":"JBSWY3DPEHPK3PXP",
          "uris":[{"uri":"https://example.test","match":null}],"fido2Credentials":[]},
        "notes":"line one\nline two","fields":[{"name":"Hidden","type":1,"value":"custom-secret"},
          {"name":"Flag","type":2,"value":"true"}],"futureField":{"retain":true}}]})
}
fn convert(value: &Value) -> kagitaba_cxf::Conversion {
    bitwarden::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn item(c: &kagitaba_cxf::Conversion) -> &Value {
    &c.document().as_json()["accounts"][0]["items"][0]
}
fn credential<'a>(item: &'a Value, kind: &str) -> &'a Value {
    item["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["type"] == kind)
        .unwrap()
}

#[test]
fn passwords_folders_fields_notes_and_metadata_reach_encrypted_wallet() {
    let source = export();
    let converted = convert(&source);
    assert!(converted.report().warnings.is_empty());
    let value = item(&converted);
    assert_eq!(
        credential(value, "basic-auth")["password"]["value"],
        "test-secret"
    );
    assert_eq!(credential(value, "totp")["secret"], "JBSWY3DPEHPK3PXP");
    assert_eq!(
        credential(value, "custom-fields")["fields"][0]["fieldType"],
        "concealed-string"
    );
    assert_eq!(
        credential(value, "note")["content"]["value"],
        "line one\nline two"
    );
    assert_eq!(value["creationAt"], 1735689600u64);
    assert_eq!(value["extensions"][0]["data"], source["items"][0]);
    let mut rng = ChaCha20Rng::from_seed([33; 32]);
    let identity = SoftwareIdentity::generate(&mut rng).unwrap();
    let public = identity.public_key();
    let wallet = Wallet::from_parts([public.clone()], []).unwrap();
    let plan = converted.document().plan_import(&wallet, &mut rng).unwrap();
    let imported = plan
        .encrypt_into(&wallet, &[public.id()], &mut rng)
        .unwrap();
    assert_eq!(imported.entries().len(), 2);
    for planned in plan.entries() {
        let opened = block_on(Payload::open(
            &imported.entries()[&planned.entry_id()],
            &public,
            &identity,
        ))
        .unwrap();
        assert_eq!(opened.entity(), planned.entity());
    }
    let account = &converted.document().as_json()["accounts"][0];
    assert_eq!(account["collections"][0]["items"][0]["item"], value["id"]);
    assert!(wallet.entries().is_empty());
}

#[test]
fn passkeys_preserve_binary_ids_and_private_keys_and_nonzero_counters_stay_opaque() {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[1; 32]);
    let key = data_encoding::BASE64URL_NOPAD.encode(&der);
    let passkey = json!({"credentialId":"b64.AAECA_8","keyType":"public-key","keyAlgorithm":"EdDSA",
      "keyCurve":"Ed25519","keyValue":key,"rpId":"example.test","userHandle":"dXNlcg",
      "userName":"alice","userDisplayName":"Alice","counter":"0","discoverable":"true"});
    let mut source = export();
    source["items"][0]["login"]["fido2Credentials"] = json!([passkey]);
    let converted = convert(&source);
    let mapped = credential(item(&converted), "passkey");
    assert_eq!(mapped["credentialId"], "AAECA_8");
    assert_eq!(mapped["key"], key);
    source["items"][0]["login"]["fido2Credentials"][0]["credentialId"] =
        "e8d88789-e916-e196-3cbd-81dafae71bbc".into();
    assert_eq!(
        credential(item(&convert(&source)), "passkey")["credentialId"],
        "6NiHiekW4ZY8vYHa-ucbvA"
    );
    for counter in [json!(1), json!("42"), Value::Null] {
        source["items"][0]["login"]["fido2Credentials"][0]["counter"] = counter;
        let converted = convert(&source);
        assert!(
            converted
                .report()
                .warnings
                .iter()
                .any(|w| w.kind == WarningKind::OpaquePasskey)
        );
        assert!(
            !item(&converted)["credentials"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["type"] == "passkey")
        );
        assert_eq!(
            item(&converted)["extensions"][0]["data"],
            source["items"][0]
        );
    }
}

#[test]
fn otp_uri_parameters_are_preserved_and_unsupported_variants_are_reported() {
    let mut source = export();
    source["items"][0]["login"]["totp"]="otpauth://totp/Example:alice%40example.test?secret=jbswy3dpehpk3pxp&issuer=Example&algorithm=SHA256&digits=8&period=60".into();
    let converted = convert(&source);
    let otp = credential(item(&converted), "totp");
    assert_eq!(otp["period"], 60);
    assert_eq!(otp["digits"], 8);
    assert_eq!(otp["algorithm"], "sha256");
    assert_eq!(otp["username"], "alice@example.test");
    assert_eq!(otp["issuer"], "Example");
    for unsupported in [
        "steam://ABCDE",
        "otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP&counter=2",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&secret=AAAA",
        "otpauth://totp/test?secret=AAAA&algorithm=MD5",
        "otpauth://totp/test?secret=AAAA&period=0",
        "!invalid!",
    ] {
        source["items"][0]["login"]["totp"] = unsupported.into();
        let converted = convert(&source);
        assert!(
            converted
                .report()
                .warnings
                .iter()
                .any(|w| w.kind == WarningKind::OpaqueOtp)
        );
    }
}

#[test]
fn uri_policies_unsupported_types_linked_fields_history_and_trash_are_explicit() {
    let mut source = export();
    let s = &mut source["items"][0];
    s["login"]["uris"] = json!([{"uri":"https://example.test","match":5},
      {"uri":"androidapp://com.example.app","match":null}]);
    s["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":3,"name":"Linked","linkedId":101,"value":null}));
    s["folderId"] = "missing".into();
    s["reprompt"] = 1.into();
    s["passwordHistory"] = json!([{"password":"old-secret","lastUsedDate":"2025-01-01"}]);
    source["items"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"other","name":"Card","type":3,"card":{"number":"4111111111111111"}}));
    source["items"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"trash","name":"Deleted","type":2,"deletedDate":"2025-01-01"}));
    let converted = convert(&source);
    assert_eq!(converted.report().items, 2);
    for kind in [
        WarningKind::UriPolicy,
        WarningKind::OpaqueField,
        WarningKind::MissingCollection,
        WarningKind::Reprompt,
        WarningKind::History,
        WarningKind::OpaqueItem,
        WarningKind::Deleted,
    ] {
        assert!(converted.report().warnings.iter().any(|w| w.kind == kind));
    }
    assert_eq!(item(&converted)["scope"]["urls"], json!([]));
    assert_eq!(
        item(&converted)["scope"]["androidApps"][0]["bundleId"],
        "com.example.app"
    );
}

#[test]
fn invalid_or_encrypted_exports_fail_without_secret_diagnostics() {
    for raw in [
        br#"{}"#.as_slice(),
        br#"{"encrypted":false,"items":[],"items":[]}"#,
        br#"{"encrypted":false,"items":"secret-value"}"#,
    ] {
        assert!(bitwarden::from_json(raw).is_err());
    }
    assert!(matches!(
        bitwarden::from_json(br#"{"encrypted":true,"data":"secret-value"}"#),
        Err(Error::EncryptedExport)
    ));
    let mut source = export();
    let duplicate = source["items"][0].clone();
    source["items"].as_array_mut().unwrap().push(duplicate);
    assert!(matches!(
        bitwarden::from_json(&serde_json::to_vec(&source).unwrap()),
        Err(Error::DuplicateId)
    ));
    let mut nested = json!("deep-value");
    for _ in 0..59 {
        nested = json!([nested]);
    }
    let mut source = export();
    source["items"][0]["unknown"] = nested;
    assert!(bitwarden::from_json(&serde_json::to_vec(&source).unwrap()).is_err());
    let mut bytes = b"\xef\xbb\xbf".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&export()).unwrap());
    assert_eq!(
        bitwarden::from_reader(std::io::Cursor::new(bytes))
            .unwrap()
            .report()
            .items,
        1
    );
}

#[test]
fn organisation_collections_and_folder_namespaces_do_not_collide() {
    let mut source = export();
    source["collections"] = json!([{"id":"folder-1","name":"Shared"}]);
    source["items"][0]["collectionIds"] = json!(["folder-1"]);
    let converted = convert(&source);
    let roots = converted.document().as_json()["accounts"][0]["collections"]
        .as_array()
        .unwrap();
    assert_eq!(roots.len(), 2);
    assert_ne!(roots[0]["id"], roots[1]["id"]);
    assert_eq!(roots[0]["items"], roots[1]["items"]);
}

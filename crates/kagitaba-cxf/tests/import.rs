use futures::executor::block_on;
use kagitaba_core::{EntryId, crypto::SoftwareIdentity, wallet::Wallet};
use kagitaba_cxf::{Document, Error, Payload, PayloadKind};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

fn fixture() -> Value {
    // Deliberately reuse item IDs across accounts. All data are synthetic.
    json!({
        "version": {"major": 1, "minor": 0},
        "exporterRpId": "example.test", "exporterDisplayName": "Example", "timestamp": 42,
        "futureHeader": {"retain": true},
        "accounts": [{
            "id": "YQ", "username": "Alice", "email": "alice@example.test", "vendorAccount": "retained",
            "items": [{
                "id": "aQ", "title": "Login", "futureItem": {"retain": 7},
                "credentials": [
                    {"type": "basic-auth", "username": {"fieldType": "string", "value": "alice"},
                     "password": {"fieldType": "concealed-string", "value": "test-password", "futureField": "retain"}},
                    {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30, "digits": 6, "algorithm": "sha1"},
                    {"type": "future-credential", "opaque": {"private": "retain"}},
                    {"type": "item-reference", "reference": {"item": "aQ", "account": "Yg"}}
                ]
            }],
            "collections": [{
                "id": "cg", "title": "Root", "items": [{"item": "aQ", "extra": "retain"}],
                "subCollections": [{"id": "bg", "title": "Nested", "items": [
                    {"item": "aQ", "account": "Yg"}, {"item": "bWlzc2luZw"}
                ]}]
            }, {"id": "cw", "title": "Other root", "items": []}]
        }, {
            "id": "Yg", "username": "Bob", "email": "bob@example.test",
            "collections": [], "items": [{"id": "aQ", "title": "Other login", "credentials": []}]
        }]
    })
}

fn parse(value: &Value) -> Document {
    Document::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([37; 32])
}

#[test]
fn document_round_trip_preserves_unknown_fields_and_usable_typed_model() {
    let input = fixture();
    let document = parse(&input);
    let roundtrip: Value = serde_json::from_slice(&document.to_json().unwrap()).unwrap();
    assert_eq!(roundtrip, input);
    let typed = document.typed().unwrap();
    assert_eq!(typed.accounts.len(), 2);
    assert_eq!(typed.accounts[0].collections.len(), 2);
    assert_eq!(typed.accounts[0].items[0].credentials.len(), 4);
}

#[test]
fn references_are_remapped_across_accounts_and_nested_roots_stay_atomic() {
    let document = parse(&fixture());
    let plan = document
        .plan_import(&Wallet::default(), &mut rng())
        .unwrap();
    assert_eq!(plan.entries().len(), 4); // Two items, two roots; no separate child.
    let report = plan.report();
    assert_eq!(
        (
            report.items,
            report.root_collections,
            report.unresolved_links,
            report.opaque_credentials
        ),
        (2, 2, 1, 1)
    );
    let alice = plan
        .entries()
        .iter()
        .find(|p| p.entity()["title"] == "Login")
        .unwrap();
    let bob = plan
        .entries()
        .iter()
        .find(|p| p.entity()["title"] == "Other login")
        .unwrap();
    let root = plan
        .entries()
        .iter()
        .find(|p| p.entity()["title"] == "Root")
        .unwrap();
    assert_ne!(alice.entry_id(), bob.entry_id());
    assert_eq!(root.entity()["items"][0]["item"], alice.entity()["id"]);
    assert_eq!(root.entity()["items"][0]["extra"], "retain");
    let child = &root.entity()["subCollections"][0];
    assert_eq!(child["items"][0]["item"], bob.entity()["id"]);
    assert!(child["items"][0].get("account").is_none());
    assert_eq!(
        child["items"][1],
        json!({"item": "bWlzc2luZw", "account": "YQ"})
    );
    assert_eq!(
        alice.entity()["credentials"][3]["reference"]["item"],
        bob.entity()["id"]
    );
    let source = alice.source().unwrap();
    assert_eq!(source["account"]["vendorAccount"], "retained");
    assert!(source["account"].get("items").is_none());
    assert!(source["header"].get("accounts").is_none());
    assert_eq!(source["originalId"], "aQ");
}

#[test]
fn import_encrypts_for_exact_recipients_and_preserves_existing_snapshot() {
    let mut rng = rng();
    let identities: Vec<_> = (0..3)
        .map(|_| SoftwareIdentity::generate(&mut rng).unwrap())
        .collect();
    let keys: Vec<_> = identities
        .iter()
        .map(SoftwareIdentity::public_key)
        .collect();
    let wallet = Wallet::from_parts(keys.clone(), []).unwrap();
    let plan = parse(&fixture()).plan_import(&wallet, &mut rng).unwrap();
    let imported = plan
        .encrypt_into(&wallet, &[keys[0].id(), keys[1].id()], &mut rng)
        .unwrap();
    assert!(wallet.entries().is_empty());
    assert_eq!(imported.entries().len(), 4);
    for planned in plan.entries() {
        let entry = &imported.entries()[&planned.entry_id()];
        assert_eq!(entry.grants().len(), 2);
        assert!(!entry.grants().contains_key(&keys[2].id()));
        for i in 0..2 {
            let opened = block_on(Payload::open(entry, &keys[i], &identities[i])).unwrap();
            assert_eq!(opened.entity(), planned.entity());
        }
        assert!(block_on(Payload::open(entry, &keys[2], &identities[2])).is_err());
    }
    assert!(matches!(
        plan.encrypt_into(&imported, &[keys[0].id()], &mut rng),
        Err(Error::DuplicateId)
    ));
    assert!(matches!(
        plan.encrypt_into(&wallet, &[], &mut rng),
        Err(Error::InvalidRecipients)
    ));
    assert!(matches!(
        plan.encrypt_into(&wallet, &[keys[0].id(), keys[0].id()], &mut rng),
        Err(Error::InvalidRecipients)
    ));
}

#[test]
fn payload_edits_preserve_unknown_data_and_rotate_revision_and_grants() {
    let mut rng = rng();
    let identity = SoftwareIdentity::generate(&mut rng).unwrap();
    let key = identity.public_key();
    let plan = parse(&fixture())
        .plan_import(&Wallet::default(), &mut rng)
        .unwrap();
    let original = &plan.entries()[0];
    let first = original.seal(std::slice::from_ref(&key), &mut rng).unwrap();
    let mut edited = block_on(Payload::open(&first, &key, &identity)).unwrap();
    edited.set_title("Renamed".into(), 100);
    assert_eq!(
        edited.entity()["futureItem"],
        original.entity()["futureItem"]
    );
    assert_eq!(
        edited.entity()["credentials"],
        original.entity()["credentials"]
    );
    let second = edited.seal(std::slice::from_ref(&key), &mut rng).unwrap();
    assert_ne!(
        first.primary().revision_id(),
        second.primary().revision_id()
    );
    assert_ne!(first.primary().body(), second.primary().body());
    assert!(
        first.grants()[&key.id()]
            .validate_for(second.primary())
            .is_err()
    );
    assert!(matches!(
        Payload::from_json(EntryId::from_bytes([0; 16]), &edited.to_json().unwrap()),
        Err(Error::WrongEntry)
    ));
}

#[test]
fn malformed_and_ambiguous_documents_are_rejected_without_secret_errors() {
    for input in [
        b"{}".as_slice(),
        b"{\"secret\":1,\"secret\":2}",
        b"{} trailing",
        b"[[]]",
    ] {
        assert!(Document::from_json(input).is_err());
    }
    let mut value = fixture();
    value["version"]["major"] = 2.into();
    assert!(matches!(
        Document::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(Error::UnsupportedVersion)
    ));
    value = fixture();
    value["accounts"][0]["collections"][0]["id"] = "aQ".into();
    assert!(matches!(
        Document::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(Error::DuplicateId)
    ));
    value = fixture();
    value["accounts"][1]["id"] = "YQ==".into(); // Same bytes, alternative padding.
    assert!(matches!(
        Document::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(Error::DuplicateId)
    ));
    for bad in ["not base64!", "aR", "", &"YQ".repeat(65)] {
        value = fixture();
        value["accounts"][0]["items"][0]["id"] = bad.into();
        assert!(Document::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    value = fixture();
    value["accounts"][0]["items"][0]["credentials"][1]["secret"] = "secret-DO-NOT-PRINT".into();
    let error = Document::from_json(&serde_json::to_vec(&value).unwrap())
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("DO-NOT-PRINT"));
    value["accounts"][0]["items"][0]["credentials"][1] = json!({"type": "passkey", "key": "YQ"});
    assert!(Document::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn empty_accounts_and_future_versions_and_credentials_are_explicit() {
    let mut value = fixture();
    value["version"]["minor"] = 5.into();
    value["accounts"][0]["items"][0]["credentials"][1]["algorithm"] = "future-hash".into();
    value["accounts"].as_array_mut().unwrap().push(json!({
        "id": "ZQ", "username": "", "email": "", "items": [], "collections": []
    }));
    let plan = parse(&value)
        .plan_import(&Wallet::default(), &mut rng())
        .unwrap();
    assert_eq!(plan.report().opaque_credentials, 2);
    assert_eq!(plan.report().empty_accounts, 1);
    let empty = json!({"version":{"major":1,"minor":0},"exporterRpId":"example.test",
        "exporterDisplayName":"test","timestamp":0,"accounts":[]});
    assert!(
        parse(&empty)
            .plan_import(&Wallet::default(), &mut rng())
            .unwrap()
            .entries()
            .is_empty()
    );
}

#[test]
fn cxp_response_is_not_misidentified_as_plaintext_cxf() {
    let response = br#"{"version":0,"hpke":{},"payload":"YQ"}"#;
    assert!(matches!(
        Document::from_json(response),
        Err(Error::CxpSessionRequired)
    ));
}

#[test]
fn native_collection_roundtrip() {
    let id = EntryId::from_bytes([17; 16]);
    let entity = json!({"id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Root","items":[]});
    let payload = Payload::new(
        id,
        PayloadKind::Collection,
        &serde_json::to_vec(&entity).unwrap(),
    )
    .unwrap();
    let read = Payload::from_json(id, &payload.to_json().unwrap()).unwrap();
    assert_eq!(read.kind(), PayloadKind::Collection);
    assert_eq!(read.entity(), &entity);
}

#[test]
fn passkey_pkcs8_and_notes_survive_import_and_encryption() {
    // Synthetic RFC 8410 Ed25519 PKCS#8 structure with a 32-byte test seed.
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[1; 32]);
    let key = data_encoding::BASE64URL_NOPAD.encode(&der);
    let mut input = fixture();
    let passkey = json!({"type":"passkey", "credentialId":"Y3JlZA", "rpId":"example.test",
        "username":"alice", "userDisplayName":"Alice", "userHandle":"dXNlcg", "key":key,
        "fido2Extensions":{"credBlob":"YmxvYg","futureExtension":{"keep":true}}});
    input["accounts"][0]["items"][0]["credentials"]
        .as_array_mut()
        .unwrap()
        .extend([
            passkey.clone(),
            json!({"type":"note","content":{"fieldType":"string","value":"test note"}}),
        ]);
    let document =
        Document::from_reader(std::io::Cursor::new(serde_json::to_vec(&input).unwrap())).unwrap();
    let mut rng = rng();
    let plan = document.plan_import(&Wallet::default(), &mut rng).unwrap();
    let identity = SoftwareIdentity::generate(&mut rng).unwrap();
    let entry = plan.entries()[0]
        .seal(&[identity.public_key()], &mut rng)
        .unwrap();
    let opened = block_on(Payload::open(&entry, &identity.public_key(), &identity)).unwrap();
    assert_eq!(opened.entity()["credentials"][4], passkey);
    input["accounts"][0]["items"][0]["credentials"][4]["key"] = "YQ".into();
    assert!(Document::from_json(&serde_json::to_vec(&input).unwrap()).is_err());
}

#[test]
fn unknown_numeric_values_are_not_rounded_or_confused_with_internal_number_tags() {
    let mut input = fixture();
    input["futureHeader"] = serde_json::from_str(r#"{"large":123456789012345678901234567890,"precise":1.12345678901234567890,"$serde_json::private::Number":"not a number"}"#).unwrap();
    let document = parse(&input);
    assert_eq!(
        Document::from_json(&document.to_json().unwrap())
            .unwrap()
            .as_json(),
        &input
    );
    let bytes = serde_json::to_string(&input).unwrap().replace(
        "\"futureHeader\":{",
        "\"futureHeader\":{\"duplicate\":1,\"duplicate\":2,",
    );
    assert!(Document::from_json(bytes.as_bytes()).is_err());
}

#[test]
fn input_streams_and_payloads_are_bounded() {
    let input = std::io::repeat(b' ');
    assert!(matches!(
        Document::from_reader(input),
        Err(Error::SizeLimit)
    ));
    let nested = format!("{}0{}", "[".repeat(150), "]".repeat(150));
    assert!(Document::from_json(nested.as_bytes()).is_err());
    let mut input = fixture();
    input["accounts"][0]["items"][0]["huge"] = "x".repeat(1024 * 1024).into();
    let document = parse(&input);
    assert!(matches!(
        document.plan_import(&Wallet::default(), &mut rng()),
        Err(Error::SizeLimit)
    ));
}

#[test]
fn construction_checks_nesting_of_the_complete_envelope() {
    let id = EntryId::from_bytes([0; 16]);
    for depth in [62, 63] {
        let mut extension = Value::Null;
        for _ in 0..depth {
            extension = json!([extension]);
        }
        let entity = json!({"id":"AAAAAAAAAAAAAAAAAAAAAA","title":"Nested", "credentials":[], "vendorExtension":extension});
        let payload = Payload::new(id, PayloadKind::Item, &serde_json::to_vec(&entity).unwrap());
        if depth == 63 {
            assert!(payload.is_err());
            continue;
        }
        let payload = payload.unwrap();
        Payload::from_json(id, &payload.to_json().unwrap()).unwrap();
        let mut rng = rng();
        let identity = SoftwareIdentity::generate(&mut rng).unwrap();
        let entry = payload.seal(&[identity.public_key()], &mut rng).unwrap();
        block_on(Payload::open(&entry, &identity.public_key(), &identity)).unwrap();
    }
}

#[test]
fn plain_cxf_cannot_activate_owned_attachments_without_their_blobs() {
    use data_encoding::BASE64URL_NOPAD;
    let external=json!({"type":"file","id":BASE64URL_NOPAD.encode(&[9;16]),"name":"example.pdf","decryptedSize":3,"integrityHash":BASE64URL_NOPAD.encode(&[0;32])});
    let mut input=fixture();
    input["accounts"][0]["items"][0]["credentials"].as_array_mut().unwrap().push(external.clone());
    let source=parse(&input);
    let plan=source.plan_import(&Wallet::default(),&mut rng()).unwrap();
    assert_eq!(plan.report().external_files,1);
    assert!(plan.entries().iter().any(|p|p.entity()["credentials"].as_array().is_some_and(|c|c.contains(&external))));
    for marker in [Value::Null,json!({"version":1,"blobId":"01010101010101010101010101010101","key":BASE64URL_NOPAD.encode(&[3;32]),"chunkCount":1})] {
        let mut owned=input.clone();
        owned["accounts"][0]["items"][0]["credentials"].as_array_mut().unwrap().last_mut().unwrap()["kagitabaFile"]=marker;
        let source=parse(&owned);
        assert!(matches!(source.plan_import(&Wallet::default(),&mut rng()),Err(Error::OwnedAttachmentsUnsupported)));
        let preserved:Value=serde_json::from_slice(&source.to_json().unwrap()).unwrap();
        assert_eq!(preserved,owned);
    }
}

#[test]
fn opaque_type_breakdown_counts_types_without_credential_values() {
    let mut input = fixture();
    let credentials = input["accounts"][0]["items"][0]["credentials"].as_array_mut().unwrap();
    credentials.push(json!({"type":"future-credential", "secret":"never in report"}));
    credentials.push(json!({"type":"another-credential", "secret":"never in report"}));
    credentials.push(json!({"type":"totp", "secret":"JBSWY3DPEHPK3PXP", "period":30,"digits":6,"algorithm":"future"}));
    let plan = parse(&input).plan_import(&Wallet::default(), &mut rng()).unwrap();
    let report = plan.report();
    assert_eq!(report.opaque_credentials, 4);
    assert_eq!(report.opaque_credential_types, std::collections::BTreeMap::from([
        ("future-credential".into(), 2), ("another-credential".into(), 1), ("totp".into(), 1)
    ]));
    assert!(!format!("{report:?}").contains("never in report"));
    assert_eq!(plan.report(), report);
}

#[test]
fn supported_custom_fields_are_not_reported_as_unknown() {
    let mut input = fixture();
    let credentials = input["accounts"][0]["items"][0]["credentials"].as_array_mut().unwrap();
    credentials.push(json!({"type":"custom-fields", "fields":[
        {"label":"Pin","fieldType":"string","value":"synthetic"},
        {"label":"Secret","fieldType":"concealed-string","value":"synthetic"},
        {"label":"Enabled","fieldType":"boolean","value":"true"}
    ]}));
    let plan = parse(&input).plan_import(&Wallet::default(), &mut rng()).unwrap();
    assert!(!plan.report().opaque_credential_types.contains_key("custom-fields"));
    assert!(plan.entries().iter().any(|payload| payload.entity()["credentials"].as_array().is_some_and(|credentials| credentials.iter().any(|c| c["type"] == "custom-fields"))));
}

#[test]
fn preserved_custom_field_groups_report_distinct_types_not_values() {
    let mut input = fixture();
    let credentials = input["accounts"][0]["items"][0]["credentials"].as_array_mut().unwrap();
    credentials.push(json!({"type":"custom-fields", "fields":[
        {"label":"Never in report A","fieldType":"email","value":"private@example.test"},
        {"label":"Never in report B","fieldType":"email","value":"other@example.test"},
        {"label":"Never in report C","fieldType":"number","value":"42"},
        {"label":"Never in report D","fieldType":"string","value":"retained alongside unknown types"}
    ]}));
    credentials.push(json!({"type":"custom-fields", "fields":[
        {"label":"Never in report E","fieldType":"number","value":"123"}
    ]}));
    let plan = parse(&input).plan_import(&Wallet::default(), &mut rng()).unwrap();
    let report = plan.report();
    assert_eq!(report.opaque_credential_types["custom-fields"], 2);
    assert_eq!(report.preserved_custom_field_types, std::collections::BTreeMap::from([
        ("email".into(), 2), ("number".into(), 2), ("string".into(), 1)
    ]));
    let summary = format!("{report:?}");
    assert!(!summary.contains("Never in report") && !summary.contains("example.test") && !summary.contains("retained alongside"));
}

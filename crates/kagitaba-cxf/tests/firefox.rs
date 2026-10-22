use futures::executor::block_on;
use kagitaba_core::{crypto::SoftwareIdentity, wallet::Wallet};
use kagitaba_cxf::{Error, Payload, WarningKind, firefox};
use rand_core::SeedableRng;

#[test]
fn quoted_bom_reordered_columns_roundtrip_through_encrypted_import() {
    let csv = "\u{feff}password,guid,url,username,formActionOrigin,httpRealm,timeCreated,timeLastUsed,timePasswordChanged,future\r\n\" a,\"\"b\"\"\r\nc \",same,https://example.test,\"user,one\",https://example.test,,1234567,2345678,3456789,\"preserve\"";
    let converted = firefox::from_reader(csv.as_bytes()).unwrap();
    assert!(converted.report().warnings.is_empty());
    let item = &converted.document().as_json()["accounts"][0]["items"][0];
    assert_eq!(item["creationAt"], 1234);
    assert_eq!(item["modifiedAt"], 3456);
    assert_eq!(item["scope"]["urls"][0], "https://example.test");
    assert_eq!(item["extensions"][0]["data"]["timeLastUsed"], "2345678");
    assert_eq!(item["extensions"][0]["data"]["future"], "preserve");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([23; 32]);
    let identity = SoftwareIdentity::generate(&mut rng).unwrap();
    let key = identity.public_key();
    let wallet = Wallet::from_parts([key.clone()], []).unwrap();
    let plan = converted.document().plan_import(&wallet, &mut rng).unwrap();
    let sealed = plan.encrypt_into(&wallet, &[key.id()], &mut rng).unwrap();
    let reopened = block_on(Payload::open(
        sealed.entries().values().next().unwrap(),
        &key,
        &identity,
    ))
    .unwrap();
    assert_eq!(
        reopened.entity()["credentials"][0]["password"]["value"],
        " a,\"b\"\r\nc "
    );
    assert_eq!(
        reopened.entity()["credentials"][0]["username"]["value"],
        "user,one"
    );
    assert_eq!(
        reopened.entity()["extensions"][0]["data"]["future"],
        "preserve"
    );
}

#[test]
fn repeated_guids_and_rows_keep_distinct_ids_and_empty_passwords() {
    let csv = b"url,username,password,guid\nhttps://example.test,,,repeated\nhttps://example.test,,,repeated\n";
    let converted = firefox::from_bytes(csv).unwrap();
    let items = converted.document().as_json()["accounts"][0]["items"]
        .as_array()
        .unwrap();
    assert_eq!(items.len(), 2);
    assert_ne!(items[0]["id"], items[1]["id"]);
    assert_eq!(items[0]["credentials"][0]["password"]["value"], "");
    assert!(
        firefox::from_bytes(b"url,username,password\r\n")
            .unwrap()
            .report()
            .items
            == 0
    );
}

#[test]
fn realm_foreign_action_and_invalid_timestamps_stay_source_only() {
    for (url, realm, action) in [
        ("https://example.test", "Realm", ""),
        ("https://example.test", "", "https://other.test"),
        ("file:///tmp/private", "", ""),
        ("https://example.test/path", "", ""),
        ("https://example.test", "", "https://example.test/path"),
    ] {
        let csv = format!(
            "url,username,password,httpRealm,formActionOrigin,timeCreated\n{url},u,p,{realm},{action},invalid"
        );
        let converted = firefox::from_bytes(csv.as_bytes()).unwrap();
        assert!(
            converted
                .report()
                .warnings
                .iter()
                .any(|w| w.kind == WarningKind::UriPolicy)
        );
        assert!(
            converted
                .report()
                .warnings
                .iter()
                .any(|w| w.kind == WarningKind::Timestamp)
        );
        let item = &converted.document().as_json()["accounts"][0]["items"][0];
        assert!(item.get("scope").is_none());
        assert_eq!(item["extensions"][0]["data"]["url"], url);
        assert_eq!(item["extensions"][0]["data"]["httpRealm"], realm);
    }
}

#[test]
fn malformed_csv_and_oversized_input_fail_without_input_in_errors() {
    for csv in [
        "url,username,password,password\na,b,c,d",
        "url,username\na,b",
        "url,username,password\na,b",
        "url,username,password\na,b,c,d",
        "url,username,password\na,b,\"SECRET",
        "url,username,password\na,b,SECRET\"bad",
        "url,username,password\na,b,\"SECRET\"bad",
    ] {
        let error = firefox::from_bytes(csv.as_bytes()).err().unwrap();
        assert!(!error.to_string().contains("SECRET"));
    }
    assert!(firefox::from_bytes(b"url,username,password\na,b,\xff").is_err());
    assert!(matches!(
        firefox::from_bytes(&vec![b'a'; kagitaba_cxf::MAX_DOCUMENT_BYTES + 1]),
        Err(Error::SizeLimit)
    ));
    struct Endless;
    impl std::io::Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(b'a');
            Ok(buffer.len())
        }
    }
    assert!(matches!(
        firefox::from_reader(Endless),
        Err(Error::SizeLimit)
    ));
}

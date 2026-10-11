use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::executor::block_on;
use kagitaba_browser::execute;
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn b64(value: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn bytes(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}
fn call(request: Value, seed: u8) -> Result<Value, kagitaba_browser::Error> {
    let mut random = vec![0; 8192];
    ChaCha20Rng::from_seed([seed; 32]).fill_bytes(&mut random);
    block_on(execute(&request.to_string(), random)).map(|s| serde_json::from_str(&s).unwrap())
}
fn identity(seed: u8) -> Value {
    call(json!({"op":"identity_generate"}), seed).unwrap()
}

#[test]
fn identity_requires_fresh_randomness_and_authenticated_matching_prf_context() {
    assert!(block_on(execute(r#"{"op":"identity_generate"}"#, vec![])).is_err());
    let identity = identity(1);
    assert_ne!(identity["participantId"], identity["signingId"]);
    let mut request = json!({"op":"identity_wrap", "identity":identity["identity"], "prf":b64([3;32]), "context":"installation-one"});
    let wrapped = call(request.clone(), 2).unwrap();
    assert_ne!(wrapped, call(request.clone(), 3).unwrap());
    request["op"] = "identity_unwrap".into();
    request["envelope"] = wrapped["envelope"].clone();
    assert_eq!(call(request.clone(), 4).unwrap(), identity);
    request["prf"] = b64([4; 32]).into();
    assert!(call(request.clone(), 4).is_err());
    request["prf"] = b64([3; 32]).into();
    request["context"] = "installation-two".into();
    assert!(call(request.clone(), 4).is_err());
    request["context"] = "installation-one".into();
    let mut corrupted = bytes(&wrapped["envelope"]);
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    request["envelope"] = b64(corrupted).into();
    assert!(call(request, 4).is_err());
}

fn payload() -> String {
    json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item", "entity":{"id":b64([7;16]),"title":"Synthetic","credentials":[],"unknown":{"retained":true}}}).to_string()
}

#[test]
fn form_edits_preserve_exact_numbers_and_unknown_field_members() {
    let mut original: Value = serde_json::from_str(&payload()).unwrap();
    original["entity"]["credentials"] = json!([{"type":"basic-auth", "username":{"fieldType":"string","value":"before","label":"Account","vendor":true},"password":{"fieldType":"concealed-string","value":"before","vendor":17}}]);
    let mut raw = original.to_string();
    raw = raw.replace("\"retained\":true", "\"retained\":9007199254740993,\"decimal\":1.2345678901234567890123456789");
    let edited = call(json!({"op":"payload_edit", "entryId":hex::encode([7;16]), "payload":raw, "changes":{"title":"Changed","login":{"password":"after"}}}), 1).unwrap();
    let encoded = edited["payload"].as_str().unwrap();
    assert!(encoded.contains("9007199254740993"));
    assert!(encoded.contains("1.2345678901234567890123456789"));
    let value: Value = serde_json::from_str(encoded).unwrap();
    assert_eq!(value["entity"]["credentials"][0]["username"]["label"], "Account");
    assert_eq!(value["entity"]["credentials"][0]["password"]["vendor"], 17);
    assert_eq!(value["entity"]["credentials"][0]["password"]["value"], "after");
    assert!(call(json!({"op":"payload_edit", "entryId":hex::encode([8;16]), "payload":raw, "changes":{}}), 1).is_err());
}

#[test]
fn records_roundtrip_binds_recipient_entry_revision_and_payload() {
    let alice = identity(1);
    let bob = identity(2);
    let outsider = identity(3);
    let request = json!({"op":"entry_encrypt", "entryId":hex::encode([7;16]),"payload":payload(),"recipients":[alice["participantPem"],bob["participantPem"]]});
    let entry = call(request.clone(), 4).unwrap();
    let updated = call(request, 5).unwrap();
    for who in [&alice, &bob] {
        let result = call(json!({"op":"entry_decrypt","identity":who["identity"],"primary":entry["primary"],"grant":entry["grants"][who["participantId"].as_str().unwrap()]}), 1).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(result["payload"].as_str().unwrap()).unwrap(),
            serde_json::from_str::<Value>(&payload()).unwrap()
        );
    }
    let mut decrypt = json!({"op":"entry_decrypt","identity":outsider["identity"],"primary":entry["primary"],"grant":entry["grants"][alice["participantId"].as_str().unwrap()]});
    assert!(call(decrypt.clone(), 1).is_err());
    decrypt["identity"] = alice["identity"].clone();
    decrypt["primary"] = updated["primary"].clone();
    assert!(call(decrypt.clone(), 1).is_err());
    let mut primary = bytes(&entry["primary"]);
    let last = primary.len() - 1;
    primary[last] ^= 1;
    decrypt["primary"] = b64(primary).into();
    assert!(call(decrypt, 1).is_err());
}

#[test]
fn ssh_signature_binds_namespace_message_and_authorized_key() {
    let alice = identity(1);
    let bob = identity(2);
    let signed=call(json!({"op":"ssh_sign","identity":alice["identity"],"message":b64(b"synthetic unsigned commit")}),3).unwrap();
    let mut verify = json!({"op":"ssh_verify","publicKey":alice["signingPem"],"message":b64(b"synthetic unsigned commit"),"signature":signed["signature"]});
    assert_eq!(call(verify.clone(), 3).unwrap()["valid"], true);
    verify["publicKey"] = bob["signingPem"].clone();
    assert!(call(verify.clone(), 3).is_err());
    verify["publicKey"] = alice["signingPem"].clone();
    verify["message"] = b64(b"changed commit").into();
    assert!(call(verify, 3).is_err());
    let inspected = call(
        json!({"op":"ssh_inspect","signature":signed["signature"]}),
        3,
    )
    .unwrap();
    assert_eq!(inspected["publicKey"], alice["signingPem"]);
}

#[test]
fn software_passkey_registration_and_assertion_are_verifiable_and_counter_zero() {
    let client = |kind| {
        b64(json!({"type":kind,"challenge":b64([9;32]),"origin":"https://example.test","crossOrigin":false}).to_string())
    };
    let registered=call(json!({"op":"passkey_create","rpId":"example.test","userHandle":b64([1;16]),"clientDataJSON":client("webauthn.create"),"uv":true}),4).unwrap();
    let registration = bytes(&registered["authenticatorData"]);
    assert_eq!(
        &registration[..32],
        Sha256::digest(b"example.test").as_slice()
    );
    assert_eq!(registration[32], 0x4d);
    assert_eq!(&registration[33..37], &[0; 4]);
    assert_eq!(&registration[55..87], bytes(&registered["credentialId"]));
    assert_eq!(&registration[87..], bytes(&registered["cosePublicKey"]));
    assert!(
        bytes(&registered["attestationObject"])
            .windows(registration.len())
            .any(|w| w == registration)
    );
    let request = json!({"op":"passkey_assert","rpId":"example.test","privateKey":registered["privateKey"],"clientDataJSON":client("webauthn.get"),"uv":false});
    let assertion = call(request.clone(), 5).unwrap();
    let mut message = bytes(&assertion["authenticatorData"]);
    assert_eq!(message[32], 0x09);
    assert_eq!(&message[33..37], &[0; 4]);
    message.extend_from_slice(&Sha256::digest(
        URL_SAFE_NO_PAD.decode(client("webauthn.get")).unwrap(),
    ));
    let public = VerifyingKey::from_public_key_der(&bytes(&registered["publicKey"])).unwrap();
    let signature = Signature::from_der(&bytes(&assertion["signature"])).unwrap();
    public.verify(&message, &signature).unwrap();
    message[0] ^= 1;
    assert!(public.verify(&message, &signature).is_err());
    assert_eq!(assertion, call(request, 6).unwrap()); // deterministic ECDSA, no counter increment
    assert!(call(json!({"op":"passkey_validate","privateKey":b64([0;48])}), 1).is_err());
}

fn files(identity: &Value) -> Value {
    let id = identity["participantId"].as_str().unwrap();
    let mut files = json!({"kagitaba-format":b64(b"1\n")});
    files[format!("participants/{id}/pub.pem")] =
        b64(identity["participantPem"].as_str().unwrap()).into();
    files[format!("participants/{id}/sign.pem")] =
        b64(identity["signingPem"].as_str().unwrap()).into();
    files
}

#[test]
fn snapshot_checks_canonical_paths_registered_grants_and_revision_transitions() {
    let identity = identity(1);
    let mut files = files(&identity);
    let entry=call(json!({"op":"entry_encrypt","entryId":hex::encode([7;16]),"payload":payload(),"recipients":[identity["participantPem"]]}),2).unwrap();
    let primary_path = format!("entries/{}/primary", hex::encode([7; 16]));
    files[&primary_path] = entry["primary"].clone();
    files[format!(
        "entries/{}/grants/{}",
        hex::encode([7; 16]),
        identity["participantId"].as_str().unwrap()
    )] = entry["grants"][identity["participantId"].as_str().unwrap()].clone();
    let accepted = call(json!({"op":"validate_snapshot","files":files}), 1).unwrap();
    assert_eq!(accepted["entries"], json!([hex::encode([7; 16])]));
    let mut wrong = files.clone();
    wrong["unexpected"] = b64(b"hello").into();
    assert!(call(json!({"op":"validate_snapshot","files":wrong}), 1).is_err());
    let mut wrong = files.clone();
    wrong.as_object_mut().unwrap().remove(&format!(
        "participants/{}/sign.pem",
        identity["participantId"].as_str().unwrap()
    ));
    assert!(call(json!({"op":"validate_snapshot","files":wrong}), 1).is_err());
    let mut changed = files.clone();
    let mut primary = bytes(&changed[&primary_path]);
    let last = primary.len() - 1;
    primary[last] ^= 1;
    changed[&primary_path] = b64(primary).into();
    // Remove grant so structural digest binding does not itself detect this.
    changed
        .as_object_mut()
        .unwrap()
        .retain(|path, _| !path.contains("/grants/"));
    call(json!({"op":"validate_snapshot","files":changed}), 1).unwrap();
    assert!(
        call(
            json!({"op":"validate_snapshot","files":changed,"previous":files}),
            1
        )
        .is_err()
    );
}

#[test]
fn browser_and_native_store_produce_identical_git_sshsig() {
    use kagitaba_core::crypto::PublicKey;
    use kagitaba_store::{Signer, Snapshot, Store};
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    struct NativeSigner {
        public: PublicKey,
        signing: SigningKey,
    }
    impl Signer for NativeSigner {
        fn public_key(&self) -> &PublicKey {
            &self.public
        }
        fn sign(&self, message: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
            let signature: Signature = self.signing.sign(message);
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
    let identity = identity(7);
    let native = NativeSigner {
        public: PublicKey::from_pem(identity["signingPem"].as_str().unwrap()).unwrap(),
        signing: SigningKey::from_slice(&bytes(&identity["identity"])[36..]).unwrap(),
    };
    let directory = tempfile::tempdir().unwrap();
    let store = Store::create(
        &directory.path().join("wallet"),
        Snapshot::empty(
            PublicKey::from_pem(identity["participantPem"].as_str().unwrap()).unwrap(),
            native.public.clone(),
        )
        .unwrap(),
        &native,
    )
    .unwrap();
    let transfer: Value = serde_json::from_slice(&store.export_transfer().unwrap()).unwrap();
    let commit = transfer["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "commit")
        .unwrap();
    let commit = String::from_utf8(bytes(&commit["data"])).unwrap();
    let (headers, body) = commit.split_once("\n\n").unwrap();
    let mut unsigned = Vec::new();
    let mut signature = Vec::new();
    for line in headers.lines() {
        if let Some(line) = line.strip_prefix("gpgsig ") {
            signature.push(line);
        } else if let Some(line) = line.strip_prefix(' ') {
            signature.push(line);
        } else {
            unsigned.push(line);
        }
    }
    let message = format!("{}\n\n{body}", unsigned.join("\n"));
    let native_signature = format!("{}\n", signature.join("\n"));
    let browser_signature = call(
        json!({"op":"ssh_sign", "identity":identity["identity"], "message":b64(message.as_bytes())}),
        3,
    )
    .unwrap();
    assert_eq!(
        native_signature,
        browser_signature["signature"].as_str().unwrap()
    );
}

#[test]
fn recovery_metadata_must_match_enrolled_identity_and_supported_wrapper() {
    let identity = identity(1);
    let context = hex::encode([9; 16]);
    let wrapped = call(json!({"op":"identity_wrap", "identity":identity["identity"], "prf":b64([4;32]), "context":context}),2).unwrap();
    let metadata = json!({"format":"kagitaba-browser-installation", "version":1,
        "participantPem":identity["participantPem"], "participantId":identity["participantId"],
        "signingPem":identity["signingPem"], "signingId":identity["signingId"],
        "installationId":context, "unlock":{"rpId":"kagitaba.local", "prfInput":b64([5;32]), "credentialId":b64([6;32])}, "envelope":wrapped["envelope"]});
    let mut files = files(&identity);
    let path = format!(
        "participants/{}/browser.json",
        identity["participantId"].as_str().unwrap()
    );
    files[&path] = b64(metadata.to_string()).into();
    call(json!({"op":"validate_snapshot","files":files}), 1).unwrap();
    let mut wrong = metadata.clone();
    wrong["participantId"] = hex::encode([0; 32]).into();
    files[&path] = b64(wrong.to_string()).into();
    assert!(call(json!({"op":"validate_snapshot","files":files}), 1).is_err());
    let mut wrong = metadata.clone();
    wrong["unlock"]["rpId"] = "attacker.test".into();
    files[&path] = b64(wrong.to_string()).into();
    assert!(call(json!({"op":"validate_snapshot","files":files}), 1).is_err());
    let mut wrong = metadata;
    wrong["identity"] = identity["identity"].clone();
    files[&path] = b64(wrong.to_string()).into();
    assert!(call(json!({"op":"validate_snapshot","files":files}), 1).is_err());
}

#[test]
fn local_secrets_bind_identity_remote_context_and_ciphertext() {
    let alice = identity(1);
    let bob = identity(2);
    let context = r#"["https://example.test/wallet.git","synthetic-user"]"#;
    let encrypted=call(json!({"op":"local_encrypt","identity":alice["identity"],"context":context,"plaintext":"synthetic-token"}),3).unwrap();
    assert_ne!(encrypted,call(json!({"op":"local_encrypt","identity":alice["identity"],"context":context,"plaintext":"synthetic-token"}),4).unwrap());
    let mut request = json!({"op":"local_decrypt","identity":alice["identity"],"context":context,"envelope":encrypted["envelope"]});
    assert_eq!(
        call(request.clone(), 5).unwrap()["plaintext"],
        "synthetic-token"
    );
    request["identity"] = bob["identity"].clone();
    assert!(call(request.clone(), 5).is_err());
    request["identity"] = alice["identity"].clone();
    request["context"] = "https://attacker.test/wallet.git".into();
    assert!(call(request.clone(), 5).is_err());
    request["context"] = context.into();
    let mut tampered = bytes(&encrypted["envelope"]);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    request["envelope"] = b64(tampered).into();
    assert!(call(request, 5).is_err());
    assert!(call(json!({"op":"local_encrypt","identity":alice["identity"],"context":"x".repeat(4097),"plaintext":"token"}),5).is_err());
    assert!(call(json!({"op":"local_encrypt","identity":alice["identity"],"context":context,"plaintext":"x".repeat(16385)}),5).is_err());
    assert!(block_on(execute(&json!({"op":"local_encrypt","identity":alice["identity"],"context":context,"plaintext":"token"}).to_string(),vec![])).is_err());
}

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use kagitaba_android::execute;
use kagitaba_core::crypto::PublicKey;
use kagitaba_store::{Store, parse_oid};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn call(request: Value, seed: u8) -> Result<Value, &'static str> {
    let mut random = vec![0; 16384];
    ChaCha20Rng::from_seed([seed; 32]).fill_bytes(&mut random);
    execute(request.to_string().as_bytes(), random).map(|s| serde_json::from_str(&s).unwrap())
}

#[test]
fn android_creates_signed_native_wallet_and_preserves_unknown_encrypted_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    let identity = call(json!({"op":"identity_generate"}), 1).unwrap();
    let initial = call(
        json!({"op":"store_create", "path":path, "identity":identity["identity"]}),
        2,
    )
    .unwrap();
    let id = "07070707070707070707070707070707";
    let payload = json!({"format":"kagitaba-cxf", "version":1, "cxfVersion":{"major":1,"minor":0}, "kind":"item",
        "entity":{"id": B64.encode([7;16]), "title":"Synthetic Android login", "credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":"alice"},"password":{"fieldType":"concealed-string","value":"test-only"}}],
        "kagitabaAndroid":{"apps":[{"package":"org.example.test","certificates":["AA:BB"]}]}, "unknown":"preserved"}}).to_string();
    let encrypted = call(json!({"op":"entry_encrypt","entryId":id,"payload":payload,"recipients":[identity["participantPem"]]}), 3).unwrap();
    let saved = call(json!({"op":"store_save", "path":path, "root":initial["root"],"checkpoint":initial["head"],"identity":identity["identity"],
        "entryId":id,"primary":encrypted["primary"],"grants":encrypted["grants"]}), 4).unwrap();
    let native = Store::open(
        &path,
        PublicKey::from_pem(initial["root"].as_str().unwrap()).unwrap(),
        Some(parse_oid(initial["head"].as_str().unwrap()).unwrap()),
    )
    .unwrap();
    assert_eq!(native.head.to_string(), saved["head"]);
    assert_eq!(native.snapshot.wallet.entries().len(), 1);
    let decrypted = call(json!({"op":"entry_decrypt", "identity":identity["identity"],"primary":saved["entries"][0]["primary"],
        "grant": saved["entries"][0]["grants"][identity["participantId"].as_str().unwrap()]}), 5).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(decrypted["payload"].as_str().unwrap()).unwrap(),
        serde_json::from_str::<Value>(&payload).unwrap()
    );
    let outsider = call(json!({"op":"identity_generate"}), 6).unwrap();
    let catalogue_request=json!({"op":"store_catalog","path":path,"root":saved["root"],"checkpoint":saved["head"],"identity":identity["identity"]});
    let catalogue=call(catalogue_request.clone(),21).unwrap();
    assert_eq!(catalogue["written"],true);
    assert_eq!(catalogue["rows"][0]["id"],id);
    assert_eq!(catalogue["rows"][0]["usernames"],json!(["alice"]));
    assert_eq!(catalogue["rows"][0]["password"],true);
    assert!(!catalogue.to_string().contains("test-only"));
    assert!(catalogue["rows"][0].get("credentials").is_none());
    let again=call(catalogue_request,22).unwrap();
    assert_eq!(again["written"],false);
    assert_eq!(again["head"],catalogue["head"]);
    assert!(call(json!({"op":"store_catalog","path":path,"root":saved["root"],"identity":identity["identity"]}),23).is_err());
    assert!(call(json!({"op":"store_catalog","path":path,"root":saved["root"],"checkpoint":saved["head"],"identity":outsider["identity"]}),24).is_err());
    assert!(call(json!({"op":"store_delete","path":path,"root":saved["root"],"checkpoint":saved["head"],"identity":outsider["identity"],"entryId":id}), 7).is_err());
    assert_eq!(call(json!({"op":"store_open","path":path,"root":outsider["signingPem"],"checkpoint":saved["head"]}), 7).unwrap_err(), "Wallet signature is missing, invalid, or signed by an unauthorized participant. No changes were accepted.");
    assert!(call(json!({"op":"store_open","path":path}), 7).is_err());
    let deleted = call(json!({"op":"store_delete","path":path,"root":saved["root"],"checkpoint":saved["head"],"identity":identity["identity"],"entryId":id}), 7).unwrap();
    assert_eq!(deleted["entries"], json!([]));
    // Trying to accept an old checkpoint is a rollback, even if its signature is valid.
    assert_eq!(call(json!({"op":"store_accept","path":path,"root":deleted["root"],"checkpoint":deleted["head"],"candidate":saved["head"]}), 8).unwrap_err(), "Wallet history does not include this device's trusted checkpoint. Fetch updates or resolve divergence on your computer; do not reset trust.");
}

#[test]
fn android_names_are_signed_metadata_and_do_not_change_participant_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    let identity = call(json!({"op":"identity_generate"}), 31).unwrap();
    let initial = call(json!({"op":"store_create", "path":path, "identity":identity["identity"]}),32).unwrap();
    let id = identity["participantId"].as_str().unwrap();
    let meta_id = "09090909090909090909090909090909";
    let encrypt_name = |name: &str, seed| call(json!({"op":"metadata_encrypt","entryId":meta_id,"participantId":id,"name":name,"recipients":[identity["participantPem"]]}),seed);
    let rename = |encrypted: &Value| json!({"op":"store_name_participant","path":path,"root":initial["root"],"checkpoint":initial["head"],"identity":identity["identity"],"participantId":id,"primary":encrypted["primary"],"grants":encrypted["grants"]});
    let encrypted_name = encrypt_name("Pixel",33).unwrap();
    let named = call(rename(&encrypted_name),33).unwrap();
    assert_eq!(named["participantMetadata"][id], meta_id);
    assert!(named.get("participantNames").is_none());
    assert!(!named.to_string().contains("Pixel"));
    assert!(!path.join(format!("participants/{id}/name.json")).exists());
    let decrypted = call(json!({"op":"metadata_decrypt","identity":identity["identity"],"participantId":id,"primary":encrypted_name["primary"],"grant":encrypted_name["grants"][id]}),34).unwrap();
    assert_eq!(decrypted["name"], "Pixel");
    assert_eq!(named["participants"], initial["participants"]);
    assert_eq!(named["signers"], initial["signers"]);
    assert_eq!(named["entries"].as_array().unwrap().len(), 1);
    assert_ne!(named["head"], initial["head"]);
    assert!(encrypt_name("bad\nname",34).is_err());
    let entry_id = "07070707070707070707070707070707";
    let payload = json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item","entity":{"id":B64.encode([7;16]),"title":"Synthetic name test","credentials":[]}}).to_string();
    let encrypted = call(json!({"op":"entry_encrypt","entryId":entry_id,"payload":payload,"recipients":[identity["participantPem"]]}),35).unwrap();
    let saved = call(json!({"op":"store_save", "path":path,"root":initial["root"],"checkpoint":initial["head"],"identity":identity["identity"],"entryId":entry_id,"primary":encrypted["primary"],"grants":encrypted["grants"]}),35).unwrap();
    assert_eq!(saved["participantMetadata"][id], meta_id);
    let empty = encrypt_name("",36).unwrap();
    call(rename(&empty),36).unwrap();
    let decrypted = call(json!({"op":"metadata_decrypt","identity":identity["identity"],"participantId":id,"primary":empty["primary"],"grant":empty["grants"][id]}),37).unwrap();
    assert_eq!(decrypted["name"], "");
}

#[test]
fn android_browser_supplied_hash_is_signed_exactly_once_and_length_checked() {
    let data = json!({"type":"webauthn.create","origin":"https://example.test","challenge":B64.encode([1;32])}).to_string();
    let registered = call(json!({"op":"passkey_create","rpId":"example.test","userHandle":B64.encode([2;16]),"clientDataJSON":B64.encode(data),"uv":true}), 2).unwrap();
    let client_hash = Sha256::digest(b"browser-owned clientDataJSON including cross-origin fields");
    let request = json!({"op":"passkey_assert","rpId":"example.test","privateKey":registered["privateKey"],"clientDataHash":B64.encode(client_hash),"uv":true});
    let signed = call(request.clone(), 3).unwrap();
    let mut signed_data = B64
        .decode(signed["authenticatorData"].as_str().unwrap())
        .unwrap();
    assert_eq!(&signed_data[33..37], &[0; 4]);
    assert_eq!(signed_data[32], 0x0d);
    signed_data.extend_from_slice(&client_hash);
    let key = VerifyingKey::from_public_key_der(
        &B64.decode(registered["publicKey"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    key.verify(
        &signed_data,
        &Signature::from_der(&B64.decode(signed["signature"].as_str().unwrap()).unwrap()).unwrap(),
    )
    .unwrap();
    for len in [0, 31, 33, 64] {
        let mut invalid = request.clone();
        invalid["clientDataHash"] = B64.encode(vec![0; len]).into();
        assert!(call(invalid, 3).is_err());
    }
}

#[test]
fn android_preserves_native_attachments_on_edit_refuses_reduction_and_deletes_owner_tree() {
    use kagitaba_core::wallet::{Entry,PrimaryRecord,GrantRecord};
    use kagitaba_store::Signer;
    use p256::ecdsa::{SigningKey,signature::Signer as _};
    struct NativeSigner { key: SigningKey, public: PublicKey }
    impl Signer for NativeSigner {
        fn public_key(&self)->&PublicKey { &self.public }
        fn sign(&self,message:&[u8])->kagitaba_store::Result<Vec<u8>> { let signature:Signature=self.key.sign(message);Ok(signature.to_der().as_bytes().to_vec()) }
    }
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("wallet");
    let own=call(json!({"op":"identity_generate"}),1).unwrap();
    let initial=call(json!({"op":"store_create","path":path,"identity":own["identity"]}),2).unwrap();
    let signer=NativeSigner{key:SigningKey::from_slice(&B64.decode(own["identity"].as_str().unwrap()).unwrap()[36..]).unwrap(),public:PublicKey::from_pem(own["signingPem"].as_str().unwrap()).unwrap()};
    let mut store=Store::open(&path,signer.public.clone(),Some(parse_oid(initial["head"].as_str().unwrap()).unwrap())).unwrap();
    let id=kagitaba_core::EntryId::from_bytes([7;16]);
    let raw=json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item","entity":{"id":B64.encode([7;16]),"title":"Attached","credentials":[]}}).to_string();
    let payload=kagitaba_cxf::Payload::from_json(id,raw.as_bytes()).unwrap();
    let (payload,blobs)=kagitaba_cxf::attachments::add(&payload,"file.txt",b"synthetic attachment",&mut ChaCha20Rng::from_seed([3;32])).unwrap();
    let raw=String::from_utf8(payload.to_json().unwrap().to_vec()).unwrap();
    let encrypted=call(json!({"op":"entry_encrypt","entryId":id.to_string(),"payload":raw,"recipients":[own["participantPem"]]}),4).unwrap();
    let entry=Entry::from_parts(PrimaryRecord::from_bytes(&B64.decode(encrypted["primary"].as_str().unwrap()).unwrap()).unwrap(), encrypted["grants"].as_object().unwrap().values().map(|value|GrantRecord::from_bytes(&B64.decode(value.as_str().unwrap()).unwrap()).unwrap())).unwrap();
    let mut next=store.snapshot.clone();next.wallet=next.wallet.with_entry(entry).unwrap();next.attachments.insert(id,blobs.iter().map(|(id,chunks)|(id.clone(),kagitaba_store::AttachmentBlob::from_chunks(chunks).unwrap())).collect());
    store.save(next,&signer,"Synthetic attachment").unwrap();
    let opened=call(json!({"op":"store_open","path":path,"root":initial["root"],"checkpoint":store.head.to_string()}),5).unwrap();
    assert_eq!(opened["entries"][0]["hasAttachments"],true);
    let edited=call(json!({"op":"payload_edit","entryId":id.to_string(),"payload":raw,"changes":{"title":"Edited title"}}),5).unwrap();
    call(json!({"op":"validate_attachment_edit","entryId":id.to_string(),"payload":edited["payload"],"previousPayload":raw}),5).unwrap();
    let encrypted=call(json!({"op":"entry_encrypt","entryId":id.to_string(),"payload":edited["payload"],"recipients":[own["participantPem"]]}),6).unwrap();
    let mut request=json!({"op":"store_save","path":path,"root":initial["root"],"checkpoint":store.head.to_string(),"identity":own["identity"],"entryId":id.to_string(),"primary":encrypted["primary"],"grants":{}});
    assert_eq!(call(request.clone(),7).unwrap_err(),"Attachment recipients must be changed in the native app");
    request["grants"]=encrypted["grants"].clone();
    let saved=call(request,7).unwrap();
    let native=Store::open(&path,signer.public.clone(),Some(parse_oid(saved["head"].as_str().unwrap()).unwrap())).unwrap();
    assert_eq!(native.snapshot.attachments[&id],blobs.iter().map(|(id,chunks)|(id.clone(),kagitaba_store::AttachmentBlob::from_chunks(chunks).unwrap())).collect());
    let deleted=call(json!({"op":"store_delete","path":path,"root":initial["root"],"checkpoint":saved["head"],"identity":own["identity"],"entryId":id.to_string()}),8).unwrap();
    let native=Store::open(&path,signer.public,Some(parse_oid(deleted["head"].as_str().unwrap()).unwrap())).unwrap();
    assert!(native.snapshot.attachments.is_empty());
}

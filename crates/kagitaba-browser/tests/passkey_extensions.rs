use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::executor::block_on;
use kagitaba_browser::execute;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Value, json};

fn b64(value: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn call(request: &Value, seed: u8) -> Result<Value, kagitaba_browser::Error> {
    let mut random = vec![0; 8192];
    ChaCha20Rng::from_seed([seed; 32]).fill_bytes(&mut random);
    block_on(execute(&request.to_string(), random)).map(|s| serde_json::from_str(&s).unwrap())
}
fn create_request() -> Value {
    json!({"op":"passkey_create","rpId":"example.test","userHandle":b64([1;16]),
        "clientDataJSON":b64(json!({"type":"webauthn.create","challenge":"AQ","origin":"https://example.test"}).to_string()),
        "uv":true,"prf":true,"prfEval":{"first":b64(b"hello"),"second":""}})
}
fn assertion(credential: &Value) -> Value {
    json!({"op":"passkey_assert","rpId":"example.test","privateKey":credential["privateKey"],
        "clientDataHash":b64([9;32]),"uv":true,"prfKey":credential["prfKey"],
        "prfEval":{"first":b64(b"hello"),"second":""}})
}

#[test]
fn prf_matches_independent_hmac_sha256_vectors_and_requires_uv() {
    let credential = call(&create_request(), 1).unwrap();
    let mut request = assertion(&credential);
    request["prfKey"] = b64([7; 32]).into();
    let result = call(&request, 2).unwrap();
    // Python stdlib hmac/hashlib: HMAC(key, SHA256(b"WebAuthn PRF\0" + input)).
    assert_eq!(
        result["prfResults"],
        json!({
            "first":"UW1a3ukMVxXEAfp82K_w-bhGv8GWcPCG79otXHU7nHU",
            "second":"lRUh-YWKtuH8GvgrEuMe9YSAHSDGQ3EBoo3fVxBVmlg"
        })
    );
    for field in ["prfKey", "prfEval"] {
        let mut bad = request.clone();
        bad[field] = Value::Null;
        assert!(call(&bad, 2).is_err());
    }
    request["uv"] = false.into();
    assert!(call(&request, 2).is_err());
    let mut creation = create_request();
    creation["uv"] = false.into();
    assert!(call(&creation, 2).is_err());
}

#[test]
fn prf_is_stable_per_credential_separates_inputs_and_survives_encrypted_transfer() {
    let credential = call(&create_request(), 1).unwrap();
    let other = call(&create_request(), 2).unwrap();
    assert_ne!(credential["prfKey"], other["prfKey"]);
    assert_ne!(credential["prfResults"], other["prfResults"]);
    assert_ne!(
        credential["prfResults"]["first"],
        credential["prfResults"]["second"]
    );
    assert_eq!(
        call(&assertion(&credential), 3).unwrap()["prfResults"],
        credential["prfResults"]
    );

    let identity = call(&json!({"op":"identity_generate"}), 4).unwrap();
    let payload = json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},
    "kind":"item","entity":{"id":b64([7;16]),"title":"Synthetic PRF fixture","credentials":[{
        "type":"passkey","credentialId":credential["credentialId"],"rpId":"example.test",
        "userHandle":credential["userHandle"],"username":"synthetic","userDisplayName":"Synthetic",
        "key":credential["privateKey"],"kagitabaPasskey":{"version":1,"prfKey":credential["prfKey"],"largeBlob":"AAEC"}
    }]}});
    let encrypted = call(
        &json!({"op":"entry_encrypt","entryId":hex::encode([7;16]),
        "payload":payload.to_string(),"recipients":[identity["participantPem"]]}),
        5,
    )
    .unwrap();
    let opened = call(&json!({"op":"entry_decrypt","identity":identity["identity"],
        "primary":encrypted["primary"],"grant":encrypted["grants"][identity["participantId"].as_str().unwrap()]}), 6).unwrap();
    let restored: Value = serde_json::from_str(opened["payload"].as_str().unwrap()).unwrap();
    assert_eq!(restored, payload);
    let stored = &restored["entity"]["credentials"][0];
    let mut request = assertion(&credential);
    request["privateKey"] = stored["key"].clone();
    request["prfKey"] = stored["kagitabaPasskey"]["prfKey"].clone();
    assert_eq!(
        call(&request, 7).unwrap()["prfResults"],
        credential["prfResults"]
    );
}

#[test]
fn prf_bounds_missing_inputs_and_randomness_fail_closed() {
    let credential = call(&create_request(), 1).unwrap();
    let request = assertion(&credential);
    for key in [vec![], vec![1; 31], vec![1; 33]] {
        let mut bad = request.clone();
        bad["prfKey"] = b64(key).into();
        assert!(call(&bad, 2).is_err());
    }
    for eval in [
        json!({"second":"AQ"}),
        json!({"first":"!"}),
        json!({"first":b64(vec![0;32769])}),
    ] {
        let mut bad = request.clone();
        bad["prfEval"] = eval;
        assert!(call(&bad, 2).is_err());
    }
    let mut missing_key = request.clone();
    missing_key.as_object_mut().unwrap().remove("prfKey");
    assert!(call(&missing_key, 2).is_err());
    let mut no_eval = request;
    no_eval.as_object_mut().unwrap().remove("prfEval");
    assert!(call(&no_eval, 2).unwrap().get("prfResults").is_none());
    let mut creation = create_request();
    creation.as_object_mut().unwrap().remove("prfEval");
    assert!(call(&creation, 3).unwrap().get("prfKey").is_some());
    // Enough for an ES256 scalar and credential ID, but not the independent PRF key.
    assert!(block_on(execute(&creation.to_string(), vec![1; 64])).is_err());
}

//! ES256 software authenticator primitives. Browser policy and verified origin,
//! RP selection, presence and actual UV decisions belong to the privileged app.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToSec1Point,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};

fn length(out: &mut Vec<u8>, major: u8, n: usize) {
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 255 {
        out.extend_from_slice(&[major | 24, n as u8]);
    } else {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    length(out, 0x40, value.len());
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    length(out, 0x60, value.len());
    out.extend_from_slice(value.as_bytes());
}
fn cose(secret: &p256::SecretKey) -> Vec<u8> {
    let point = secret.public_key().to_sec1_point(false);
    let mut result = vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21];
    bytes(&mut result, &point.as_bytes()[1..33]);
    result.push(0x22);
    bytes(&mut result, &point.as_bytes()[33..]);
    result
}
fn auth_data(request: &Value, attested: bool) -> Result<Vec<u8>> {
    let rp = string(request, "rpId")?;
    if rp.is_empty()
        || rp.len() > 253
        || rp
            .bytes()
            .any(|b| !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'.' && b != b'-')
    {
        return Err(Error);
    }
    let uv = request.get("uv").and_then(Value::as_bool).ok_or(Error)?;
    // UP; BE (software key can be backed up); BS remains false until known backed up.
    let flags = 0x09 | if uv { 0x04 } else { 0 } | if attested { 0x40 } else { 0 };
    let mut data = Sha256::digest(rp.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&[0; 4]); // CXF import requires counter zero forever.
    Ok(data)
}
fn client_data(request: &Value, expected: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = binary(request, "clientDataJSON")?;
    if bytes.len() > 8192 {
        return Err(Error);
    }
    let data: Value = serde_json::from_slice(&bytes).map_err(|_| Error)?;
    if data["type"] != expected
        || string(&data, "origin")?.is_empty()
        || decode(string(&data, "challenge")?)?.is_empty()
    {
        return Err(Error);
    }
    Ok(bytes)
}

// WebAuthn's abstract PRF implementation: a separate random per-credential
// secret, never the signing key and never the wallet-unlock PRF. The application
// persists this secret inside the encrypted credential, alongside its PKCS#8.
fn prf_results(request: &Value, key: &[u8]) -> Result<Option<Value>> {
    if key.len() != 32 || request.get("uv").and_then(Value::as_bool) != Some(true) {
        return Err(Error);
    }
    let Some(eval) = request.get("prfEval") else {
        return Ok(None);
    };
    let evaluate = |name| -> Result<String> {
        let input = binary(eval, name)?;
        if input.len() > 32768 {
            return Err(Error);
        }
        let mut salt = Sha256::new();
        salt.update(b"WebAuthn PRF\0");
        salt.update(&input);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error)?;
        mac.update(&salt.finalize());
        let mut output = mac.finalize().into_bytes();
        let encoded = b64(output.as_slice());
        output.as_mut_slice().zeroize();
        Ok(encoded)
    };
    let mut result = json!({"first": evaluate("first")?});
    if eval.get("second").is_some() {
        result["second"] = evaluate("second")?.into();
    }
    Ok(Some(result))
}
pub(super) fn operation(request: &Value, random: &mut Random) -> Result<Value> {
    match string(request, "op")? {
        "passkey_create" => {
            client_data(request, "webauthn.create")?;
            let user = binary(request, "userHandle")?;
            if user.is_empty() || user.len() > 64 {
                return Err(Error);
            }
            let secret = p256::SecretKey::try_generate_from_rng(random).map_err(|_| Error)?;
            let mut id = [0; 32];
            random.try_fill_bytes(&mut id)?;
            let cose_key = cose(&secret);
            let mut auth = auth_data(request, true)?;
            auth.extend_from_slice(&[0; 16]); // no identifying AAGUID / no attestation
            auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
            auth.extend_from_slice(&id);
            auth.extend_from_slice(&cose_key);
            let mut attestation = vec![0xa3];
            text(&mut attestation, "fmt");
            text(&mut attestation, "none");
            text(&mut attestation, "attStmt");
            attestation.push(0xa0);
            text(&mut attestation, "authData");
            bytes(&mut attestation, &auth);
            let mut result = json!({"privateKey": b64(secret.to_pkcs8_der().map_err(|_| Error)?.as_bytes()),
                "credentialId": b64(id), "userHandle": b64(user), "cosePublicKey": b64(cose_key),
                "publicKey": b64(public(&secret)?.to_der()), "publicKeyAlgorithm": -7,
                "authenticatorData": b64(auth), "attestationObject": b64(attestation)});
            if request.get("prf").and_then(Value::as_bool) == Some(true) {
                let mut key = Zeroizing::new([0; 32]);
                random.try_fill_bytes(key.as_mut())?;
                if let Some(values) = prf_results(request, key.as_ref())? {
                    result["prfResults"] = values;
                }
                result["prfKey"] = b64(key.as_ref()).into();
            } else if request.get("prfEval").is_some() {
                return Err(Error);
            }
            Ok(result)
        }
        "passkey_assert" => {
            let secret = p256::SecretKey::from_pkcs8_der(&binary(request, "privateKey")?)
                .map_err(|_| Error)?;
            let mut message = auth_data(request, false)?;
            let auth = b64(&message);
            // Android privileged browser callers provide the already-computed
            // clientDataHash. Only the trusted provider may supply this field.
            // Ordinary browser requests continue to validate and hash their JSON.
            let hash = if request.get("clientDataHash").is_some() {
                let hash = binary(request, "clientDataHash")?;
                if hash.len() != 32 {
                    return Err(Error);
                }
                hash.to_vec()
            } else {
                Sha256::digest(client_data(request, "webauthn.get")?).to_vec()
            };
            message.extend_from_slice(&hash);
            let signature: Signature = SigningKey::from(secret).sign(&message);
            let mut result =
                json!({"authenticatorData": auth, "signature": b64(signature.to_der().as_bytes())});
            if request.get("prfKey").is_some() {
                if let Some(values) = prf_results(request, &binary(request, "prfKey")?)? {
                    result["prfResults"] = values;
                }
            } else if request.get("prfEval").is_some() {
                return Err(Error);
            }
            Ok(result)
        }
        "passkey_validate" => {
            let secret = p256::SecretKey::from_pkcs8_der(&binary(request, "privateKey")?)
                .map_err(|_| Error)?;
            Ok(json!({"publicKey": b64(public(&secret)?.to_der()), "publicKeyAlgorithm": -7}))
        }
        _ => Err(Error),
    }
}

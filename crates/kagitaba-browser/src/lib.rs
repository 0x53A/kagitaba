//! Portable application cryptography for the standalone browser client.
#![forbid(unsafe_code)]

mod passkey;
mod edit;
mod snapshot;
mod ssh;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use kagitaba_core::{
    EntryId,
    crypto::{Ciphertext, ContentKey, PublicKey, SoftwareIdentity},
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use kagitaba_cxf::Payload;
use p256::{elliptic_curve::Generate, pkcs8::EncodePublicKey};
use rand_core::{TryCryptoRng, TryRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Error>;

/// Errors deliberately contain no caller-controlled or secret values.
#[derive(Debug)]
pub struct Error;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid or unsupported browser cryptographic operation")
    }
}
impl std::error::Error for Error {}

/// The caller supplies fresh cryptographically random bytes for every call.
/// Exhaustion is an error, never a deterministic expansion or implicit OS RNG.
struct Random {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}
impl TryRng for Random {
    type Error = Error;
    fn try_next_u32(&mut self) -> Result<u32> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        let end = self.position.checked_add(dst.len()).ok_or(Error)?;
        dst.copy_from_slice(self.bytes.get(self.position..end).ok_or(Error)?);
        self.bytes[self.position..end].zeroize();
        self.position = end;
        Ok(())
    }
}
impl TryCryptoRng for Random {}

struct SecretJson(Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or(Error)
}
fn decode(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map(Zeroizing::new)
        .map_err(|_| Error)
}
fn binary(value: &Value, key: &str) -> Result<Zeroizing<Vec<u8>>> {
    decode(string(value, key)?)
}
fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn public(secret: &p256::SecretKey) -> Result<PublicKey> {
    PublicKey::from_der(
        secret
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error)?
            .as_bytes(),
    )
    .map_err(|_| Error)
}

struct Identity {
    agreement: p256::SecretKey,
    signing: p256::SecretKey,
}
impl Identity {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 68 || &bytes[..4] != b"KBI1" {
            return Err(Error);
        }
        Ok(Self {
            agreement: p256::SecretKey::from_slice(&bytes[4..36]).map_err(|_| Error)?,
            signing: p256::SecretKey::from_slice(&bytes[36..]).map_err(|_| Error)?,
        })
    }
    fn serialize(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(b"KBI1".to_vec());
        out.extend_from_slice(&self.agreement.to_bytes());
        out.extend_from_slice(&self.signing.to_bytes());
        out
    }
    fn response(&self) -> Result<Value> {
        let participant = public(&self.agreement)?;
        let signing = public(&self.signing)?;
        Ok(json!({
            "identity": b64(self.serialize()),
            "participantPem": participant.to_pem(), "participantId": participant.id().to_string(),
            "signingPem": signing.to_pem(), "signingId": signing.id().to_string()
        }))
    }
}

fn unlock_key(request: &Value) -> Result<(ContentKey, Vec<u8>)> {
    let prf = binary(request, "prf")?;
    let installation = string(request, "context")?;
    if prf.len() != 32 || installation.is_empty() || installation.len() > 512 {
        return Err(Error);
    }
    let mut context = b"Kagitaba/browser/v1/identity\0".to_vec();
    context.extend_from_slice(installation.as_bytes());
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"Kagitaba/browser/v1/PRF-unlock\0"), &prf)
        .expand(&context, key.as_mut())
        .map_err(|_| Error)?;
    Ok((ContentKey::from_bytes(*key), context))
}

fn local_key(request: &Value) -> Result<(ContentKey, Vec<u8>)> {
    let identity = Identity::parse(&binary(request, "identity")?)?;
    let supplied = string(request, "context")?;
    if supplied.is_empty() || supplied.len() > 4096 {
        return Err(Error);
    }
    let mut context = b"Kagitaba/browser/v1/local-secret\0".to_vec();
    context.extend_from_slice(supplied.as_bytes());
    let scalar = Zeroizing::new(identity.signing.to_bytes());
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(
        Some(b"Kagitaba/browser/v1/local-storage-key\0"),
        scalar.as_slice(),
    )
    .expand(&context, key.as_mut())
    .map_err(|_| Error)?;
    Ok((ContentKey::from_bytes(*key), context))
}

/// JSON command boundary. The returned identity and payload are secrets; callers
/// must retain them only in privileged volatile memory. Never log this interface.
#[wasm_bindgen]
pub async fn command(
    request_json: &str,
    random_bytes: Vec<u8>,
) -> std::result::Result<String, JsValue> {
    execute(request_json, random_bytes)
        .await
        .map_err(|_| JsValue::from_str("Browser cryptographic operation failed"))
}

/// Native-testable implementation of the same boundary as [`command`].
pub async fn execute(request_json: &str, random_bytes: Vec<u8>) -> Result<String> {
    if request_json.len() > 96 * 1024 * 1024 || random_bytes.len() > 1024 * 1024 {
        return Err(Error);
    }
    let request = SecretJson(serde_json::from_str(request_json).map_err(|_| Error)?);
    let mut random = Random {
        bytes: Zeroizing::new(random_bytes),
        position: 0,
    };
    let result = SecretJson(dispatch(&request.0, &mut random).await?);
    serde_json::to_string(&result.0).map_err(|_| Error)
}

async fn dispatch(request: &Value, random: &mut Random) -> Result<Value> {
    match string(request, "op")? {
        "payload_edit" => edit::operation(request),
        "identity_generate" => Identity {
            agreement: p256::SecretKey::try_generate_from_rng(random).map_err(|_| Error)?,
            signing: p256::SecretKey::try_generate_from_rng(random).map_err(|_| Error)?,
        }
        .response(),
        "identity_wrap" => {
            let identity = binary(request, "identity")?;
            Identity::parse(&identity)?;
            let (key, context) = unlock_key(request)?;
            let sealed = Ciphertext::seal(&identity, &key, &context, random).map_err(|_| Error)?;
            Ok(json!({"envelope": b64(sealed.as_bytes())}))
        }
        "identity_unwrap" => {
            let (key, context) = unlock_key(request)?;
            let sealed =
                Ciphertext::from_bytes(&binary(request, "envelope")?).map_err(|_| Error)?;
            let clear = sealed.open(&key, &context).map_err(|_| Error)?;
            Identity::parse(clear.as_bytes())?.response()
        }
        "local_encrypt" => {
            let (key, context) = local_key(request)?;
            let plaintext = string(request, "plaintext")?;
            if plaintext.len() > 16384 {
                return Err(Error);
            }
            let sealed = Ciphertext::seal(plaintext.as_bytes(), &key, &context, random)
                .map_err(|_| Error)?;
            Ok(json!({"envelope": b64(sealed.as_bytes())}))
        }
        "local_decrypt" => {
            let (key, context) = local_key(request)?;
            let envelope = binary(request, "envelope")?;
            if envelope.len() > 60 + 16384 + 16 {
                return Err(Error);
            }
            let sealed = Ciphertext::from_bytes(&envelope).map_err(|_| Error)?;
            let clear = sealed.open(&key, &context).map_err(|_| Error)?;
            Ok(json!({"plaintext": std::str::from_utf8(clear.as_bytes()).map_err(|_| Error)?}))
        }
        "entry_encrypt" | "metadata_encrypt" => {
            let id: EntryId = string(request, "entryId")?.parse().map_err(|_| Error)?;
            let recipients = request["recipients"]
                .as_array()
                .ok_or(Error)?
                .iter()
                .map(|v| PublicKey::from_pem(v.as_str().ok_or(Error)?).map_err(|_| Error))
                .collect::<Result<Vec<_>>>()?;
            if recipients.len() > 1024 {
                return Err(Error);
            }
            let entry = if string(request, "op")? == "metadata_encrypt" {
                let participant = string(request, "participantId")?.parse().map_err(|_| Error)?;
                let mut payload = if let Some(json) = request.get("payload").and_then(Value::as_str) {
                    kagitaba_cxf::ParticipantMetadata::from_json(id, participant, json.as_bytes()).map_err(|_| Error)?
                } else { kagitaba_cxf::ParticipantMetadata::new(id, participant) };
                payload.set_name(string(request, "name")?).map_err(|_| Error)?;
                payload.seal(&recipients, random).map_err(|_| Error)?
            } else {
                Payload::from_json(id, string(request, "payload")?.as_bytes()).map_err(|_| Error)?.seal(&recipients, random).map_err(|_| Error)?
            };
            let grants = entry
                .grants()
                .iter()
                .map(|(id, grant)| (id.to_string(), Value::String(b64(grant.to_bytes()))))
                .collect::<serde_json::Map<_, _>>();
            Ok(json!({"primary": b64(entry.primary().to_bytes()), "grants": grants}))
        }
        "entry_decrypt" | "metadata_decrypt" => {
            let identity = Identity::parse(&binary(request, "identity")?)?;
            let scalar = Zeroizing::new(identity.agreement.to_bytes());
            let software =
                SoftwareIdentity::from_bytes(scalar.as_slice().try_into().map_err(|_| Error)?)
                    .map_err(|_| Error)?;
            let primary =
                PrimaryRecord::from_bytes(&binary(request, "primary")?).map_err(|_| Error)?;
            let grant = GrantRecord::from_bytes(&binary(request, "grant")?).map_err(|_| Error)?;
            let entry = Entry::from_parts(primary, [grant]).map_err(|_| Error)?;
            if string(request, "op")? == "metadata_decrypt" {
                let participant = string(request, "participantId")?.parse().map_err(|_| Error)?;
                let payload = kagitaba_cxf::ParticipantMetadata::open(&entry, participant, &software.public_key(), &software).await.map_err(|_| Error)?;
                return Ok(json!({"payload":std::str::from_utf8(&payload.to_json().map_err(|_| Error)?).map_err(|_| Error)?, "name":payload.name().unwrap_or("")}));
            }
            let payload = Payload::open(&entry, &software.public_key(), &software)
                .await
                .map_err(|_| Error)?;
            Ok(
                json!({"payload": std::str::from_utf8(&payload.to_json().map_err(|_| Error)?).map_err(|_| Error)?}),
            )
        }
        "public_key" => {
            let key = PublicKey::from_pem(string(request, "pem")?).map_err(|_| Error)?;
            Ok(json!({"id": key.id().to_string()}))
        }
        "hash" => {
            let data = binary(request, "data")?;
            let digest = match string(request, "algorithm")? {
                "sha256" => Sha256::digest(&data).to_vec(),
                "sha1" => sha1::Sha1::digest(&data).to_vec(),
                _ => return Err(Error),
            };
            Ok(json!({"digest": b64(&digest), "hex": hex::encode(digest)}))
        }
        "ssh_sign" | "ssh_verify" | "ssh_inspect" => ssh::operation(request),
        "passkey_create" | "passkey_assert" | "passkey_validate" => {
            passkey::operation(request, random)
        }
        "validate_snapshot" => snapshot::operation(request),
        _ => Err(Error),
    }
}

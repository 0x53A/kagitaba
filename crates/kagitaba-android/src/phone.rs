//! Application-owned Android Keystore callbacks. No private scalar crosses JNI.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JObject, JValue},
};
use kagitaba_core::{
    KeyId,
    crypto::{AgreementRequest, AgreementSecret, KeyAgreement, PublicKey},
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use kagitaba_store::Signer;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const ERROR: &str = "Phone key operation failed. Authenticate again or use another enrolled key.";
struct Phone {
    vm: JavaVM,
    callback: GlobalRef,
    encryption: PublicKey,
    signing: PublicKey,
    active: AtomicBool,
}
impl Phone {
    fn call(&self, method: &str, input: &[u8], max: usize) -> Result<Zeroizing<Vec<u8>>> {
        if !self.active.load(Ordering::Acquire) {
            return Err(ERROR);
        }
        let result = (|| -> jni::errors::Result<_> {
            let mut env = self.vm.attach_current_thread()?;
            env.with_local_frame(8, |env| {
                let request = env.byte_array_from_slice(input)?;
                let result = env.call_method(
                    self.callback.as_obj(),
                    method,
                    "([B)[B",
                    &[JValue::Object(request.as_ref())],
                );
                if env.exception_check()? {
                    env.exception_clear()?;
                }
                env.set_byte_array_region(&request, 0, &vec![0; input.len()])?;
                let response = JByteArray::from(result?.l()?);
                let len = env.get_array_length(&response)? as usize;
                if len > max {
                    return Err(jni::errors::Error::NullPtr("oversized result"));
                }
                let bytes = Zeroizing::new(env.convert_byte_array(&response)?);
                env.set_byte_array_region(&response, 0, &vec![0; len])?;
                Ok(bytes)
            })
        })()
        .map_err(|_| ERROR)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(ERROR);
        }
        Ok(result)
    }
}
impl KeyAgreement for Phone {
    fn key_id(&self) -> KeyId {
        self.encryption.id()
    }
    async fn agree(&self, request: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
        if request.recipient() != self.key_id() {
            return Err(kagitaba_core::Error::WrongRecipient);
        }
        let bytes = self
            .call("agree", request.peer_public_key(), 32)
            .map_err(|_| kagitaba_core::Error::KeyUnavailable)?;
        Ok(AgreementSecret::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| kagitaba_core::Error::KeyUnavailable)?,
        ))
    }
}
impl Signer for Phone {
    fn public_key(&self) -> &PublicKey {
        &self.signing
    }
    fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.call("sign", bytes, 80)
            .map(|b| b.to_vec())
            .map_err(|_| kagitaba_store::Error::Signing)
    }
}
static SESSIONS: OnceLock<Mutex<HashMap<u64, Arc<Phone>>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
fn sessions() -> &'static Mutex<HashMap<u64, Arc<Phone>>> {
    SESSIONS.get_or_init(Default::default)
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field].as_str().ok_or(ERROR)
}
pub(super) fn open(env: &mut JNIEnv<'_>, callback: JObject<'_>, input: &str) -> Result<String> {
    let v: Value = serde_json::from_str(input).map_err(|_| ERROR)?;
    let encryption = PublicKey::from_pem(text(&v, "participantPem")?).map_err(|_| ERROR)?;
    let signing = PublicKey::from_pem(text(&v, "signingPem")?).map_err(|_| ERROR)?;
    if encryption == signing {
        return Err(ERROR);
    }
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    let response = json!({"identity":format!("phone:{handle}"),"participantId":encryption.id().to_string(),"participantPem":encryption.to_pem(),"signingId":signing.id().to_string(),"signingPem":signing.to_pem()});
    let phone = Phone {
        vm: env.get_java_vm().map_err(|_| ERROR)?,
        callback: env.new_global_ref(callback).map_err(|_| ERROR)?,
        encryption,
        signing,
        active: AtomicBool::new(true),
    };
    let mut all = sessions().lock().map_err(|_| ERROR)?;
    if all.len() >= 4 {
        return Err(ERROR);
    }
    all.insert(handle, Arc::new(phone));
    Ok(response.to_string())
}
pub(super) fn execute(input: &str, random: Vec<u8>) -> Result<String> {
    let request = super::store::Secret(serde_json::from_str(input).map_err(|_| ERROR)?);
    let v = &request.0;
    let handle: u64 = text(v, "identity")?
        .strip_prefix("phone:")
        .ok_or(ERROR)?
        .parse()
        .map_err(|_| ERROR)?;
    let op = text(v, "op")?;
    let phone = {
        let mut all = sessions().lock().map_err(|_| ERROR)?;
        if op == "phone_close" {
            if let Some(phone) = all.remove(&handle) {
                phone.active.store(false, Ordering::Release);
            }
            return Ok("{}".into());
        }
        all.get(&handle).cloned().ok_or(ERROR)?
    };
    match op {
        "store_catalog" => {
            super::index::execute(input, &*phone, &phone.encryption, &*phone, random)
        }
        op if op.starts_with("store_") => {
            super::store::execute_with(input, Some((&*phone, &phone.encryption)), random)
        }
        "entry_decrypt" | "metadata_decrypt" => {
            let decode = |field| {
                B64.decode(text(v, field)?)
                    .map(Zeroizing::new)
                    .map_err(|_| ERROR)
            };
            let primary = PrimaryRecord::from_bytes(&decode("primary")?).map_err(|_| ERROR)?;
            let grant = GrantRecord::from_bytes(&decode("grant")?).map_err(|_| ERROR)?;
            let entry = Entry::from_parts(primary, [grant]).map_err(|_| ERROR)?;
            let result = if op == "metadata_decrypt" {
                let participant = text(v, "participantId")?.parse().map_err(|_| ERROR)?;
                let payload = futures::executor::block_on(kagitaba_cxf::ParticipantMetadata::open(
                    &entry,
                    participant,
                    &phone.encryption,
                    &*phone,
                ))
                .map_err(|_| ERROR)?;
                let bytes = payload.to_json().map_err(|_| ERROR)?;
                json!({"payload":std::str::from_utf8(&bytes).map_err(|_| ERROR)?,"name":payload.name().unwrap_or("")})
            } else {
                let payload = futures::executor::block_on(kagitaba_cxf::Payload::open(
                    &entry,
                    &phone.encryption,
                    &*phone,
                ))
                .map_err(|_| ERROR)?;
                let bytes = payload.to_json().map_err(|_| ERROR)?;
                json!({"payload":std::str::from_utf8(&bytes).map_err(|_| ERROR)?})
            };
            let result = super::store::Secret(result);
            serde_json::to_string(&result.0).map_err(|_| ERROR)
        }
        _ => Err(ERROR),
    }
}

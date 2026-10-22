//! Android transport only; the shared Rust PIV adapter owns protocol and crypto.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JObject, JValue},
};
use kagitaba_core::{
    crypto::{Ciphertext, ContentKey, PublicKey, WrappedKey},
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use kagitaba_cxf::Payload;
use kagitaba_device::{
    KeyPolicy, PinPolicy, Piv, Policies, PrivateOperation, Session, Slots, TouchPolicy, Transport,
};
use kagitaba_store::Signer;
use rand_core::{TryCryptoRng, TryRng};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
struct AndroidTransport {
    vm: JavaVM,
    connection: GlobalRef,
}
impl Transport for AndroidTransport {
    fn exchange(&mut self, command: &[u8]) -> kagitaba_device::Result<Zeroizing<Vec<u8>>> {
        let result = (|| -> jni::errors::Result<_> {
            let mut env = self.vm.attach_current_thread()?;
            let request = env.byte_array_from_slice(command)?;
            let result = env.call_method(
                self.connection.as_obj(),
                "exchange",
                "([B)[B",
                &[JValue::Object(request.as_ref())],
            );
            // Never propagate/log Java transport exceptions across the Rust API.
            if env.exception_check()? {
                env.exception_clear()?;
            }
            env.set_byte_array_region(&request, 0, &vec![0; command.len()])?;
            env.delete_local_ref(request)?;
            let response = JByteArray::from(result?.l()?);
            let bytes = env.convert_byte_array(&response)?;
            let len = env.get_array_length(&response)?;
            env.set_byte_array_region(&response, 0, &vec![0; len as usize])?;
            env.delete_local_ref(response)?;
            Ok(Zeroizing::new(bytes))
        })();
        result.map_err(|_| kagitaba_device::Error::Usb)
    }
}
struct Hardware(Session<AndroidTransport>);
impl Signer for Hardware {
    fn public_key(&self) -> &PublicKey {
        &self.0.signing
    }
    fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.0
            .sign(bytes)
            .map_err(|_| kagitaba_store::Error::Signing)
    }
}
static SESSIONS: OnceLock<Mutex<HashMap<u64, Arc<Hardware>>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
fn sessions() -> &'static Mutex<HashMap<u64, Arc<Hardware>>> {
    SESSIONS.get_or_init(Default::default)
}
fn err(_: impl std::fmt::Display) -> &'static str {
    "PIV operation failed. Reconnect your YubiKey and unlock again."
}
const TOKEN_OTHER_KEY: &str = "Sync token belongs to another key. Unlock with that key or enter a Git token in Connection settings.";
fn local_key_error(error: kagitaba_core::Error) -> &'static str {
    match error {
        kagitaba_core::Error::WrongRecipient => TOKEN_OTHER_KEY,
        other => err(other),
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("Invalid PIV request")
}
fn bytes(v: &Value, key: &str) -> Result<Zeroizing<Vec<u8>>> {
    B64.decode(text(v, key)?).map(Zeroizing::new).map_err(err)
}
pub(super) fn open(env: &mut JNIEnv<'_>, connection: JObject<'_>, input: &str) -> Result<String> {
    let request = super::store::Secret(serde_json::from_str(input).map_err(err)?);
    let v = &request.0;
    let transport = AndroidTransport {
        vm: env.get_java_vm().map_err(err)?,
        connection: env.new_global_ref(&connection).map_err(err)?,
    };
    let mut card = Piv::new(transport).map_err(err)?;
    if v["op"] == "inspect" {
        return detect(&mut card, v).map(|v| v.to_string());
    }
    if v["op"] == "inspect_slots" {
        let mut empty = Vec::new();
        let mut occupied = Vec::new();
        let mut policies = serde_json::Map::new();
        for slot in 0x82..=0x95 {
            match card.key_metadata(slot) {
                Err(kagitaba_device::Error::Status(0x6a88)) => empty.push(slot),
                Ok(metadata) => {
                    occupied.push(slot);
                    policies.insert(slot.to_string(), policy_json(metadata.policy));
                }
                Err(kagitaba_device::Error::Unsupported) => {}
                Err(e) => return Err(err(e)),
            }
        }
        return Ok(json!({"serial":card.serial_number().map_err(err)?.to_string(), "emptySlots":empty, "occupiedSlots":occupied,"policies":policies}).to_string());
    }
    let slot = |name| -> Result<u8> {
        u8::try_from(v[name].as_u64().ok_or("Invalid PIV slots")?).map_err(err)
    };
    let slots = Slots::new(slot("encryptionSlot")?, slot("signingSlot")?).map_err(err)?;
    let serial = card.serial_number().map_err(err)?.to_string();
    if v["op"] == "provision" {
        let defaults = Policies::default();
        let encryption_policy = requested_policy(v, "encryptionPolicy", defaults.encryption)?;
        let signing_policy = requested_policy(v, "signingPolicy", defaults.signing)?;
        if v["confirmed"].as_bool() != Some(true) {
            return Err("Confirm generation in the selected empty PIV slots.");
        }
        if v["serial"].as_str() != Some(&serial) {
            return Err("The YubiKey changed. Detect it again before generating keys.");
        }
        for slot in [slots.encryption(), slots.signing()] {
            if !matches!(
                card.public_key(slot),
                Err(kagitaba_device::Error::Status(0x6a88))
            ) {
                return Err(
                    "A selected PIV slot is occupied or cannot be verified empty. Nothing was changed.",
                );
            }
        }
        let key_text = text(v, "managementKey")?;
        if ![32, 48, 64].contains(&key_text.len())
            || !key_text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Management key must be 32, 48 or 64 hexadecimal characters.");
        }
        let key = Zeroizing::new(
            (0..key_text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&key_text[i..i + 2], 16).map_err(err))
                .collect::<Result<Vec<_>>>()?,
        );
        card.verify_pin(text(v, "pin")?).map_err(pin_error)?;
        card.authenticate_management(&key)
            .map_err(|_| "Management authentication failed. No keys were generated.")?;
        card.generate_empty_with_policy(slots.encryption(), encryption_policy).and_then(|_| card.generate_empty_with_policy(slots.signing(), signing_policy))
            .map_err(|_| "Provisioning stopped. A slot may now contain a generated key. Inspect the slots on your computer before trying again.")?;
    }
    // Recheck public keys on the connection actually receiving the PIN, before
    // any PIN attempt. Routing metadata alone is never authentication.
    for (name, slot) in [
        ("participantPem", slots.encryption()),
        ("signingPem", slots.signing()),
    ] {
        if let Some(pem) = v[name].as_str()
            && card.public_key(slot).map_err(err)? != PublicKey::from_pem(pem).map_err(err)?
        {
            return Err(
                "The connected YubiKey does not match the selected wallet participant. No PIN was sent.",
            );
        }
    }
    let mut session =
        Session::unlock_with_slots(card, text(v, "pin")?, slots).map_err(pin_error)?;
    let callback = env.new_global_ref(&connection).map_err(err)?;
    let vm = env.get_java_vm().map_err(err)?;
    session.set_observer(move |event| {
        let policy = match event {
            PrivateOperation::Finished => -1,
            PrivateOperation::Started(touch) => touch.map_or(0, |p| i32::from(p.code())),
        };
        if let Ok(mut env) = vm.attach_current_thread() {
            let _ = env.call_method(
                callback.as_obj(),
                "setTouchPending",
                "(I)V",
                &[JValue::Int(policy)],
            );
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
        }
    });
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    let response = json!({"identity": format!("piv:{handle}"), "participantId": session.encryption.id().to_string(),
        "participantPem": session.encryption.to_pem(), "signingId": session.signing.id().to_string(), "signingPem": session.signing.to_pem(),
        "encryptionPolicy":policy_json(session.encryption_policy), "signingPolicy":policy_json(session.signing_policy),
        "device": {"version":1,"serial":serial,"encryptionSlot":slots.encryption(),"signingSlot":slots.signing()}});
    let mut all = sessions().lock().map_err(err)?;
    if all.len() >= 4 {
        return Err("Too many PIV sessions");
    }
    all.insert(handle, Arc::new(Hardware(session)));
    Ok(response.to_string())
}
fn policy_json(policy: Option<KeyPolicy>) -> Value {
    policy.map_or(
        Value::Null,
        |p| json!({"pin":p.pin.code(), "touch":p.touch.code()}),
    )
}
fn requested_policy(v: &Value, name: &str, default: KeyPolicy) -> Result<KeyPolicy> {
    let Some(value) = v.get(name) else {
        return Ok(default);
    };
    let pin = match value["pin"].as_u64() {
        Some(1) => PinPolicy::Never,
        Some(2) => PinPolicy::Once,
        _ => return Err("Unsupported PIV policy selection."),
    };
    let touch = match value["touch"].as_u64() {
        Some(1) => TouchPolicy::Never,
        Some(2) => TouchPolicy::Always,
        Some(3) => TouchPolicy::Cached,
        _ => return Err("Unsupported PIV policy selection."),
    };
    Ok(KeyPolicy { pin, touch })
}
fn pin_error(e: kagitaba_device::Error) -> &'static str {
    match e {
        kagitaba_device::Error::Pin(0) | kagitaba_device::Error::Blocked => {
            "PIV PIN is blocked. Use your recovery procedure on your computer."
        }
        kagitaba_device::Error::Pin(1) => {
            "Incorrect PIV PIN. 1 attempt remains. No automatic retry."
        }
        kagitaba_device::Error::Pin(2) => {
            "Incorrect PIV PIN. 2 attempts remain. No automatic retry."
        }
        kagitaba_device::Error::Pin(_) => "Incorrect PIV PIN. No automatic retry.",
        kagitaba_device::Error::InvalidPin => "PIV PIN must contain 6–8 ASCII characters.",
        _ => {
            "Cannot open these PIV slots. Check the selected slots, PIV interface and YubiKey firmware (5.3+)."
        }
    }
}

fn detect<T: Transport>(card: &mut Piv<T>, request: &Value) -> Result<Value> {
    let candidates = request["candidates"]
        .as_array()
        .ok_or("Invalid PIV candidates")?;
    if candidates.len() > 1024 {
        return Err("Invalid PIV candidates");
    }
    let serial = card.serial_number().map_err(err)?.to_string();
    let mut keys: std::collections::BTreeMap<u8, Option<PublicKey>> =
        std::collections::BTreeMap::new();
    let mut read_key = |slot: u8| -> Result<Option<PublicKey>> {
        if !(0x82..=0x95).contains(&slot) {
            return Ok(None);
        }
        if let Some(key) = keys.get(&slot) {
            return Ok(key.clone());
        }
        let key = match card.public_key(slot) {
            Ok(key) => Some(key),
            Err(kagitaba_device::Error::Status(0x6a88) | kagitaba_device::Error::Unsupported) => {
                None
            }
            Err(e) => return Err(err(e)),
        };
        keys.insert(slot, key.clone());
        Ok(key)
    };
    let mut matches = Vec::new();
    for candidate in candidates {
        let encryption = PublicKey::from_pem(text(candidate, "participantPem")?).map_err(err)?;
        let signing = PublicKey::from_pem(text(candidate, "signingPem")?).map_err(err)?;
        let hint = &candidate["device"];
        let mut pair = None;
        if hint["serial"].as_str() == Some(&serial)
            && let (Some(enc), Some(sig)) = (
                hint["encryptionSlot"]
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok()),
                hint["signingSlot"]
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok()),
            )
            && Slots::new(enc, sig).is_ok()
            && read_key(enc)?.as_ref() == Some(&encryption)
            && read_key(sig)?.as_ref() == Some(&signing)
        {
            pair = Some((enc, sig));
        }
        // Older wallets may omit serial/slot hints. Compare the actual public
        // keys in supported slots, without guessing a PIN or changing the card.
        if pair.is_none() {
            let mut enc = None;
            let mut sig = None;
            for slot in 0x82..=0x95 {
                let key = read_key(slot)?;
                if key.as_ref() == Some(&encryption) {
                    enc = Some(slot);
                }
                if key.as_ref() == Some(&signing) {
                    sig = Some(slot);
                }
            }
            if let (Some(enc), Some(sig)) = (enc, sig)
                && enc != sig
            {
                pair = Some((enc, sig));
            }
        }
        if let Some((enc, sig)) = pair {
            matches.push(json!({"participantId": encryption.id().to_string(), "participantPem": encryption.to_pem(),
                "signingPem": signing.to_pem(), "name": candidate["name"].as_str().unwrap_or(""), "serial": serial,
                "encryptionSlot": enc, "signingSlot": sig}));
        }
    }
    for item in &mut matches {
        for (slot, policy) in [
            ("encryptionSlot", "encryptionPolicy"),
            ("signingSlot", "signingPolicy"),
        ] {
            item[policy] = policy_json(
                card.key_metadata(item[slot].as_u64().ok_or("Invalid PIV slots")? as u8)
                    .map_err(err)?
                    .policy,
            );
        }
    }
    Ok(json!({"matches":matches}))
}
pub(super) struct Random(pub(super) Zeroizing<Vec<u8>>, pub(super) usize);
impl TryRng for Random {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> std::io::Result<u32> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> std::io::Result<u64> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        let end = self
            .1
            .checked_add(dst.len())
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        dst.copy_from_slice(
            self.0
                .get(self.1..end)
                .ok_or(std::io::ErrorKind::UnexpectedEof)?,
        );
        self.0[self.1..end].fill(0);
        self.1 = end;
        Ok(())
    }
}
impl TryCryptoRng for Random {}
pub(super) fn execute(input: &str, random: Vec<u8>) -> Result<String> {
    let request = super::store::Secret(serde_json::from_str(input).map_err(err)?);
    let v = &request.0;
    let handle: u64 = text(v, "identity")?
        .strip_prefix("piv:")
        .ok_or("Invalid PIV session")?
        .parse()
        .map_err(err)?;
    let op = text(v, "op")?;
    let hardware = {
        let mut all = sessions().lock().map_err(err)?;
        if op == "piv_close" {
            all.remove(&handle);
            return Ok("{}".into());
        }
        all.get(&handle)
            .cloned()
            .ok_or("YubiKey session expired. Unlock again.")?
    };
    if op == "store_catalog" {
        return super::index::execute(input, &*hardware, &hardware.0.encryption, &hardware.0, random);
    }
    if op.starts_with("store_") {
        return super::store::execute_with(
            input,
            Some((&*hardware, &hardware.0.encryption)),
            random,
        );
    }
    let result = match op {
        "entry_decrypt" | "metadata_decrypt" => {
            let primary = PrimaryRecord::from_bytes(&bytes(v, "primary")?).map_err(err)?;
            let grant = GrantRecord::from_bytes(&bytes(v, "grant")?).map_err(err)?;
            let entry = Entry::from_parts(primary, [grant]).map_err(err)?;
            if op == "metadata_decrypt" {
                let participant = text(v, "participantId")?.parse().map_err(err)?;
                let payload = futures::executor::block_on(kagitaba_cxf::ParticipantMetadata::open(
                    &entry,
                    participant,
                    &hardware.0.encryption,
                    &hardware.0,
                ))
                .map_err(err)?;
                return serde_json::to_string(&json!({"payload":std::str::from_utf8(&payload.to_json().map_err(err)?).map_err(err)?, "name":payload.name().unwrap_or("")})).map_err(err);
            }
            let payload = futures::executor::block_on(Payload::open(
                &entry,
                &hardware.0.encryption,
                &hardware.0,
            ))
            .map_err(err)?;
            json!({"payload": std::str::from_utf8(&payload.to_json().map_err(err)?).map_err(err)?})
        }
        "local_encrypt" | "local_decrypt" => {
            let supplied = text(v, "context")?;
            if supplied.is_empty() || supplied.len() > 4096 {
                return Err("Invalid PIV context");
            }
            let context = format!("Kagitaba/Android/v1/PIV-local\0{supplied}");
            if op == "local_encrypt" {
                let plaintext = text(v, "plaintext")?;
                if plaintext.len() > 16384 {
                    return Err("Invalid PIV local secret");
                }
                let mut rng = Random(Zeroizing::new(random), 0);
                let key = ContentKey::generate(&mut rng).map_err(err)?;
                let sealed =
                    Ciphertext::seal(plaintext.as_bytes(), &key, context.as_bytes(), &mut rng)
                        .map_err(err)?;
                let wrapped =
                    WrappedKey::wrap(&key, &hardware.0.encryption, context.as_bytes(), &mut rng)
                        .map_err(err)?;
                let envelope = json!({"format":"kagitaba-android-piv-local-1", "wrapped":B64.encode(wrapped.as_bytes()), "sealed":B64.encode(sealed.as_bytes())});
                json!({"envelope": envelope.to_string()})
            } else {
                let envelope = text(v, "envelope")?;
                if envelope.len() > 32768 {
                    return Err("Invalid PIV local secret");
                }
                let envelope: Value = serde_json::from_str(envelope)
                    .map_err(|_| "Re-enter the Git token for your YubiKey participant.")?;
                if envelope["format"] != "kagitaba-android-piv-local-1" {
                    return Err("Invalid PIV local secret");
                }
                let wrapped = WrappedKey::from_bytes(&bytes(&envelope, "wrapped")?).map_err(err)?;
                let key = futures::executor::block_on(wrapped.unwrap(
                    &hardware.0.encryption,
                    context.as_bytes(),
                    &hardware.0,
                ))
                .map_err(local_key_error)?;
                let clear = Ciphertext::from_bytes(&bytes(&envelope, "sealed")?)
                    .map_err(err)?
                    .open(&key, context.as_bytes())
                    .map_err(err)?;
                json!({"plaintext": std::str::from_utf8(clear.as_bytes()).map_err(err)?})
            }
        }
        _ => return Err("Unsupported PIV operation"),
    };
    let result = super::store::Secret(result);
    serde_json::to_string(&result.0).map_err(err)
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn provisioning_policy_defaults_and_validation() {
        let default = Policies::default().encryption;
        assert_eq!(
            requested_policy(&json!({}), "policy", default).unwrap(),
            default
        );
        assert_eq!(
            requested_policy(&json!({"policy":{"pin":1,"touch":2}}), "policy", default).unwrap(),
            KeyPolicy {
                pin: PinPolicy::Never,
                touch: TouchPolicy::Always
            }
        );
        for value in [
            json!({"pin":3,"touch":2}),
            json!({"pin":0,"touch":2}),
            json!({"pin":2,"touch":0}),
            json!({"pin":2}),
            Value::Null,
        ] {
            assert!(requested_policy(&json!({"policy":value}), "policy", default).is_err());
        }
    }
}

#[cfg(test)]
mod local_token_tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use rand_core::SeedableRng;

    #[test]
    fn second_participant_token_mismatch_is_not_a_hardware_failure() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([31; 32]);
        let first = SoftwareIdentity::generate(&mut rng).unwrap();
        let second = SoftwareIdentity::generate(&mut rng).unwrap();
        let key = ContentKey::generate(&mut rng).unwrap();
        let context = b"synthetic sync token";
        let wrapped = WrappedKey::wrap(&key, &first.public_key(), context, &mut rng).unwrap();
        let result = futures::executor::block_on(wrapped.unwrap(&second.public_key(), context, &second))
            .map_err(local_key_error);
        assert!(matches!(result, Err(TOKEN_OTHER_KEY)));
        assert!(futures::executor::block_on(wrapped.unwrap(&first.public_key(), context, &first)).is_ok());
        assert_eq!(local_key_error(kagitaba_core::Error::KeyUnavailable), err("hardware"));
        assert_eq!(local_key_error(kagitaba_core::Error::Authentication), err("authentication"));
    }
}

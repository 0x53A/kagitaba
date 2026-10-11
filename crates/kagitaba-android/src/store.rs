//! Android filesystem boundary, reusing the native signed-history verifier.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use kagitaba_core::{
    crypto::PublicKey,
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use kagitaba_store::{Signer, Snapshot, Store};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    pkcs8::EncodePublicKey,
};
use serde_json::{Value, json};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, &'static str>;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("Missing request field")
}
fn error(_: impl std::fmt::Display) -> &'static str {
    "Invalid wallet request or credential encoding"
}
fn store_error(error: kagitaba_store::Error) -> &'static str {
    use kagitaba_store::Error;
    match error {
        Error::History => {
            "Unsupported wallet history. Update all clients to a version supporting signed merges."
        }
        Error::InvalidName => {
            "Participant name must be 1–128 characters without surrounding whitespace or control characters."
        }
        Error::Checkpoint => {
            "Wallet history does not include this device's trusted checkpoint. Fetch updates or resolve divergence on your computer; do not reset trust."
        }
        Error::UnrelatedHistory => "These wallets have different origins and cannot be merged.",
        Error::AmbiguousMergeBase => {
            "Wallet history has multiple merge bases. This app cannot resolve it automatically."
        }
        Error::Conflict => {
            "Wallet merge has conflicting entry or participant changes. No changes were accepted; resolve the conflict on your computer."
        }
        Error::Signature => {
            "Wallet signature is missing, invalid, or signed by an unauthorized participant. No changes were accepted."
        }
        Error::Invalid | Error::Core(_) => {
            "Wallet records are invalid, unsupported, or exceed limits. Update the app if a newer client wrote this wallet."
        }
        Error::Io => {
            "Wallet storage could not be read or written. Check available device storage and retry."
        }
        Error::DirtyWorktree => {
            "Wallet working files differ from signed history. Preserve a backup and repair the working copy before saving."
        }
        Error::WrongBranch => {
            "The wallet branch is not selected. Repair the repository before saving."
        }
        Error::WorktreeLocked => {
            "Another Git operation is using the wallet. Wait for it to finish and retry."
        }
        Error::Stale => {
            "Wallet changed during this operation. Reload and retry; no new update was accepted."
        }
        Error::Signing => {
            "The signing key refused this operation. Unlock the participant and retry."
        }
        Error::DestinationNotEmpty => {
            "The wallet destination is not empty. Open the existing wallet or choose an empty destination."
        }
    }
}

pub(super) struct Secret(pub(super) Value);
impl Drop for Secret {
    fn drop(&mut self) {
        fn clear(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}
struct Identity {
    signing: SigningKey,
    public: PublicKey,
    agreement: PublicKey,
}
struct SignerRef<'a>(&'a dyn Signer);
impl Signer for SignerRef<'_> {
    fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }
    fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.0.sign(bytes)
    }
}
impl Identity {
    fn read(v: &Value) -> Result<Self> {
        let bytes = Zeroizing::new(B64.decode(text(v, "identity")?).map_err(error)?);
        if bytes.len() != 68 || &bytes[..4] != b"KBI1" {
            return Err("Invalid identity");
        }
        let sign = p256::SecretKey::from_slice(&bytes[36..]).map_err(error)?;
        let enc = p256::SecretKey::from_slice(&bytes[4..36]).map_err(error)?;
        let public = PublicKey::from_der(
            sign.public_key()
                .to_public_key_der()
                .map_err(error)?
                .as_bytes(),
        )
        .map_err(error)?;
        let agreement = PublicKey::from_der(
            enc.public_key()
                .to_public_key_der()
                .map_err(error)?
                .as_bytes(),
        )
        .map_err(error)?;
        Ok(Self {
            signing: SigningKey::from(sign),
            public,
            agreement,
        })
    }
}
impl Signer for Identity {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        let signature: Signature = self.signing.sign(bytes);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
pub(super) fn execute(input: &str, random: Vec<u8>) -> Result<String> {
    execute_with(input, None, random)
}
pub(super) fn execute_with(
    input: &str,
    hardware: Option<(&dyn Signer, &PublicKey)>,
    random: Vec<u8>,
) -> Result<String> {
    let mut rng = super::piv::Random(Zeroizing::new(random), 0);
    let request = Secret(serde_json::from_str(input).map_err(error)?);
    let v = &request.0;
    let path = Path::new(text(v, "path")?);
    let op = text(v, "op")?;
    let mut store = if op == "store_create" {
        let identity;
        let (signer, agreement) = if let Some(pair) = hardware {
            pair
        } else {
            identity = Identity::read(v)?;
            (&identity as &dyn Signer, &identity.agreement)
        };
        let mut snapshot =
            Snapshot::empty(agreement.clone(), signer.public_key().clone()).map_err(store_error)?;
        if let Some(device) = v.get("device") {
            let hint = kagitaba_store::DeviceHint::from_json(&serde_json::to_vec(device).map_err(error)?).map_err(store_error)?;
            snapshot.devices.insert(agreement.id(), hint);
        }
        Store::create(path, snapshot, &SignerRef(signer)).map_err(store_error)?
    } else {
        let root = if v.get("root").is_some() {
            PublicKey::from_pem(text(v, "root")?).map_err(error)?
        } else if op == "store_connect" {
            // Explicit HTTPS first-use bootstrap; verification still checks the
            // entire chain and membership of the genesis signer.
            Store::inspect_root(path).map_err(store_error)?
        } else {
            return Err("Wallet trust is missing");
        };
        let checkpoint = v
            .get("checkpoint")
            .map(|s| {
                kagitaba_store::parse_oid(s.as_str().ok_or("Invalid checkpoint")?).map_err(error)
            })
            .transpose()?;
        if op != "store_connect" && checkpoint.is_none() {
            return Err("Wallet checkpoint is missing");
        }
        Store::open(path, root, checkpoint).map_err(store_error)?
    };
    match op {
        "store_create" | "store_connect" | "store_open" => {}
        "store_accept" => store
            .accept(kagitaba_store::parse_oid(text(v, "candidate")?).map_err(error)?)
            .map_err(store_error)?,
        "store_export" => {
            return String::from_utf8(store.export_transfer().map_err(store_error)?).map_err(error);
        }
        "store_import" => store
            .import_transfer(text(v, "transfer")?.as_bytes())
            .map_err(store_error)?,
        "store_name_participant" => {
            let software;
            let signer = if let Some((signer, _)) = hardware {
                signer
            } else {
                software = Identity::read(v)?;
                &software
            };
            let id = text(v, "participantId")?.parse().map_err(error)?;
            if !store.snapshot.wallet.participants().contains_key(&id) {
                return Err("Unknown wallet participant");
            }
            let mut next = store.snapshot.clone();
            let entry = encrypted_entry(v)?;
            let entry_id = entry.primary().entry_id();
            if next.metadata.get(&id).is_some_and(|old| *old != entry_id)
                || (next.wallet.entries().contains_key(&entry_id) && next.metadata.get(&id) != Some(&entry_id))
                || entry.grants().keys().ne(next.wallet.participants().keys()) { return Err("Invalid wallet request or credential encoding"); }
            next.names.remove(&id);
            next.wallet = next.wallet.with_entry(entry).map_err(error)?;
            next.metadata.insert(id, entry_id);
            next.prune_legacy(&mut rng).map_err(store_error)?;
            store
                .save(next, &SignerRef(signer), "Name participant")
                .map_err(store_error)?;
        }
        "store_save" | "store_delete" => {
            let software;
            let signer = if let Some((signer, _)) = hardware {
                signer
            } else {
                software = Identity::read(v)?;
                &software
            };
            let id = text(v, "entryId")?.parse().map_err(error)?;
            if store.snapshot.is_metadata(&id) { return Err("Invalid wallet request or credential encoding"); }
            let wallet = if op == "store_delete" {
                store.snapshot.wallet.without_entry(id).map_err(error)?
            } else {
                let primary =
                    PrimaryRecord::from_bytes(&B64.decode(text(v, "primary")?).map_err(error)?)
                        .map_err(error)?;
                if primary.entry_id() != id {
                    return Err("Entry identity mismatch");
                }
                let grants = v["grants"]
                    .as_object()
                    .ok_or("Missing grants")?
                    .values()
                    .map(|value| {
                        GrantRecord::from_bytes(
                            &B64.decode(value.as_str().ok_or("Invalid grant")?)
                                .map_err(error)?,
                        )
                        .map_err(error)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let entry = Entry::from_parts(primary, grants).map_err(error)?;
                store.snapshot.wallet.with_entry(entry).map_err(error)?
            };
            let mut next = store.snapshot.clone();
            next.wallet = wallet;
            next.prune_legacy(&mut rng).map_err(store_error)?;
            store
                .save(
                    next,
                    &SignerRef(signer),
                    if op == "store_save" {
                        "Save Android credential"
                    } else {
                        "Delete Android credential"
                    },
                )
                .map_err(store_error)?;
        }
        _ => return Err("Unknown wallet operation"),
    }
    let entries: Vec<_> = store.snapshot.wallet.entries().iter().map(|(id, entry)| {
        let grants: serde_json::Map<String, Value> = entry.grants().iter().map(|(id, grant)| (id.to_string(), json!(B64.encode(grant.to_bytes())))).collect();
        json!({"id": id.to_string(), "primary": B64.encode(entry.primary().to_bytes()), "grants": grants})
    }).collect();
    let participants: serde_json::Map<String, Value> = store
        .snapshot
        .wallet
        .participants()
        .iter()
        .map(|(id, key)| (id.to_string(), json!(key.to_pem())))
        .collect();
    let signers: Vec<_> = store
        .snapshot
        .signers
        .keys()
        .map(ToString::to_string)
        .collect();
    let metadata: serde_json::Map<String, Value> = store
        .snapshot
        .metadata
        .iter()
        .map(|(id, entry)| (id.to_string(), json!(entry.to_string())))
        .collect();
    let devices: serde_json::Map<String, Value> = store.snapshot.devices.iter().map(|(id, hint)| {
        (id.to_string(), json!({"serial": hint.serial, "encryptionSlot": hint.encryption_slot, "signingSlot": hint.signing_slot}))
    }).collect();
    let signing_keys: serde_json::Map<String, Value> = store.snapshot.signers.iter()
        .map(|(id, key)| (id.to_string(), json!(key.to_pem()))).collect();
    serde_json::to_string(
        &json!({"root": store.root_signer.to_pem(), "head": store.head.to_string(),
        "participants": participants, "participantMetadata": metadata, "signers": signers, "signingKeys": signing_keys, "devices": devices, "entries": entries}),
    )
    .map_err(error)
}

fn encrypted_entry(v: &Value) -> Result<Entry> {
    let primary = PrimaryRecord::from_bytes(&B64.decode(text(v, "primary")?).map_err(error)?).map_err(error)?;
    let grants = v["grants"].as_object().ok_or("Missing grants")?.iter().map(|(id, value)| {
        let grant = GrantRecord::from_bytes(&B64.decode(value.as_str().ok_or("Invalid grant")?).map_err(error)?).map_err(error)?;
        if grant.recipient().to_string() != *id { return Err("Invalid grant"); }
        Ok(grant)
    }).collect::<Result<Vec<_>>>()?;
    Entry::from_parts(primary, grants).map_err(error)
}

#[cfg(test)]
mod error_tests {
    use super::*;
    #[test]
    fn history_conflict_signature_and_io_are_distinct_fixed_diagnostics() {
        use kagitaba_store::Error;
        let messages = [
            Error::History,
            Error::Checkpoint,
            Error::Conflict,
            Error::Signature,
            Error::Io,
        ]
        .map(store_error);
        assert_eq!(
            messages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            messages.len()
        );
        assert!(messages[0].contains("signed merges"));
        assert!(messages[1].contains("trusted checkpoint"));
        assert!(messages[2].contains("conflicting entry or participant"));
        assert!(messages[3].contains("signature"));
        assert!(messages[4].contains("storage"));
    }
}

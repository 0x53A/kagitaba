//! Native WebAuthn endpoint. The transport bridge has no credential semantics.
use crate::gateway::Permit;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use kagitaba_core::{
    EntryId,
    crypto::{KeyAgreement, PublicKey},
};
use kagitaba_cxf::Payload;
use kagitaba_store::Snapshot;
use rand::TryRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "Invalid or unsupported passkey request";
#[derive(Clone)]
pub struct Request {
    pub origin: String,
    pub rp_id: String,
    pub create: bool,
    pub input: Value,
}
pub struct Account {
    pub entry: EntryId,
    pub credential: String,
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
}
struct Secret(Value);
impl Drop for Secret {
    fn drop(&mut self) {
        crate::gateway::wipe(&mut self.0);
    }
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(INVALID)
}
fn binary(value: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    let bytes = B64.decode(value).map_err(|_| INVALID)?;
    if !(min..=max).contains(&bytes.len()) {
        return Err(INVALID);
    }
    Ok(bytes)
}
impl Request {
    pub fn parse(origin: &str, kind: &str, input: &Value) -> Result<Self> {
        if !input.is_object() || !["create", "get"].contains(&kind) {
            return Err(INVALID);
        }
        let site = url::Url::parse(origin).map_err(|_| INVALID)?;
        let host = site.domain().ok_or(INVALID)?;
        let create = kind == "create";
        let rp = if create {
            input["rp"].get("id")
        } else {
            input.get("rpId")
        };
        let rp = match rp {
            Some(v) => v.as_str().ok_or(INVALID)?,
            None => host,
        };
        if rp.len() > 253
            || rp != rp.to_ascii_lowercase()
            || rp.ends_with('.')
            || psl::domain_str(rp).is_none()
            || !(host == rp
                || host
                    .strip_suffix(rp)
                    .is_some_and(|prefix| prefix.ends_with('.')))
            || url::Url::parse(&format!("https://{rp}"))
                .map_err(|_| INVALID)?
                .domain()
                != Some(rp)
        {
            return Err(INVALID);
        }
        binary(string(input, "challenge")?, 16, 1024)?;
        let uv = if create {
            input["authenticatorSelection"].get("userVerification")
        } else {
            input.get("userVerification")
        };
        if let Some(uv) = uv
            && !["required", "preferred", "discouraged"].contains(&uv.as_str().ok_or(INVALID)?)
        {
            return Err(INVALID);
        }
        if let Some(extensions) = input.get("extensions") {
            let extensions = extensions.as_object().ok_or(INVALID)?;
            if extensions.keys().any(|k| k != "credProps")
                || extensions.get("credProps").is_some_and(|v| !v.is_boolean())
            {
                return Err(INVALID);
            }
        }
        for name in ["allowCredentials", "excludeCredentials"] {
            if let Some(list) = input.get(name) {
                let list = list.as_array().ok_or(INVALID)?;
                if list.len() > 128 {
                    return Err(INVALID);
                }
                for descriptor in list {
                    if descriptor["type"] != "public-key" {
                        return Err(INVALID);
                    }
                    binary(string(descriptor, "id")?, 1, 1024)?;
                }
            }
        }
        if create {
            if input["authenticatorSelection"]["authenticatorAttachment"] == "platform"
                || input["attestation"] == "enterprise"
            {
                return Err(INVALID);
            }
            if !input["pubKeyCredParams"]
                .as_array()
                .ok_or(INVALID)?
                .iter()
                .any(|p| p["type"] == "public-key" && p["alg"] == -7)
            {
                return Err(INVALID);
            }
            binary(string(&input["user"], "id")?, 1, 64)?;
            for (object, key) in [
                (&input["user"], "name"),
                (&input["user"], "displayName"),
                (&input["rp"], "name"),
            ] {
                if string(object, key)?.len() > 1024 || string(object, key)?.chars().count() > 256 {
                    return Err(INVALID);
                }
            }
        }
        Ok(Self {
            origin: origin.into(),
            rp_id: rp.into(),
            create,
            input: input.clone(),
        })
    }
    fn listed(&self, field: &str, id: &str) -> bool {
        self.input[field]
            .as_array()
            .is_some_and(|list| list.iter().any(|c| c["id"] == id))
    }
    fn allows(&self, credential: &Value) -> bool {
        credential["type"] == "passkey"
            && credential["rpId"] == self.rp_id
            && credential["credentialId"].as_str().is_some_and(|id| {
                binary(id, 1, 1024).is_ok()
                    && (self.create
                        || self.input["allowCredentials"]
                            .as_array()
                            .is_none_or(|a| a.is_empty())
                        || self.listed("allowCredentials", id))
            })
            && credential["userHandle"]
                .as_str()
                .is_some_and(|h| binary(h, 1, 64).is_ok())
    }
    fn client_data(&self) -> String {
        B64.encode(json!({"type":if self.create {"webauthn.create"}else{"webauthn.get"},"origin":self.origin,
            "challenge":self.input["challenge"],"crossOrigin":false}).to_string())
    }
}
async fn crypto(value: Value) -> Result<Secret> {
    let request = Secret(value);
    let text = Zeroizing::new(serde_json::to_string(&request.0).map_err(|_| INVALID)?);
    let mut random = vec![0; 4096];
    rand::rngs::SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| INVALID)?;
    let response = Zeroizing::new(
        kagitaba_browser::execute(&text, random)
            .await
            .map_err(|_| INVALID)?,
    );
    Ok(Secret(
        serde_json::from_str(&response).map_err(|_| INVALID)?,
    ))
}
async fn opened(
    entry: &kagitaba_core::wallet::Entry,
    public: &PublicKey,
    agreement: &impl KeyAgreement,
) -> Result<Secret> {
    let payload = Payload::open(entry, public, agreement)
        .await
        .map_err(|_| INVALID)?;
    Ok(Secret(
        serde_json::from_slice(&payload.to_json().map_err(|_| INVALID)?).map_err(|_| INVALID)?,
    ))
}
pub async fn accounts(
    snapshot: &Snapshot,
    public: &PublicKey,
    agreement: &impl KeyAgreement,
    request: &Request,
    permit: &Permit,
) -> Result<Vec<Account>> {
    accounts_with_index(snapshot, public, agreement, request, permit, None).await
}
pub async fn accounts_with_index(
    snapshot: &Snapshot,
    public: &PublicKey,
    agreement: &impl KeyAgreement,
    request: &Request,
    permit: &Permit,
    index: Option<&kagitaba_store::index::Index>,
) -> Result<Vec<Account>> {
    let index = index.filter(|index| index.is_current(snapshot, public.id()));
    let mut accounts = vec![];
    for (id, entry) in snapshot.wallet.entries() {
        permit.check()?;
        if snapshot.is_metadata(id) || !entry.grants().contains_key(&public.id()) {
            continue;
        }
        if let Some(index) = index
            && !index.rows().get(id).is_some_and(|row| row.passkey && row.scopes.contains(&request.rp_id))
        {
            continue;
        }
        let payload = opened(entry, public, agreement).await?;
        permit.check()?;
        if payload.0["kind"] != "item" {
            continue;
        }
        let entity = &payload.0["entity"];
        for credential in entity["credentials"].as_array().ok_or(INVALID)? {
            if !request.allows(credential) {
                continue;
            }
            if crypto(with_backup_flags(json!({"op":"passkey_validate","privateKey":string(credential,"key")?}), credential))
                .await
                .is_err()
            {
                continue;
            }
            accounts.push(Account {
                entry: *id,
                credential: string(credential, "credentialId")?.into(),
                title: Zeroizing::new(entity["title"].as_str().unwrap_or("Passkey").into()),
                username: Zeroizing::new(credential["username"].as_str().unwrap_or("").into()),
            });
        }
    }
    permit.check()?;
    Ok(accounts)
}
/// Only the worker calls this after fresh PIN verification and native approval.
pub async fn assertion(
    snapshot: &Snapshot,
    public: &PublicKey,
    agreement: &impl KeyAgreement,
    request: &Request,
    selected: (EntryId, &str),
    permit: &Permit,
) -> Result<Zeroizing<String>> {
    if request.create || snapshot.is_metadata(&selected.0) {
        return Err(INVALID);
    }
    permit.check()?;
    let payload = opened(
        snapshot.wallet.entries().get(&selected.0).ok_or(INVALID)?,
        public,
        agreement,
    )
    .await?;
    permit.check()?;
    let credential = payload.0["entity"]["credentials"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .find(|c| request.allows(c) && c["credentialId"] == selected.1)
        .ok_or(INVALID)?;
    let client_data = request.client_data();
    let signed=crypto(with_backup_flags(json!({"op":"passkey_assert","privateKey":string(credential,"key")?,"rpId":request.rp_id,"clientDataJSON":client_data,"uv":true}), credential)).await?;
    permit.check()?;
    Ok(Zeroizing::new(json!({"version":1,"credential":{"id":selected.1,"response":{"clientDataJSON":client_data,
        "authenticatorData":signed.0["authenticatorData"],"signature":signed.0["signature"],"userHandle":credential["userHandle"]},"extensions":{}}}).to_string()))
}
/// Prepared registration: the worker MUST durably sign/save before sending response.
pub async fn registration(
    snapshot: &Snapshot,
    public: &PublicKey,
    agreement: &impl KeyAgreement,
    request: &Request,
    permit: &Permit,
) -> Result<(Snapshot, Zeroizing<String>)> {
    if !request.create {
        return Err(INVALID);
    }
    let existing = accounts(snapshot, public, agreement, request, permit).await?;
    if existing
        .iter()
        .any(|a| request.listed("excludeCredentials", &a.credential))
    {
        return Err("A matching passkey already exists");
    }
    let client_data = request.client_data();
    let generated=crypto(json!({"op":"passkey_create","rpId":request.rp_id,"userHandle":request.input["user"]["id"],"clientDataJSON":client_data,"uv":true})).await?;
    permit.check()?;
    let mut id = [0; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut id)
        .map_err(|_| INVALID)?;
    let entry_id = EntryId::from_bytes(id);
    if snapshot.wallet.entries().contains_key(&entry_id) {
        return Err(INVALID);
    }
    let entity = Secret(
        json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item",
        "entity":{"id":B64.encode(id),"title":format!("{} — {}",request.rp_id,string(&request.input["user"],"name")?),
            "credentials":[{"type":"passkey","credentialId":generated.0["credentialId"],"rpId":request.rp_id,
                "userHandle":request.input["user"]["id"],"username":request.input["user"]["name"],"userDisplayName":request.input["user"]["displayName"],"key":generated.0["privateKey"]}],
            "scope":{"urls":[request.origin],"androidApps":[]}}}),
    );
    let raw = Zeroizing::new(serde_json::to_vec(&entity.0).map_err(|_| INVALID)?);
    let payload = Payload::from_json(entry_id, &raw).map_err(|_| INVALID)?;
    let entry = payload
        .seal(std::slice::from_ref(public), &mut rand::rngs::SysRng)
        .map_err(|_| INVALID)?;
    let mut next = snapshot.clone();
    next.wallet = next.wallet.with_entry(entry).map_err(|_| INVALID)?;
    let extensions = if request.input["extensions"]["credProps"] == true {
        json!({"credProps":{"rk":true}})
    } else {
        json!({})
    };
    let response=Zeroizing::new(json!({"version":1,"credential":{"id":generated.0["credentialId"],"response":{
        "clientDataJSON":client_data,"authenticatorData":generated.0["authenticatorData"],"attestationObject":generated.0["attestationObject"],"publicKey":generated.0["publicKey"]},"extensions":extensions}}).to_string());
    permit.check()?;
    Ok((next, response))
}

// Forward presence exactly, including malformed/null values for the shared validator.
fn with_backup_flags(mut request: Value, credential: &Value) -> Value {
    request.as_object_mut().expect("constructed request object").remove("kagitabaBackupFlags");
    if let Some(flags) = credential.get("kagitabaBackupFlags") {
        request["kagitabaBackupFlags"] = flags.clone();
    }
    request
}


#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use kagitaba_core::crypto::SoftwareIdentity;
    use p256::{
        ecdsa::{Signature, VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };
    use sha2::{Digest, Sha256};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    fn permit() -> Permit {
        Permit {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(90),
        }
    }
    fn input() -> Value {
        json!({"challenge":B64.encode([7;32]),"rp":{"id":"example.com","name":"Example"},"user":{"id":B64.encode([4;16]),"name":"synthetic","displayName":"Synthetic"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"extensions":{"credProps":true}})
    }
    #[test]
    fn current_index_filters_unrelated_entries_but_never_authorizes_or_trusts_stale_rows() {
        use kagitaba_core::crypto::{AgreementRequest, AgreementSecret};
        struct Deny(kagitaba_core::KeyId, std::cell::Cell<usize>);
        impl KeyAgreement for Deny {
            fn key_id(&self) -> kagitaba_core::KeyId { self.0 }
            async fn agree(&self, _: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
                self.1.set(self.1.get()+1);
                Err(kagitaba_core::Error::KeyUnavailable)
            }
        }
        block_on(async {
            let identity = SoftwareIdentity::from_bytes(&[9;32]).unwrap();
            let public = identity.public_key();
            let snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
            let permission = permit();
            let create = Request::parse("https://example.com", "create", &input()).unwrap();
            let (mut snapshot, _) = registration(&snapshot, &public, &identity, &create, &permission).await.unwrap();
            let index = kagitaba_store::index::Index::refresh(&snapshot, &public, &identity, None).await.unwrap();
            let deny = Deny(public.id(), std::cell::Cell::new(0));
            let get = Request::parse("https://other.com", "get", &json!({"challenge":B64.encode([7;32]),"rpId":"other.com"})).unwrap();
            assert!(accounts_with_index(&snapshot, &public, &deny, &get, &permission, Some(&index)).await.unwrap().is_empty());
            assert_eq!(deny.1.get(), 0);
            let matching = Request::parse("https://example.com", "get", &json!({"challenge":B64.encode([7;32]),"rpId":"example.com"})).unwrap();
            assert!(accounts_with_index(&snapshot, &public, &deny, &matching, &permission, Some(&index)).await.is_err());
            assert_eq!(deny.1.get(), 1); // Matching hint still requires actual decryption.
            let id = EntryId::from_bytes([42;16]);
            let payload = Payload::new(id, kagitaba_cxf::PayloadKind::Item, &serde_json::to_vec(&json!({"id":B64.encode(id.as_bytes()),"title":"Other","credentials":[]})).unwrap()).unwrap();
            snapshot.wallet = snapshot.wallet.with_entry(payload.seal(std::slice::from_ref(&public), &mut rand::rngs::SysRng).unwrap()).unwrap();
            assert!(accounts_with_index(&snapshot, &public, &deny, &get, &permission, Some(&index)).await.is_err());
            assert_eq!(deny.1.get(), 2); // Stale filter is ignored, never hides newly accessible entries.
        });
    }
    #[test]
    fn rp_and_options_fail_closed() {
        let mut value = input();
        assert!(Request::parse("https://login.example.com", "create", &value).is_ok());
        for rp in [
            "com",
            "evil.com",
            "example.com.evil.com",
            "github.io",
            "EXAMPLE.COM",
            "example.com.",
        ] {
            value["rp"]["id"] = json!(rp);
            assert!(Request::parse("https://login.example.com", "create", &value).is_err());
        }
        value = input();
        value["extensions"] = json!({"prf":{}});
        assert!(Request::parse("https://example.com", "create", &value).is_err());
        value = input();
        value["challenge"] = json!("AA");
        assert!(Request::parse("https://example.com", "create", &value).is_err());
    }
    #[test]
    fn encrypted_registration_and_scoped_zero_counter_assertion() {
        block_on(async {
            let identity = SoftwareIdentity::from_bytes(&[1; 32]).unwrap();
            let public = identity.public_key();
            let snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
            let permit = permit();
            let request = Request::parse("https://example.com", "create", &input()).unwrap();
            let (next, response) = registration(&snapshot, &public, &identity, &request, &permit)
                .await
                .unwrap();
            assert!(snapshot.wallet.entries().is_empty());
            let response: Value = serde_json::from_str(&response).unwrap();
            assert!(!response.to_string().contains("privateKey"));
            let id = response["credential"]["id"].as_str().unwrap();
            let get=Request::parse("https://example.com","get",&json!({"challenge":B64.encode([8;32]),"rpId":"example.com","allowCredentials":[{"type":"public-key","id":id}]})).unwrap();
            let list = accounts(&next, &public, &identity, &get, &permit)
                .await
                .unwrap();
            assert_eq!(list.len(), 1);
            let signed = assertion(
                &next,
                &public,
                &identity,
                &get,
                (list[0].entry, id),
                &permit,
            )
            .await
            .unwrap();
            let signed: Value = serde_json::from_str(&signed).unwrap();
            let r = &signed["credential"]["response"];
            let auth = B64
                .decode(r["authenticatorData"].as_str().unwrap())
                .unwrap();
            assert_eq!(&auth[..32], &Sha256::digest(b"example.com")[..]);
            assert_eq!(auth[32] & 5, 5);
            assert_eq!(&auth[33..37], &[0; 4]);
            let client = B64.decode(r["clientDataJSON"].as_str().unwrap()).unwrap();
            let mut message = auth;
            message.extend(Sha256::digest(&client));
            let key = VerifyingKey::from_public_key_der(
                &B64.decode(
                    response["credential"]["response"]["publicKey"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            let signature =
                Signature::from_der(&B64.decode(r["signature"].as_str().unwrap()).unwrap())
                    .unwrap();
            key.verify(&message, &signature).unwrap();
            let mut excluded = input();
            excluded["excludeCredentials"] = json!([{"type":"public-key","id":id}]);
            let excluded = Request::parse("https://example.com", "create", &excluded).unwrap();
            assert!(
                registration(&next, &public, &identity, &excluded, &permit)
                    .await
                    .is_err()
            );
            let wrong = Request::parse(
                "https://elsewhere.com",
                "get",
                &json!({"challenge":B64.encode([8;32])}),
            )
            .unwrap();
            assert!(
                assertion(
                    &next,
                    &public,
                    &identity,
                    &wrong,
                    (list[0].entry, id),
                    &permit
                )
                .await
                .is_err()
            );
            permit.cancelled.store(true, Ordering::Release);
            assert!(
                assertion(
                    &next,
                    &public,
                    &identity,
                    &get,
                    (list[0].entry, id),
                    &permit
                )
                .await
                .is_err()
            );
        });
    }
}


#[test]
fn backup_flags_are_owned_by_credential_not_request() {
    let attack=json!({"kagitabaBackupFlags":{"eligible":false,"state":false}});
    assert_eq!(with_backup_flags(attack.clone(),&json!({})),json!({}));
    let stored=json!({"kagitabaBackupFlags":{"eligible":true,"state":true}});
    assert_eq!(with_backup_flags(attack.clone(),&stored),stored);
    assert_eq!(with_backup_flags(attack,&json!({"kagitabaBackupFlags":null})),json!({"kagitabaBackupFlags":null}));
}

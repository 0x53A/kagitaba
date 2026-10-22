//! Verified, participant-private catalogue. Returned summaries never authorize use.
use super::store::{Identity, Secret};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use kagitaba_core::crypto::{KeyAgreement, PublicKey, SoftwareIdentity};
use kagitaba_store::{
    Signer, Store,
    index::{CollectionNode, Index},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
fn error(_: impl std::fmt::Display) -> &'static str {
    "Could not load or save the participant index. Unlock and retry."
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("Missing index request field")
}

pub(super) fn software(input: &str, random: Vec<u8>) -> Result<String> {
    let request = Secret(serde_json::from_str(input).map_err(error)?);
    let signer = Identity::read(&request.0)?;
    let bytes = Zeroizing::new(B64.decode(text(&request.0, "identity")?).map_err(error)?);
    let backend =
        SoftwareIdentity::from_bytes(bytes[4..36].try_into().map_err(error)?).map_err(error)?;
    execute(input, &signer, &backend.public_key(), &backend, random)
}
pub(super) fn execute(
    input: &str,
    signer: &impl Signer,
    recipient: &PublicKey,
    backend: &impl KeyAgreement,
    random: Vec<u8>,
) -> Result<String> {
    let request = Secret(serde_json::from_str(input).map_err(error)?);
    let v = &request.0;
    let root = PublicKey::from_pem(text(v, "root")?).map_err(error)?;
    let checkpoint = kagitaba_store::parse_oid(text(v, "checkpoint")?).map_err(error)?;
    let mut store = Store::open(
        std::path::Path::new(text(v, "path")?),
        root,
        Some(checkpoint),
    )
    .map_err(error)?;
    let (index, written) = futures::executor::block_on(refresh(
        &mut store,
        signer,
        recipient,
        backend,
        &mut super::piv::Random(Zeroizing::new(random), 0),
    ))?;
    let rows: Vec<_> = index.rows().iter().map(|(id,row)| json!({
        "id":id.to_string(), "title":row.title, "kind":if row.kind==kagitaba_cxf::PayloadKind::Item {"item"} else {"collection"},
        "usernames":row.usernames, "scopes":row.scopes, "password":row.password, "totp":row.totp, "passkey":row.passkey,
        "collection":row.collection.as_ref().map(tree)
    })).collect();
    let response = Secret(
        json!({"root":store.root_signer.to_pem(),"head":store.head.to_string(),"written":written,"rows":rows}),
    );
    serde_json::to_string(&response.0).map_err(error)
}
fn tree(node: &CollectionNode) -> Value {
    json!({"id":B64.encode(&node.id),"title":node.title,"entries":node.entries.iter().map(ToString::to_string).collect::<Vec<_>>(),"unresolved":node.unresolved_links,"children":node.children.iter().map(tree).collect::<Vec<_>>()})
}
async fn refresh(
    store: &mut Store,
    signer: &impl Signer,
    recipient: &PublicKey,
    backend: &impl KeyAgreement,
    rng: &mut impl rand_core::TryCryptoRng,
) -> Result<(Index, bool)> {
    let mut next = store.snapshot.clone();
    let key = match next.provision_index_key(recipient, rng).map_err(error)? {
        Some(key) => key,
        None => next
            .open_index_key(recipient, backend)
            .await
            .map_err(error)?,
    };
    let previous = next
        .indexes
        .get(&recipient.id())
        .and_then(|bytes| Index::open(bytes, &key, recipient.id()).ok());
    let index = match previous {
        Some(index) if index.is_current(&next, recipient.id()) => index,
        previous => Index::refresh_for_listing(&next, recipient, backend, previous.as_ref())
            .await
            .map_err(error)?,
    };
    let Ok(encoded) = index.seal(&key, recipient.id()) else {
        // The authoritative payloads can exceed disposable-cache bounds. Return
        // all listing hints without publishing a partial cache or a new key.
        return Ok((index, false));
    };
    next.indexes.insert(recipient.id(), encoded);
    let written =
        next.index_keys != store.snapshot.index_keys || next.indexes != store.snapshot.indexes;
    if written {
        store
            .save(next, signer, "Refresh participant index")
            .map_err(error)?;
    }
    Ok((index, written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::{
        EntryId,
        crypto::{AgreementRequest, AgreementSecret},
    };
    use rand_core::SeedableRng;
    use std::cell::Cell;
    struct CountKey {
        inner: SoftwareIdentity,
        calls: Cell<usize>,
    }
    impl KeyAgreement for CountKey {
        fn key_id(&self) -> kagitaba_core::KeyId {
            self.inner.public_key().id()
        }
        async fn agree(
            &self,
            request: &AgreementRequest,
        ) -> kagitaba_core::Result<AgreementSecret> {
            self.calls.set(self.calls.get() + 1);
            self.inner.agree(request).await
        }
    }
    struct CountSigner {
        inner: Identity,
        calls: Cell<usize>,
    }
    impl Signer for CountSigner {
        fn public_key(&self) -> &PublicKey {
            self.inner.public_key()
        }
        fn sign(&self, data: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            self.inner.sign(data)
        }
    }
    fn payload(id: EntryId, title: &str) -> kagitaba_cxf::Payload {
        kagitaba_cxf::Payload::new(
            id,
            kagitaba_cxf::PayloadKind::Item,
            &serde_json::to_vec(
                &json!({"id":B64.encode(id.as_bytes()),"title":title,"credentials":[]}),
            )
            .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn oversized_listings_remain_complete_without_publishing_cache_or_key() {
        for collection in [false, true] {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
            let backend = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
            let public = backend.public_key();
            let mut identity = b"KBI1".to_vec();
            identity.extend([7; 32]);
            identity.extend([8; 32]);
            let signer = CountSigner {
                inner: Identity::read(&json!({"identity":B64.encode(identity)})).unwrap(),
                calls: Cell::new(0),
            };
            let mut snapshot =
                kagitaba_store::Snapshot::empty(public.clone(), signer.public_key().clone())
                    .unwrap();
            let first = EntryId::from_bytes([1; 16]);
            let second = EntryId::from_bytes([2; 16]);
            let title = "x".repeat(16_385);
            let oversized = if collection {
                kagitaba_cxf::Payload::new(
                    first,
                    kagitaba_cxf::PayloadKind::Collection,
                    &serde_json::to_vec(&json!({"id":B64.encode(first.as_bytes()),"title":title,
                        "items":[{"item":B64.encode(second.as_bytes())}],"subCollections":[]}))
                    .unwrap(),
                )
                .unwrap()
            } else {
                payload(first, &title)
            };
            for item in [oversized, payload(second, "Still accessible")] {
                snapshot.wallet = snapshot
                    .wallet
                    .with_entry(item.seal(std::slice::from_ref(&public), &mut rng).unwrap())
                    .unwrap();
            }
            let dir = tempfile::tempdir().unwrap();
            let mut store = Store::create(&dir.path().join("wallet"), snapshot, &signer).unwrap();
            let head = store.head;
            let signatures = signer.calls.get();
            for _ in 0..2 {
                let (listing, written) = futures::executor::block_on(refresh(
                    &mut store, &signer, &public, &backend, &mut rng,
                ))
                .unwrap();
                assert!(!written);
                assert_eq!(listing.rows().len(), 2);
                assert_eq!(listing.rows()[&first].title, title);
                assert_eq!(listing.rows()[&second].title, "Still accessible");
                if collection {
                    assert_eq!(
                        listing.rows()[&first].collection.as_ref().unwrap().entries,
                        vec![second]
                    );
                }
                assert_eq!(store.head, head);
                assert!(store.snapshot.index_keys.is_empty());
                assert!(store.snapshot.indexes.is_empty());
                assert_eq!(signer.calls.get(), signatures);
            }
            assert!(
                futures::executor::block_on(Index::refresh(
                    &store.snapshot,
                    &public,
                    &backend,
                    None
                ))
                .is_err()
            );
            let mut next = store.snapshot.clone();
            next.provision_index_key(&public, &mut rng).unwrap();
            next.indexes.insert(public.id(), b"stale cache".to_vec());
            store
                .save(next, &signer, "Synthetic existing index key")
                .unwrap();
            let head = store.head;
            let wrapped = store.snapshot.index_keys.clone();
            let signatures = signer.calls.get();
            let (listing, written) = futures::executor::block_on(refresh(
                &mut store, &signer, &public, &backend, &mut rng,
            ))
            .unwrap();
            assert!(!written);
            assert_eq!(listing.rows().len(), 2);
            assert_eq!(store.head, head);
            assert_eq!(store.snapshot.index_keys, wrapped);
            assert_eq!(store.snapshot.indexes[&public.id()], b"stale cache");
            assert_eq!(signer.calls.get(), signatures);
        }
    }
    #[test]
    fn cache_hit_only_unwraps_index_key_and_changed_deleted_rows_do_not_leak() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([4; 32]);
        let backend = CountKey {
            inner: SoftwareIdentity::from_bytes(&[7; 32]).unwrap(),
            calls: Cell::new(0),
        };
        let mut identity = b"KBI1".to_vec();
        identity.extend([7; 32]);
        identity.extend([8; 32]);
        let signer = CountSigner {
            inner: Identity::read(&json!({"identity":B64.encode(identity)})).unwrap(),
            calls: Cell::new(0),
        };
        let public = backend.inner.public_key();
        let mut snapshot =
            kagitaba_store::Snapshot::empty(public.clone(), signer.public_key().clone()).unwrap();
        let first = EntryId::from_bytes([1; 16]);
        let second = EntryId::from_bytes([2; 16]);
        for id in [first, second] {
            snapshot.wallet = snapshot
                .wallet
                .with_entry(
                    payload(id, "Synthetic")
                        .seal(std::slice::from_ref(&public), &mut rng)
                        .unwrap(),
                )
                .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(&dir.path().join("wallet"), snapshot, &signer).unwrap();
        let (index, written) =
            futures::executor::block_on(refresh(&mut store, &signer, &public, &backend, &mut rng))
                .unwrap();
        assert!(written);
        assert_eq!(index.rows().len(), 2);
        assert_eq!(backend.calls.get(), 2);
        let head = store.head;
        let signatures = signer.calls.get();
        backend.calls.set(0);
        let (_, written) =
            futures::executor::block_on(refresh(&mut store, &signer, &public, &backend, &mut rng))
                .unwrap();
        assert!(!written);
        assert_eq!(store.head, head);
        assert_eq!(signer.calls.get(), signatures);
        assert_eq!(backend.calls.get(), 1);
        let mut next = store.snapshot.clone();
        next.wallet = next
            .wallet
            .with_entry(
                payload(first, "Changed")
                    .seal(std::slice::from_ref(&public), &mut rng)
                    .unwrap(),
            )
            .unwrap();
        next.wallet = next.wallet.without_entry(second).unwrap();
        store.save(next, &signer, "Synthetic update").unwrap();
        backend.calls.set(0);
        let (index, written) =
            futures::executor::block_on(refresh(&mut store, &signer, &public, &backend, &mut rng))
                .unwrap();
        assert!(written);
        assert_eq!(backend.calls.get(), 2);
        assert_eq!(index.rows().len(), 1);
        assert_eq!(index.rows()[&first].title, "Changed");
        // A corrupt cache is disposable; the authoritative wrapped key survives.
        let wrapped = store.snapshot.index_keys[&public.id()].clone();
        let mut next = store.snapshot.clone();
        next.indexes.insert(public.id(), b"corrupt".to_vec());
        store
            .save(next, &signer, "Synthetic corrupt cache")
            .unwrap();
        struct Denied<'a>(&'a PublicKey);
        impl Signer for Denied<'_> {
            fn public_key(&self) -> &PublicKey {
                self.0
            }
            fn sign(&self, _: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
                Err(kagitaba_store::Error::Signing)
            }
        }
        let previous_head = store.head;
        assert!(
            futures::executor::block_on(refresh(
                &mut store,
                &Denied(signer.public_key()),
                &public,
                &backend,
                &mut rng
            ))
            .is_err()
        );
        assert_eq!(store.head, previous_head);
        assert_eq!(store.snapshot.indexes[&public.id()], b"corrupt");
        let (index, _) =
            futures::executor::block_on(refresh(&mut store, &signer, &public, &backend, &mut rng))
                .unwrap();
        assert_eq!(index.rows().len(), 1);
        assert_eq!(store.snapshot.index_keys[&public.id()], wrapped);
        let other = SoftwareIdentity::from_bytes(&[9; 32]).unwrap().public_key();
        let mut next = store.snapshot.clone();
        next.wallet = next.wallet.with_participant(other.clone()).unwrap();
        next.signers.insert(other.id(), other.clone());
        next.wallet = next
            .wallet
            .with_entry(
                payload(first, "No longer accessible")
                    .seal(&[other], &mut rng)
                    .unwrap(),
            )
            .unwrap();
        store
            .save(next, &signer, "Synthetic recipient removal")
            .unwrap();
        backend.calls.set(0);
        let (index, _) =
            futures::executor::block_on(refresh(&mut store, &signer, &public, &backend, &mut rng))
                .unwrap();
        assert!(index.rows().is_empty());
        assert_eq!(backend.calls.get(), 1);
    }
}

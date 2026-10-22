//! Reviewed additive access for an enrolled participant. No revocation or edits.
use super::*;
use kagitaba_core::{
    crypto::{KeyAgreement, WrappedKey},
    wallet::GrantRecord,
};

pub struct AccessPreview {
    pub target: KeyId,
    pub already_granted: usize,
    pub new_grants: usize,
    pub unavailable: usize,
}

pub(super) struct PendingAccess {
    head: String,
    participant: KeyId,
    target: KeyId,
    entries: Vec<EntryId>,
    already_granted: usize,
    unavailable: usize,
}
impl PendingAccess {
    pub async fn scan(
        snapshot: &Snapshot,
        head: &str,
        target: KeyId,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<Self> {
        if !snapshot.wallet.participants().contains_key(&target) {
            return Err("Choose an enrolled participant".into());
        }
        let mut pending = Self {
            head: head.to_owned(),
            participant: recipient.id(),
            target,
            entries: Vec::new(),
            already_granted: 0,
            unavailable: 0,
        };
        for (id, entry) in snapshot.wallet.entries() {
            if snapshot.is_metadata(id) {
                continue;
            }
            if !entry.grants().contains_key(&recipient.id()) {
                pending.unavailable += 1;
                continue;
            }
            let payload = match Payload::open(entry, recipient, backend).await {
                Ok(payload) => payload,
                Err(error @ kagitaba_cxf::Error::Core(kagitaba_core::Error::KeyUnavailable)) => {
                    return Err(error.into());
                }
                Err(_) => {
                    pending.unavailable += 1;
                    continue;
                }
            };
            if files::validate(snapshot, *id, &payload).is_err() {
                pending.unavailable += 1;
                continue;
            }
            if entry.grants().contains_key(&target) {
                pending.already_granted += 1;
            } else {
                pending.entries.push(*id);
            }
        }
        Ok(pending)
    }
    pub fn preview(&self) -> AccessPreview {
        AccessPreview {
            target: self.target,
            already_granted: self.already_granted,
            new_grants: self.entries.len(),
            unavailable: self.unavailable,
        }
    }
    pub async fn apply(
        &self,
        snapshot: &Snapshot,
        head: &str,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<Snapshot> {
        if self.head != head || self.participant != recipient.id() {
            return Err("Wallet or key changed; review access again".into());
        }
        if self.entries.is_empty() {
            return Err("No new access to grant".into());
        }
        let target = snapshot
            .wallet
            .participants()
            .get(&self.target)
            .ok_or("Participant is no longer enrolled")?;
        let mut next = snapshot.clone();
        for id in &self.entries {
            let entry = snapshot
                .wallet
                .entries()
                .get(id)
                .ok_or("Entry changed; review access again")?;
            if entry.grants().contains_key(&self.target) {
                return Err("Entry access changed; review access again".into());
            }
            let own = entry
                .grants()
                .get(&recipient.id())
                .ok_or("This key can no longer grant access")?;
            let key = WrappedKey::from_bytes(own.body())?
                .unwrap(
                    recipient,
                    &entry.primary().grant_context(recipient.id()),
                    backend,
                )
                .await?;
            let wrapped = WrappedKey::wrap(
                &key,
                target,
                &entry.primary().grant_context(self.target),
                &mut rand::rngs::SysRng,
            )?;
            let updated = entry.with_grant(GrantRecord::new(
                entry.primary(),
                self.target,
                wrapped.as_bytes().to_vec(),
            )?)?;
            next.wallet = next.wallet.with_entry(updated)?;
        }
        next.validate()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::{AgreementRequest, AgreementSecret, SoftwareIdentity};
    use kagitaba_cxf::{PayloadKind, attachments};
    fn id(n: u8) -> EntryId {
        EntryId::from_bytes([n; 16])
    }
    fn payload(n: u8, kind: PayloadKind) -> Payload {
        let encoded = data_encoding::BASE64URL_NOPAD.encode(id(n).as_bytes());
        let value = if kind == PayloadKind::Collection {
            serde_json::json!({"id":encoded,"title":"synthetic collection","items":[]})
        } else {
            serde_json::json!({"id":encoded,"title":"synthetic item","credentials":[]})
        };
        Payload::new(id(n), kind, &serde_json::to_vec(&value).unwrap()).unwrap()
    }
    fn fixture() -> (Snapshot, SoftwareIdentity, SoftwareIdentity) {
        let a = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let b = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
        let mut snapshot = Snapshot::empty(a.public_key(), a.public_key()).unwrap();
        snapshot.wallet = snapshot.wallet.with_participant(b.public_key()).unwrap();
        snapshot.signers.insert(b.public_key().id(), b.public_key());
        for (n, kind, keys) in [
            (1, PayloadKind::Item, vec![a.public_key()]),
            (2, PayloadKind::Collection, vec![a.public_key()]),
            (3, PayloadKind::Item, vec![a.public_key(), b.public_key()]),
            (4, PayloadKind::Item, vec![b.public_key()]),
        ] {
            snapshot.wallet = snapshot
                .wallet
                .with_entry(
                    payload(n, kind)
                        .seal(&keys, &mut rand::rngs::SysRng)
                        .unwrap(),
                )
                .unwrap();
        }
        let (file, blobs) = attachments::add(
            &payload(5, PayloadKind::Item),
            "synthetic.bin",
            b"synthetic file",
            &mut rand::rngs::SysRng,
        )
        .unwrap();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                file.seal(&[a.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        snapshot.attachments.insert(
            id(5),
            blobs
                .into_iter()
                .map(|(id, chunks)| {
                    (
                        id,
                        kagitaba_store::AttachmentBlob::from_chunks(&chunks).unwrap(),
                    )
                })
                .collect(),
        );
        (snapshot, a, b)
    }
    #[test]
    fn batch_adds_access_to_items_collections_and_files_without_changing_ciphertext() {
        let (snapshot, a, b) = fixture();
        let pending = block_on(PendingAccess::scan(
            &snapshot,
            "head",
            b.public_key().id(),
            &a.public_key(),
            &a,
        ))
        .unwrap();
        let preview = pending.preview();
        assert_eq!(
            (
                preview.already_granted,
                preview.new_grants,
                preview.unavailable
            ),
            (1, 3, 1)
        );
        let next = block_on(pending.apply(&snapshot, "head", &a.public_key(), &a)).unwrap();
        assert_eq!(next.attachments, snapshot.attachments);
        for (id, old) in snapshot.wallet.entries() {
            let new = &next.wallet.entries()[id];
            assert_eq!(new.primary(), old.primary());
            for (key, grant) in old.grants() {
                assert_eq!(&new.grants()[key], grant);
            }
            assert!(block_on(Payload::open(new, &b.public_key(), &b)).is_ok());
        }
        assert_eq!(snapshot.wallet.entries()[&id(1)].grants().len(), 1);
        let again = block_on(PendingAccess::scan(
            &next,
            "new-head",
            b.public_key().id(),
            &a.public_key(),
            &a,
        ))
        .unwrap();
        assert_eq!(again.preview().new_grants, 0);
        assert!(block_on(again.apply(&next, "new-head", &a.public_key(), &a)).is_err());
    }
    struct Denied {
        id: KeyId,
        calls: std::cell::Cell<usize>,
    }
    impl KeyAgreement for Denied {
        fn key_id(&self) -> KeyId {
            self.id
        }
        async fn agree(&self, _: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
            self.calls.set(self.calls.get() + 1);
            Err(kagitaba_core::Error::KeyUnavailable)
        }
    }
    #[test]
    fn stale_reviews_unknown_targets_and_denied_keys_never_publish_partial_access() {
        let (snapshot, a, b) = fixture();
        let pending = block_on(PendingAccess::scan(
            &snapshot,
            "head",
            b.public_key().id(),
            &a.public_key(),
            &a,
        ))
        .unwrap();
        assert!(block_on(pending.apply(&snapshot, "stale", &a.public_key(), &a)).is_err());
        assert!(block_on(pending.apply(&snapshot, "head", &b.public_key(), &b)).is_err());
        let unknown = SoftwareIdentity::from_bytes(&[9; 32]).unwrap();
        assert!(
            block_on(PendingAccess::scan(
                &snapshot,
                "head",
                unknown.public_key().id(),
                &a.public_key(),
                &a
            ))
            .is_err()
        );
        let denied = Denied {
            id: a.public_key().id(),
            calls: std::cell::Cell::new(0),
        };
        assert!(
            block_on(PendingAccess::scan(
                &snapshot,
                "head",
                b.public_key().id(),
                &a.public_key(),
                &denied
            ))
            .is_err()
        );
        assert_eq!(denied.calls.get(), 1);
        assert!(block_on(pending.apply(&snapshot, "head", &a.public_key(), &denied)).is_err());
        assert_eq!(snapshot.wallet.entries()[&id(1)].grants().len(), 1);
        assert_eq!(snapshot.wallet.entries()[&id(2)].grants().len(), 1);
    }
    #[test]
    fn denial_after_one_prepared_grant_leaves_original_snapshot_unchanged() {
        struct FailSecond<'a> {
            key: &'a SoftwareIdentity,
            calls: std::cell::Cell<usize>,
        }
        impl KeyAgreement for FailSecond<'_> {
            fn key_id(&self) -> KeyId {
                self.key.public_key().id()
            }
            async fn agree(
                &self,
                request: &AgreementRequest,
            ) -> kagitaba_core::Result<AgreementSecret> {
                self.calls.set(self.calls.get() + 1);
                if self.calls.get() == 2 {
                    return Err(kagitaba_core::Error::KeyUnavailable);
                }
                self.key.agree(request).await
            }
        }
        let (snapshot, a, b) = fixture();
        let pending = block_on(PendingAccess::scan(
            &snapshot,
            "head",
            b.public_key().id(),
            &a.public_key(),
            &a,
        ))
        .unwrap();
        let fail = FailSecond {
            key: &a,
            calls: std::cell::Cell::new(0),
        };
        assert!(block_on(pending.apply(&snapshot, "head", &a.public_key(), &fail)).is_err());
        assert_eq!(fail.calls.get(), 2);
        for n in [1, 2, 5] {
            assert!(
                !snapshot.wallet.entries()[&id(n)]
                    .grants()
                    .contains_key(&b.public_key().id())
            );
        }
    }
}

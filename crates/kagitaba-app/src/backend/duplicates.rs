//! Reviewed deletion of exact duplicates. Never merges related or inaccessible data.
use super::*;
use kagitaba_core::{
    crypto::{KeyAgreement, WrappedKey},
    wallet::GrantRecord,
};

pub struct DuplicateGroup {
    pub survivor: EntryId,
    pub removed: Vec<EntryId>,
    pub title: Zeroizing<String>,
    pub recipient_count: usize,
}
pub struct DuplicatePreview {
    pub groups: Vec<DuplicateGroup>,
    pub unavailable_entries: usize,
}
pub(super) struct PendingDuplicates {
    head: String,
    participant: KeyId,
    groups: Vec<Vec<EntryId>>,
    readable: BTreeMap<EntryId, Payload>,
    unavailable: usize,
}
impl PendingDuplicates {
    pub async fn scan(
        snapshot: &Snapshot,
        head: &str,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<Self> {
        let mut groups = BTreeMap::<[u8; 32], Vec<EntryId>>::new();
        let mut readable = BTreeMap::new();
        let mut unavailable = 0;
        let empty = BTreeMap::new();
        for (id, entry) in snapshot.wallet.entries() {
            if snapshot.is_metadata(id) {
                continue;
            }
            if !entry.grants().contains_key(&recipient.id()) {
                unavailable += 1;
                continue;
            }
            let payload = match Payload::open(entry, recipient, backend).await {
                Ok(payload) => payload,
                Err(error @ kagitaba_cxf::Error::Core(kagitaba_core::Error::KeyUnavailable)) => {
                    return Err(error.into());
                }
                Err(_) => {
                    unavailable += 1;
                    continue;
                }
            };
            match import_duplicates::fingerprint(
                &payload,
                snapshot.attachments.get(id).unwrap_or(&empty),
            ) {
                Ok(Some(hash)) => {
                    groups.entry(hash).or_default().push(*id);
                }
                Ok(None) => (),
                Err(_) => {
                    unavailable += 1;
                    continue;
                }
            }
            readable.insert(*id, payload);
        }
        let mut groups: Vec<_> = groups.into_values().filter(|ids| ids.len() > 1).collect();
        groups.sort_by_key(|ids| ids[0]);
        Ok(Self {
            head: head.to_owned(),
            participant: recipient.id(),
            groups,
            readable,
            unavailable,
        })
    }
    pub fn preview(&self, snapshot: &Snapshot) -> DuplicatePreview {
        DuplicatePreview {
            unavailable_entries: self.unavailable,
            groups: self
                .groups
                .iter()
                .map(|ids| {
                    let recipients = ids
                        .iter()
                        .flat_map(|id| snapshot.wallet.entries()[id].grants().keys().copied())
                        .collect::<BTreeSet<_>>();
                    DuplicateGroup {
                        survivor: ids[0],
                        removed: ids[1..].to_vec(),
                        title: Zeroizing::new(
                            self.readable[&ids[0]].entity()["title"]
                                .as_str()
                                .unwrap_or("Untitled")
                                .to_owned(),
                        ),
                        recipient_count: recipients.len(),
                    }
                })
                .collect(),
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
            return Err("Wallet or key changed; review duplicates again".into());
        }
        if self.groups.is_empty() {
            return Err("No duplicates to delete".into());
        }
        let remap: BTreeMap<_, _> = self
            .groups
            .iter()
            .flat_map(|ids| ids[1..].iter().map(|id| (*id, ids[0])))
            .collect();
        let mut next = snapshot.clone();
        let mut merged_payloads = BTreeMap::new();
        for ids in &self.groups {
            let recipients: BTreeSet<_> = ids
                .iter()
                .map(|id| {
                    snapshot
                        .wallet
                        .entries()
                        .get(id)
                        .ok_or("Duplicate changed; scan again")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .flat_map(|entry| entry.grants().keys().copied())
                .collect();
            let entry = &snapshot.wallet.entries()[&ids[0]];
            let incoming = ids[1..].iter().map(|id| &self.readable[id]).collect::<Vec<_>>();
            if let Some(merged) = super::import_duplicates::merge_provenance(&self.readable[&ids[0]], &incoming)? {
                let keys = recipients.iter().map(|id| next.wallet.participants().get(id).cloned().ok_or("Unknown participant")).collect::<std::result::Result<Vec<_>, _>>()?;
                next.wallet = next.wallet.with_entry(merged.seal(&keys, &mut rand::rngs::SysRng)?)?;
                merged_payloads.insert(ids[0], merged);
                continue;
            }
            let missing: Vec<_> = recipients
                .into_iter()
                .filter(|id| !entry.grants().contains_key(id))
                .collect();
            if missing.is_empty() {
                continue;
            }
            let grant = entry
                .grants()
                .get(&recipient.id())
                .ok_or("This key cannot extend duplicate access")?;
            let key = WrappedKey::from_bytes(grant.body())?
                .unwrap(
                    recipient,
                    &entry.primary().grant_context(recipient.id()),
                    backend,
                )
                .await?;
            let mut updated = entry.clone();
            for id in missing {
                let public = snapshot
                    .wallet
                    .participants()
                    .get(&id)
                    .ok_or("Unknown participant")?;
                let wrapped = WrappedKey::wrap(
                    &key,
                    public,
                    &entry.primary().grant_context(id),
                    &mut rand::rngs::SysRng,
                )?;
                updated = updated.with_grant(GrantRecord::new(
                    entry.primary(),
                    id,
                    wrapped.as_bytes().to_vec(),
                )?)?;
            }
            next.wallet = next.wallet.with_entry(updated)?;
        }
        for (id, payload) in &self.readable {
            if remap.contains_key(id) {
                continue;
            }
            let payload = merged_payloads.get(id).unwrap_or(payload);
            let mut changed = false;
            let rewritten = payload.edited(|value| {
                changed = rewrite_links(&mut value["entity"], &remap);
                Ok(())
            })?;
            if !changed {
                continue;
            }
            let keys = next.wallet.entries()[id]
                .grants()
                .keys()
                .map(|key| {
                    next.wallet
                        .participants()
                        .get(key)
                        .cloned()
                        .ok_or("Unknown participant")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            next.wallet = next
                .wallet
                .with_entry(rewritten.seal(&keys, &mut rand::rngs::SysRng)?)?;
        }
        for removed in remap.keys() {
            next.wallet = next.wallet.without_entry(*removed)?;
            next.attachments.remove(removed);
        }
        next.validate()?;
        Ok(next)
    }
}
fn rewrite_links(entity: &mut serde_json::Value, remap: &BTreeMap<EntryId, EntryId>) -> bool {
    fn link(value: &mut serde_json::Value, remap: &BTreeMap<EntryId, EntryId>) -> bool {
        use base64::Engine;
        if value.get("account").is_some() {
            return false;
        }
        let Some(encoded) = value["item"].as_str() else {
            return false;
        };
        let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        else {
            return false;
        };
        let Ok(bytes) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            return false;
        };
        let Some(target) = remap.get(&EntryId::from_bytes(bytes)) else {
            return false;
        };
        value["item"] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(target.as_bytes())
            .into();
        true
    }
    let mut changed = false;
    if let Some(items) = entity
        .get_mut("items")
        .and_then(serde_json::Value::as_array_mut)
    {
        for item in items {
            changed |= link(item, remap);
        }
    }
    if let Some(credentials) = entity
        .get_mut("credentials")
        .and_then(serde_json::Value::as_array_mut)
    {
        for credential in credentials {
            if credential["type"] == "item-reference" {
                changed |= link(&mut credential["reference"], remap);
            }
        }
    }
    if let Some(children) = entity
        .get_mut("subCollections")
        .and_then(serde_json::Value::as_array_mut)
    {
        for child in children {
            changed |= rewrite_links(child, remap);
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use kagitaba_core::crypto::{AgreementRequest, AgreementSecret, SoftwareIdentity};
    use kagitaba_cxf::{PayloadKind, attachments};
    use serde_json::json;
    fn id(n: u8) -> EntryId {
        EntryId::from_bytes([n; 16])
    }
    fn encoded(n: u8) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id(n).as_bytes())
    }
    fn payload(n: u8, title: &str) -> Payload {
        Payload::new(id(n),PayloadKind::Item,&serde_json::to_vec(&json!({"id":encoded(n),"title":title,"credentials":[{"type":"note","content":{"fieldType":"string","value":"synthetic"}}]})).unwrap()).unwrap()
    }
    fn fixture() -> (Snapshot, SoftwareIdentity, SoftwareIdentity) {
        let local = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let other = SoftwareIdentity::from_bytes(&[9; 32]).unwrap();
        let mut snapshot = Snapshot::empty(local.public_key(), local.public_key()).unwrap();
        snapshot.wallet = snapshot
            .wallet
            .with_participant(other.public_key())
            .unwrap();
        snapshot
            .signers
            .insert(other.public_key().id(), other.public_key());
        for (n, recipients) in [
            (10, vec![local.public_key()]),
            (11, vec![local.public_key(), other.public_key()]),
            (12, vec![local.public_key()]),
        ] {
            snapshot.wallet = snapshot
                .wallet
                .with_entry(
                    payload(n, if n == 12 { "different" } else { "same" })
                        .seal(&recipients, &mut rand::rngs::SysRng)
                        .unwrap(),
                )
                .unwrap();
        }
        let collection=Payload::new(id(20),PayloadKind::Collection,&serde_json::to_vec(&json!({"id":encoded(20),"title":"root","items":[{"item":encoded(11)},{"item":encoded(11),"account":"ZXh0ZXJuYWw"}],"subCollections":[{"id":encoded(21),"title":"child","items":[{"item":encoded(11)}]}]})).unwrap()).unwrap();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                collection
                    .seal(&[local.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        (snapshot, local, other)
    }
    #[test]
    fn reviewed_exact_duplicates_union_grants_redirect_links_and_preserve_other_data() {
        let (snapshot, local, other) = fixture();
        let pending = block_on(PendingDuplicates::scan(
            &snapshot,
            "head",
            &local.public_key(),
            &local,
        ))
        .unwrap();
        let preview = pending.preview(&snapshot);
        assert_eq!(preview.groups.len(), 1);
        assert_eq!(preview.groups[0].survivor, id(10));
        assert_eq!(preview.groups[0].removed, vec![id(11)]);
        assert_eq!(preview.groups[0].recipient_count, 2);
        assert!(block_on(pending.apply(&snapshot, "stale", &local.public_key(), &local)).is_err());
        assert!(block_on(pending.apply(&snapshot, "head", &other.public_key(), &other)).is_err());
        let next = block_on(pending.apply(&snapshot, "head", &local.public_key(), &local)).unwrap();
        assert!(!next.wallet.entries().contains_key(&id(11)));
        assert_eq!(
            next.wallet.entries()[&id(10)].primary(),
            snapshot.wallet.entries()[&id(10)].primary()
        );
        assert_eq!(
            next.wallet.entries()[&id(10)].grants()[&local.public_key().id()],
            snapshot.wallet.entries()[&id(10)].grants()[&local.public_key().id()]
        );
        assert!(
            block_on(Payload::open(
                &next.wallet.entries()[&id(10)],
                &other.public_key(),
                &other
            ))
            .is_ok()
        );
        assert_eq!(
            next.wallet.entries()[&id(12)],
            snapshot.wallet.entries()[&id(12)]
        );
        let tree = block_on(Payload::open(
            &next.wallet.entries()[&id(20)],
            &local.public_key(),
            &local,
        ))
        .unwrap();
        assert_eq!(tree.entity()["items"][0]["item"], encoded(10));
        assert_eq!(tree.entity()["items"][1]["item"], encoded(11));
        assert_eq!(
            tree.entity()["subCollections"][0]["items"][0]["item"],
            encoded(10)
        );
        assert!(snapshot.wallet.entries().contains_key(&id(11)));
    }
    #[test]
    fn cleanup_preserves_cross_source_provenance_and_union_access() {
        let (mut snapshot, local, other) = fixture();
        for (n,source) in [(10,"keepass"),(11,"bitwarden")] {
            let item = payload(n,"same").edited(|value| {
                value["source"] = json!({"vendor":source,"history":"synthetic retained data"});
                Ok(())
            }).unwrap();
            let recipients = if n==10 { vec![local.public_key()] } else { vec![local.public_key(),other.public_key()] };
            snapshot.wallet = snapshot.wallet.with_entry(item.seal(&recipients,&mut rand::rngs::SysRng).unwrap()).unwrap();
        }
        let pending=block_on(PendingDuplicates::scan(&snapshot,"head",&local.public_key(),&local)).unwrap();
        assert_eq!(pending.preview(&snapshot).groups.len(),1);
        let next=block_on(pending.apply(&snapshot,"head",&local.public_key(),&local)).unwrap();
        let survivor=block_on(Payload::open(&next.wallet.entries()[&id(10)],&other.public_key(),&other)).unwrap();
        let json:serde_json::Value=serde_json::from_slice(&survivor.to_json().unwrap()).unwrap();
        let records=json["kagitabaImportProvenance"]["records"].as_array().unwrap();
        assert_eq!(records.len(),2);
        assert!(records.iter().any(|r|r["source"]["vendor"]=="keepass"));
        assert!(records.iter().any(|r|r["source"]["vendor"]=="bitwarden"));
        assert!(!next.wallet.entries().contains_key(&id(11)));
        let tree=block_on(Payload::open(&next.wallet.entries()[&id(20)],&local.public_key(),&local)).unwrap();
        assert_eq!(tree.entity()["items"][0]["item"],encoded(10));
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
    fn denial_aborts_scan_or_apply_without_mutating_snapshot() {
        let (snapshot, local, _) = fixture();
        let denied = Denied {
            id: local.public_key().id(),
            calls: std::cell::Cell::new(0),
        };
        assert!(
            block_on(PendingDuplicates::scan(
                &snapshot,
                "head",
                &local.public_key(),
                &denied
            ))
            .is_err()
        );
        assert_eq!(denied.calls.get(), 1);
        let pending = block_on(PendingDuplicates::scan(
            &snapshot,
            "head",
            &local.public_key(),
            &local,
        ))
        .unwrap();
        assert!(block_on(pending.apply(&snapshot, "head", &local.public_key(), &denied)).is_err());
        assert_eq!(snapshot.wallet.entries()[&id(10)].grants().len(), 1);
        assert!(snapshot.wallet.entries().contains_key(&id(11)));
    }
    #[test]
    fn inaccessible_entries_remain_untouched_and_are_counted() {
        let (mut snapshot, local, other) = fixture();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                payload(13, "same")
                    .seal(&[other.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        let pending = block_on(PendingDuplicates::scan(
            &snapshot,
            "head",
            &local.public_key(),
            &local,
        ))
        .unwrap();
        assert_eq!(pending.preview(&snapshot).unavailable_entries, 1);
        let next = block_on(pending.apply(&snapshot, "head", &local.public_key(), &local)).unwrap();
        assert_eq!(
            next.wallet.entries()[&id(13)],
            snapshot.wallet.entries()[&id(13)]
        );
    }
    #[test]
    fn equal_authenticated_attachments_deduplicate_without_reencrypting_survivor() {
        let local = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let mut snapshot = Snapshot::empty(local.public_key(), local.public_key()).unwrap();
        for n in [10, 11] {
            let (payload, blobs) = attachments::add(
                &payload(n, "same"),
                "synthetic.bin",
                b"synthetic file",
                &mut rand::rngs::SysRng,
            )
            .unwrap();
            let mut stored = BTreeMap::new();
            for (blob, chunks) in blobs {
                use std::io::Write;
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(&attachments::encode_blob(&chunks).unwrap())
                    .unwrap();
                stored.insert(
                    blob,
                    kagitaba_store::AttachmentBlob::from_staged(file).unwrap(),
                );
            }
            snapshot.attachments.insert(id(n), stored);
            snapshot.wallet = snapshot
                .wallet
                .with_entry(
                    payload
                        .seal(&[local.public_key()], &mut rand::rngs::SysRng)
                        .unwrap(),
                )
                .unwrap();
        }
        let pending = block_on(PendingDuplicates::scan(
            &snapshot,
            "head",
            &local.public_key(),
            &local,
        ))
        .unwrap();
        assert_eq!(pending.groups.len(), 1);
        let next = block_on(pending.apply(&snapshot, "head", &local.public_key(), &local)).unwrap();
        assert_eq!(next.attachments.len(), 1);
        assert_eq!(next.attachments[&id(10)], snapshot.attachments[&id(10)]);
        let opened = block_on(Payload::open(
            &next.wallet.entries()[&id(10)],
            &local.public_key(),
            &local,
        ))
        .unwrap();
        let file = attachments::list(&opened).unwrap().remove(0);
        let mut clear = Zeroizing::new(Vec::new());
        attachments::decrypt_stream(
            id(10),
            &file,
            &mut next.attachments[&id(10)][&file.blob_id].open().unwrap(),
            &mut *clear,
        )
        .unwrap();
        assert_eq!(clear.as_slice(), b"synthetic file");
    }
}

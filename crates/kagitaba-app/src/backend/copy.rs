//! Read-only source preparation for an explicit copy to a verified destination.
//! The caller owns trust, signing, review, lock cancellation and publication.
use super::*;
use kagitaba_core::crypto::KeyAgreement;
use kagitaba_cxf::{PayloadKind, attachments};
use serde_json::Value;

/// Prepare item copies for the normal import review/deduplication transaction.
/// `source_namespace` is a stable source-wallet trust identifier, not its path.
/// Unselected local references remain explicitly external to the destination.
/// No source mutation occurs; staging contains encrypted attachment bytes only.
pub(super) async fn prepare(
    source: &Snapshot,
    destination: &Snapshot,
    selected: &[EntryId],
    source_namespace: &[u8],
    recipient: &PublicKey,
    backend: &impl KeyAgreement,
) -> Result<import_files::PendingImport> {
    if selected.is_empty() || selected.iter().collect::<BTreeSet<_>>().len() != selected.len() {
        return Err("Choose distinct entries to copy".into());
    }
    if source_namespace.is_empty() || source_namespace.len() > 65536 {
        return Err("Missing source wallet identity".into());
    }
    let mut occupied = source
        .wallet
        .entries()
        .keys()
        .chain(destination.wallet.entries().keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut mapping = BTreeMap::new();
    for id in selected {
        if source.is_metadata(id) || !source.wallet.entries().contains_key(id) {
            return Err("Choose an existing credential entry".into());
        }
        let new = loop {
            let candidate = EntryId::generate(&mut rand::rngs::SysRng)?;
            if occupied.insert(candidate) {
                break candidate;
            }
        };
        mapping.insert(*id, new);
    }
    let mut hash = Sha256::new();
    hash.update(b"Kagitaba/copied-source-wallet/v1\0");
    hash.update(source_namespace);
    let account = data_encoding::BASE64URL_NOPAD.encode(&hash.finalize());
    let mut entries = Vec::new();
    let mut blobs = BTreeMap::new();
    for id in selected {
        let entry = source
            .wallet
            .entries()
            .get(id)
            .ok_or("Missing source entry")?;
        let original = Payload::open(entry, recipient, backend).await?;
        if original.kind() != PayloadKind::Item {
            return Err("Select individual entries; collection copying is not supported".into());
        }
        files::validate(source, *id, &original)?;
        let source_files = attachments::list(&original)?;
        let mut copied = original.with_entry_id(mapping[id])?.edited(|raw| {
            rewrite_references(&mut raw["entity"], &mapping, &account);
            Ok(())
        })?;
        let mut copied_blobs = BTreeMap::new();
        for file in source_files {
            let blob = source
                .attachments
                .get(id)
                .and_then(|files| files.get(&file.blob_id))
                .ok_or("Missing source attachment")?;
            let mut reader = blob.open()?;
            let mut encrypted = tempfile::NamedTempFile::new()?;
            copied = attachments::copy_stream(
                *id,
                &copied,
                file.id,
                &mut reader,
                &mut encrypted,
                &mut rand::rngs::SysRng,
            )?;
            let fresh = attachments::list(&copied)?
                .into_iter()
                .find(|f| f.id == file.id)
                .ok_or("Missing copied attachment")?;
            if copied_blobs
                .insert(
                    fresh.blob_id.clone(),
                    kagitaba_store::AttachmentBlob::from_staged(encrypted)?,
                )
                .is_some()
            {
                return Err("Duplicate copied attachment".into());
            }
        }
        if !copied_blobs.is_empty() {
            blobs.insert(copied.entry_id(), copied_blobs);
        }
        entries.push(copied);
    }
    import_files::PendingImport::from_prepared(entries, blobs)
}

fn rewrite_references(
    entity: &mut Value,
    mapping: &BTreeMap<EntryId, EntryId>,
    source_account: &str,
) {
    let Some(credentials) = entity["credentials"].as_array_mut() else {
        return;
    };
    for credential in credentials {
        if credential["type"] != "item-reference" {
            continue;
        }
        let reference = &mut credential["reference"];
        if reference.get("account").is_some() {
            continue;
        }
        let local = reference["item"]
            .as_str()
            .and_then(|text| {
                data_encoding::BASE64URL_NOPAD
                    .decode(text.as_bytes())
                    .or_else(|_| data_encoding::BASE64URL.decode(text.as_bytes()))
                    .ok()
            })
            .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
            .map(EntryId::from_bytes);
        if let Some(target) = local.and_then(|id| mapping.get(&id)) {
            reference["item"] = data_encoding::BASE64URL_NOPAD
                .encode(target.as_bytes())
                .into();
        } else {
            reference["account"] = source_account.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use serde_json::json;

    fn item(id: EntryId, references: &[EntryId]) -> Payload {
        let mut credentials =
            vec![json!({"type":"note","content":{"fieldType":"string","value":"Synthetic copy"}})];
        credentials.extend(references.iter().map(|id| json!({"type":"item-reference","reference":{"item":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes())}})));
        Payload::new(id,PayloadKind::Item,&serde_json::to_vec(&json!({"id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Copy","credentials":credentials,"unknown":{"retain":true}})).unwrap()).unwrap()
            .edited(|raw| {raw["source"] = json!({"vendor":"synthetic","originalId":"unchanged"});Ok(())}).unwrap()
    }
    #[test]
    fn copies_are_fresh_source_unchanged_and_only_explicit_recipients_get_grants() {
        let identity = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let other = SoftwareIdentity::from_bytes(&[9; 32]).unwrap();
        let mut source = Snapshot::empty(identity.public_key(), identity.public_key()).unwrap();
        let mut destination = source.clone();
        destination.wallet = destination
            .wallet
            .with_participant(other.public_key())
            .unwrap();
        destination
            .signers
            .insert(other.public_key().id(), other.public_key());
        let a = EntryId::from_bytes([1; 16]);
        let b = EntryId::from_bytes([2; 16]);
        let missing = EntryId::from_bytes([3; 16]);
        let original = item(a, &[b, missing]);
        let bytes = vec![57; attachments::CHUNK_BYTES + 3];
        let (original, encrypted) =
            attachments::add(&original, "synthetic.bin", &bytes, &mut rand::rngs::SysRng).unwrap();
        source.attachments.insert(
            a,
            encrypted
                .into_iter()
                .map(|(id, chunks)| {
                    (
                        id,
                        kagitaba_store::AttachmentBlob::from_chunks(&chunks).unwrap(),
                    )
                })
                .collect(),
        );
        let first = original
            .seal(&[identity.public_key()], &mut rand::rngs::SysRng)
            .unwrap();
        let source_digest = first.primary().digest();
        source.wallet = source
            .wallet
            .with_entry(first)
            .unwrap()
            .with_entry(
                item(b, &[])
                    .seal(&[identity.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        let pending = block_on(prepare(
            &source,
            &destination,
            &[a, b],
            b"synthetic source trust identity",
            &identity.public_key(),
            &identity,
        ))
        .unwrap();
        let result = pending
            .encrypt_into(&destination, &[other.public_key().id()])
            .unwrap();
        assert_eq!(
            source.wallet.entries()[&a].primary().digest(),
            source_digest
        );
        assert!(destination.wallet.entries().is_empty());
        assert_eq!(result.wallet.entries().len(), 2);
        let mut copied_a = None;
        let mut copied_b = None;
        for (id, entry) in result.wallet.entries() {
            assert!(!source.wallet.entries().contains_key(id));
            assert_eq!(entry.grants().len(), 1);
            assert!(entry.grants().contains_key(&other.public_key().id()));
            let payload = block_on(Payload::open(entry, &other.public_key(), &other)).unwrap();
            assert_eq!(payload.source(), original.source());
            assert_eq!(payload.entity()["unknown"], original.entity()["unknown"]);
            if attachments::list(&payload).unwrap().is_empty() {
                copied_b = Some(*id);
            } else {
                copied_a = Some(payload);
            }
        }
        let copied = copied_a.unwrap();
        assert_eq!(
            copied.entity()["credentials"][1]["reference"]["item"],
            data_encoding::BASE64URL_NOPAD.encode(copied_b.unwrap().as_bytes())
        );
        assert!(
            copied.entity()["credentials"][1]["reference"]
                .get("account")
                .is_none()
        );
        assert!(copied.entity()["credentials"][2]["reference"]["account"].is_string());
        let file = attachments::list(&copied).unwrap().pop().unwrap();
        assert_ne!(
            file.blob_id,
            attachments::list(&original).unwrap()[0].blob_id
        );
        let mut clear = Zeroizing::new(Vec::new());
        let mut reader = result.attachments[&copied.entry_id()][&file.blob_id]
            .open()
            .unwrap();
        attachments::decrypt_stream(copied.entry_id(), &file, &mut reader, &mut *clear).unwrap();
        assert_eq!(clear.as_slice(), bytes);
        let mut reader = result.attachments[&copied.entry_id()][&file.blob_id]
            .open()
            .unwrap();
        assert!(attachments::decrypt_stream(a, &file, &mut reader, &mut std::io::sink()).is_err());
        assert!(pending.encrypt_into(&destination, &[]).is_err());
    }

    #[test]
    fn repeated_copy_reuses_authenticated_file_duplicate() {
        let identity = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let mut source = Snapshot::empty(identity.public_key(), identity.public_key()).unwrap();
        let destination = source.clone();
        let id = EntryId::from_bytes([4; 16]);
        let (payload, blobs) = attachments::add(
            &item(id, &[]),
            "copy.bin",
            b"Synthetic",
            &mut rand::rngs::SysRng,
        )
        .unwrap();
        source.wallet = source
            .wallet
            .with_entry(
                payload
                    .seal(&[identity.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        source.attachments.insert(
            id,
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
        let first = block_on(prepare(
            &source,
            &destination,
            &[id],
            b"source",
            &identity.public_key(),
            &identity,
        ))
        .unwrap();
        let destination = first
            .encrypt_into(&destination, &[identity.public_key().id()])
            .unwrap();
        let mut second = block_on(prepare(
            &source,
            &destination,
            &[id],
            b"source",
            &identity.public_key(),
            &identity,
        ))
        .unwrap();
        block_on(second.scan_existing(
            &destination,
            "reviewed-head",
            &identity.public_key(),
            &identity,
        ))
        .unwrap();
        assert_eq!(
            second
                .preview(ImportWarnings::default())
                .unwrap()
                .existing_duplicates,
            1
        );
        let result = block_on(second.apply(
            &destination,
            "reviewed-head",
            &[identity.public_key().id()],
            true,
            &identity.public_key(),
            &identity,
        ))
        .unwrap();
        assert_eq!(result.wallet.entries().len(), 1);
        let survivor = *destination.wallet.entries().keys().next().unwrap();
        assert_eq!(
            result.wallet.entries()[&survivor].primary().digest(),
            destination.wallet.entries()[&survivor].primary().digest()
        );
        assert_eq!(result.attachments, destination.attachments);
    }
}

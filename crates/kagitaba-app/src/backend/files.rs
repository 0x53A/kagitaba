use super::*;
use kagitaba_cxf::attachments;
use std::{
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone)]
pub struct FilePermit(Arc<AtomicBool>, Option<String>);
impl FilePermit {
    #[cfg(test)]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)), None)
    }
    pub fn for_head(head: String) -> Self {
        Self(Arc::new(AtomicBool::new(true)), Some(head))
    }
    fn check_head(&self, store: &Store) -> Result<()> {
        self.check()?;
        if self.1.as_ref().is_some_and(|head| {
            !kagitaba_store::parse_oid(head).is_ok_and(|expected| expected == store.head)
        }) {
            return Err("Wallet changed; open the entry again".into());
        }
        Ok(())
    }
    pub fn cancel(&self) {
        self.0.store(false, Ordering::Release);
    }
    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err("Attachment action cancelled".into())
        }
    }
}
struct PermitReader<'a, R> {
    inner: R,
    permit: &'a FilePermit,
}
impl<R: Read> Read for PermitReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.permit
            .check()
            .map_err(|_| io::Error::other("Attachment action cancelled"))?;
        self.inner.read(output)
    }
}
struct FileSigner<'a> {
    session: &'a Session<Usb>,
    permit: &'a FilePermit,
}
impl Signer for FileSigner<'_> {
    fn public_key(&self) -> &PublicKey {
        &self.session.signing
    }
    fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.permit
            .check()
            .map_err(|_| kagitaba_store::Error::Signing)?;
        let signature = Hardware(self.session).sign(bytes)?;
        self.permit
            .check()
            .map_err(|_| kagitaba_store::Error::Signing)?;
        Ok(signature)
    }
}
fn checked_entry(
    snapshot: &Snapshot,
    id: EntryId,
    digest: [u8; 32],
) -> Result<&kagitaba_core::wallet::Entry> {
    if snapshot.is_metadata(&id) {
        return Err("Not a credential entry".into());
    }
    let entry = snapshot.wallet.entries().get(&id).ok_or("Missing entry")?;
    if entry.primary().digest() != digest {
        return Err("Entry changed; open it again".into());
    }
    Ok(entry)
}
pub(super) fn validate(snapshot: &Snapshot, id: EntryId, payload: &Payload) -> Result<()> {
    validate_map(payload, snapshot.attachments.get(&id))
}
fn validate_map(
    payload: &Payload,
    blobs: Option<&BTreeMap<String, kagitaba_store::AttachmentBlob>>,
) -> Result<()> {
    let files = attachments::list(payload)?;
    if files.len() != blobs.map_or(0, BTreeMap::len) {
        return Err("Attachment manifest does not match stored files".into());
    }
    for file in files {
        let blob = blobs
            .and_then(|map| map.get(&file.blob_id))
            .ok_or("Missing attachment data")?;
        if u64::try_from(blob.len())? != attachments::expected_blob_size(&file)? {
            return Err("Invalid attachment size".into());
        }
    }
    Ok(())
}
/// Rekey one file at a time into private encrypted staging. Snapshot mutation
/// occurs only after every source authenticates and every replacement is ready.
pub(super) fn rekey_payload(
    mut payload: Payload,
    blobs: Option<&BTreeMap<String, kagitaba_store::AttachmentBlob>>,
) -> Result<(Payload, BTreeMap<String, kagitaba_store::AttachmentBlob>)> {
    validate_map(&payload, blobs)?;
    let files = attachments::list(&payload)?;
    let mut updated = BTreeMap::new();
    for file in files {
        let mut source = blobs
            .and_then(|map| map.get(&file.blob_id))
            .ok_or("Missing attachment data")?
            .open()?;
        let mut staging = tempfile::NamedTempFile::new()?;
        payload = attachments::rekey_stream(
            &payload,
            file.id,
            &mut source,
            &mut staging,
            &mut rand::rngs::SysRng,
        )?;
        let replacement = attachments::list(&payload)?
            .into_iter()
            .find(|row| row.id == file.id)
            .ok_or("Missing replacement attachment")?;
        updated.insert(
            replacement.blob_id.clone(),
            kagitaba_store::AttachmentBlob::from_staged(staging)?,
        );
    }
    Ok((payload, updated))
}
pub(super) fn prepare_edit(
    next: &mut Snapshot,
    id: EntryId,
    old: &Payload,
    edited: Payload,
    recipients: &BTreeSet<KeyId>,
) -> Result<Payload> {
    validate(next, id, old)?;
    attachments::validate_edit(old, &edited)?;
    let previous = next.wallet.entries().get(&id).ok_or("Missing entry")?;
    if previous
        .grants()
        .keys()
        .any(|recipient| !recipients.contains(recipient))
    {
        let (updated, blobs) = rekey_payload(edited, next.attachments.get(&id))?;
        if blobs.is_empty() {
            next.attachments.remove(&id);
        } else {
            next.attachments.insert(id, blobs);
        }
        Ok(updated)
    } else {
        Ok(edited)
    }
}
fn open_source(path: &Path) -> Result<(fs::File, u64)> {
    // O_NONBLOCK avoids hanging on FIFOs; inspect the opened inode, not a
    // separate path lookup that could be replaced before opening.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("Choose a regular file".into());
    }
    if metadata.len() > attachments::MAX_FILE_BYTES as u64 {
        return Err("Attachment exceeds 64 MiB".into());
    }
    Ok((file, metadata.len()))
}
fn export_stage(path: &Path) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(tempfile::NamedTempFile::new_in(parent)?)
}
/// Only called after streaming authentication, final length/hash and EOF checks.
fn publish(temp: tempfile::NamedTempFile, path: &Path, permit: &FilePermit) -> Result<()> {
    temp.as_file().sync_all()?;
    permit.check()?;
    temp.persist_noclobber(path)
        .map_err(|_| "Could not save attachment; choose a new destination")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn export_blob(
    owner: EntryId,
    descriptor: &attachments::Attachment,
    blob: &kagitaba_store::AttachmentBlob,
    path: &Path,
    permit: &FilePermit,
) -> Result<()> {
    let mut source = PermitReader {
        inner: blob.open()?,
        permit,
    };
    let mut staging = export_stage(path)?;
    attachments::decrypt_stream(owner, descriptor, &mut source, &mut staging)?;
    publish(staging, path, permit)
}

impl Worker {
    pub(super) fn file_add(
        &mut self,
        id: EntryId,
        digest: [u8; 32],
        path: &Path,
        permit: &FilePermit,
    ) -> Result<()> {
        permit.check()?;
        let store = self.store.as_ref().ok_or("Open a wallet first")?;
        permit.check_head(store)?;
        let mut next = store.snapshot.clone();
        let entry = checked_entry(&next, id, digest)?;
        let session = self.session.as_ref().ok_or("Unlock a key first")?;
        let payload = block_on(Payload::open(entry, &session.encryption, session))?;
        validate(&next, id, &payload)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("File name is not UTF-8")?;
        let (source, size) = open_source(path)?;
        let mut source = PermitReader {
            inner: source,
            permit,
        };
        let mut staging = tempfile::NamedTempFile::new()?;
        let payload = attachments::add_stream(
            &payload,
            name,
            size,
            &mut source,
            &mut staging,
            &mut rand::rngs::SysRng,
        )?;
        permit.check()?;
        let new_file = attachments::list(&payload)?
            .into_iter()
            .find(|row| {
                !next
                    .attachments
                    .get(&id)
                    .is_some_and(|map| map.contains_key(&row.blob_id))
            })
            .ok_or("Missing attachment descriptor")?;
        let blob = kagitaba_store::AttachmentBlob::from_staged(staging)?;
        let recipients: Vec<_> = entry
            .grants()
            .keys()
            .map(|key| next.wallet.participants()[key].clone())
            .collect();
        let updated = payload.seal(&recipients, &mut rand::rngs::SysRng)?;
        next.attachments
            .entry(id)
            .or_default()
            .insert(new_file.blob_id.clone(), blob);
        next.wallet = next.wallet.with_entry(updated)?;
        self.commit_file(next, "Attach file", permit)
    }
    pub(super) fn file_rename(
        &mut self, id: EntryId, digest: [u8; 32], attachment: EntryId,
        name: &str, permit: &FilePermit,
    ) -> Result<()> {
        permit.check()?;
        let store = self.store.as_ref().ok_or("Open a wallet first")?;
        permit.check_head(store)?;
        let mut next = store.snapshot.clone();
        let entry = checked_entry(&next, id, digest)?;
        let session = self.session.as_ref().ok_or("Unlock a key first")?;
        let payload = block_on(Payload::open(entry, &session.encryption, session))?;
        validate(&next, id, &payload)?;
        let payload = attachments::rename(&payload, attachment, name)?;
        let recipients: Vec<_> = entry.grants().keys()
            .map(|key| next.wallet.participants()[key].clone()).collect();
        let updated = payload.seal(&recipients, &mut rand::rngs::SysRng)?;
        next.wallet = next.wallet.with_entry(updated)?;
        self.commit_file(next, "Rename attachment", permit)
    }
    pub(super) fn file_remove(
        &mut self,
        id: EntryId,
        digest: [u8; 32],
        attachment: EntryId,
        permit: &FilePermit,
    ) -> Result<()> {
        permit.check()?;
        let store = self.store.as_ref().ok_or("Open a wallet first")?;
        permit.check_head(store)?;
        let mut next = store.snapshot.clone();
        let entry = checked_entry(&next, id, digest)?;
        let session = self.session.as_ref().ok_or("Unlock a key first")?;
        let payload = block_on(Payload::open(entry, &session.encryption, session))?;
        validate(&next, id, &payload)?;
        let (payload, blob) = attachments::remove(&payload, attachment)?;
        let recipients: Vec<_> = entry
            .grants()
            .keys()
            .map(|key| next.wallet.participants()[key].clone())
            .collect();
        let updated = payload.seal(&recipients, &mut rand::rngs::SysRng)?;
        if let Some(blobs) = next.attachments.get_mut(&id) {
            blobs.remove(&blob);
            if blobs.is_empty() {
                next.attachments.remove(&id);
            }
        }
        next.wallet = next.wallet.with_entry(updated)?;
        self.commit_file(next, "Remove attachment", permit)
    }
    pub(super) fn file_export(
        &self,
        id: EntryId,
        digest: [u8; 32],
        attachment: EntryId,
        path: &Path,
        permit: &FilePermit,
    ) -> Result<()> {
        permit.check()?;
        let store = self.store.as_ref().ok_or("Open a wallet first")?;
        permit.check_head(store)?;
        let snapshot = &store.snapshot;
        let entry = checked_entry(snapshot, id, digest)?;
        let session = self.session.as_ref().ok_or("Unlock a key first")?;
        let payload = block_on(Payload::open(entry, &session.encryption, session))?;
        validate(snapshot, id, &payload)?;
        let descriptor = attachments::list(&payload)?
            .into_iter()
            .find(|file| file.id == attachment)
            .ok_or("Missing attachment")?;
        let blob = snapshot
            .attachments
            .get(&id)
            .and_then(|map| map.get(&descriptor.blob_id))
            .ok_or("Missing attachment data")?;
        export_blob(id, &descriptor, blob, path, permit)
    }
    fn commit_file(
        &mut self,
        mut next: Snapshot,
        message: &str,
        permit: &FilePermit,
    ) -> Result<()> {
        permit.check()?;
        let session = self.session.as_ref().ok_or("Unlock a key first")?;
        let store = self.store.as_mut().ok_or("Open a wallet first")?;
        next.prune_legacy(&mut rand::rngs::SysRng)?;
        block_on(next.complete_metadata_grants(
            &session.encryption,
            session,
            &mut rand::rngs::SysRng,
        ))?;
        refresh_index_for_write(&mut next, session, &mut self.index);
        permit.check()?;
        store.save(next, &FileSigner { session, permit }, message)?;
        save_trust(store)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use std::{
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
    };
    fn staged(bytes: &[u8]) -> kagitaba_store::AttachmentBlob {
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(bytes).unwrap();
        kagitaba_store::AttachmentBlob::from_staged(temp).unwrap()
    }
    fn decrypted(
        owner: EntryId,
        file: &attachments::Attachment,
        blob: &kagitaba_store::AttachmentBlob,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        attachments::decrypt_stream(owner, file, &mut blob.open()?, &mut out)?;
        Ok(out)
    }
    fn publish_bytes(path: &Path, bytes: &[u8], permit: &FilePermit) -> Result<()> {
        let mut temp = export_stage(path)?;
        temp.write_all(bytes)?;
        publish(temp, path, permit)
    }
    fn fixture() -> (Snapshot, Payload, EntryId, PublicKey, PublicKey) {
        let a = SoftwareIdentity::from_bytes(&[1; 32]).unwrap().public_key();
        let b = SoftwareIdentity::from_bytes(&[2; 32]).unwrap().public_key();
        let id = EntryId::from_bytes([3; 16]);
        let payload = Payload::new(id, kagitaba_cxf::PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
            "id": data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()), "title":"Attachment fixture", "credentials":[]
        })).unwrap()).unwrap();
        let (payload, blobs) = attachments::add(
            &payload,
            "example.txt",
            b"synthetic attachment",
            &mut rand::rngs::SysRng,
        )
        .unwrap();
        let mut snapshot = Snapshot::empty(a.clone(), a.clone()).unwrap();
        snapshot.wallet = snapshot.wallet.with_participant(b.clone()).unwrap();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                payload
                    .seal(&[a.clone(), b.clone()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        snapshot.attachments.insert(
            id,
            blobs
                .into_iter()
                .map(|(id, chunks)| (id, staged(&attachments::encode_blob(&chunks).unwrap())))
                .collect(),
        );
        (snapshot, payload, id, a, b)
    }
    #[test]
    fn edit_preserves_files_but_recipient_reduction_rekeys_before_sealing() {
        let (mut snapshot, old, id, a, b) = fixture();
        let original = snapshot.attachments.clone();
        let copy = Payload::from_json(id, &old.to_json().unwrap()).unwrap();
        let unchanged = prepare_edit(
            &mut snapshot,
            id,
            &old,
            copy,
            &BTreeSet::from([a.id(), b.id()]),
        )
        .unwrap();
        assert_eq!(snapshot.attachments, original);
        let before = attachments::list(&unchanged).unwrap().remove(0);
        let edited = Payload::from_json(id, &old.to_json().unwrap()).unwrap();
        let changed =
            prepare_edit(&mut snapshot, id, &old, edited, &BTreeSet::from([a.id()])).unwrap();
        let after = attachments::list(&changed).unwrap().remove(0);
        assert_eq!(before.id, after.id);
        assert_ne!(before.blob_id, after.blob_id);
        assert!(!snapshot.attachments[&id].contains_key(&before.blob_id));
        assert!(decrypted(id, &before, &snapshot.attachments[&id][&after.blob_id]).is_err());
        assert_eq!(
            &*decrypted(id, &after, &snapshot.attachments[&id][&after.blob_id]).unwrap(),
            b"synthetic attachment"
        );
    }
    #[test]
    fn descriptor_edit_corrupt_file_and_stale_parent_are_rejected() {
        let (mut snapshot, old, id, a, b) = fixture();
        let descriptor = attachments::list(&old).unwrap().remove(0);
        let (removed, _) = attachments::remove(&old, descriptor.id).unwrap();
        assert!(
            prepare_edit(
                &mut snapshot,
                id,
                &old,
                removed,
                &BTreeSet::from([a.id(), b.id()])
            )
            .is_err()
        );
        let digest = snapshot.wallet.entries()[&id].primary().digest();
        assert!(checked_entry(&snapshot, id, digest).is_ok());
        assert!(checked_entry(&snapshot, id, [0; 32]).is_err());
        let mut bytes = Vec::new();
        snapshot.attachments[&id][&descriptor.blob_id]
            .open()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        bytes[82] ^= 1;
        snapshot
            .attachments
            .get_mut(&id)
            .unwrap()
            .insert(descriptor.blob_id.clone(), staged(&bytes));
        let before = snapshot.attachments.clone();
        let copy = Payload::from_json(id, &old.to_json().unwrap()).unwrap();
        assert!(prepare_edit(&mut snapshot, id, &old, copy, &BTreeSet::from([a.id()])).is_err());
        assert_eq!(snapshot.attachments, before);
    }
    #[test]
    fn streaming_export_never_publishes_before_final_hash_verification() {
        let (snapshot, payload, owner, _, _) = fixture();
        let mut json: serde_json::Value =
            serde_json::from_slice(&payload.to_json().unwrap()).unwrap();
        json["entity"]["credentials"][0]["integrityHash"] =
            serde_json::Value::String(data_encoding::BASE64URL_NOPAD.encode(&[0; 32]));
        let wrong = Payload::from_json(owner, &serde_json::to_vec(&json).unwrap()).unwrap();
        let descriptor = attachments::list(&wrong).unwrap().remove(0);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.txt");
        assert!(
            export_blob(
                owner,
                &descriptor,
                &snapshot.attachments[&owner][&descriptor.blob_id],
                &path,
                &FilePermit::new()
            )
            .is_err()
        );
        assert!(!path.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn export_is_private_complete_non_overwriting_and_cancellable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("export.txt");
        let permit = FilePermit::new();
        publish_bytes(&path, b"verified", &permit).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"verified");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(publish_bytes(&path, b"replacement", &permit).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"verified");
        permit.cancel();
        let cancelled = temp.path().join("cancelled.txt");
        assert!(publish_bytes(&cancelled, b"secret", &permit).is_err());
        assert!(!cancelled.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        let fifo = temp.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(open_source(&fifo).is_err());
        let oversized = temp.path().join("large");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(attachments::MAX_FILE_BYTES as u64 + 1)
            .unwrap();
        assert!(open_source(&oversized).is_err());
    }
}

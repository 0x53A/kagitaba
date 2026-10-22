use super::*;

pub struct CopyPreview {
    pub path: PathBuf,
    pub participants: Vec<KeyId>,
    pub review: ImportPreview,
    pub requires_unlock: bool,
    pub default_recipient: Option<KeyId>,
}

pub(super) struct PendingCopy {
    destination: Store,
    plan: import_files::PendingImport,
    source_path: PathBuf,
    source_head: String,
    target_session: Option<Session<Usb>>,
}

impl Worker {
    pub(super) fn copy_preview(&self) -> Result<Option<CopyPreview>> {
        let Some(pending) = &self.pending_copy else {
            return Ok(None);
        };
        let authorized = pending
            .target_session
            .as_ref()
            .or(self.session.as_ref())
            .filter(|session| {
                verify_destination(
                    &pending.destination.snapshot,
                    &session.encryption,
                    &session.signing,
                )
                .is_ok()
            });
        Ok(Some(CopyPreview {
            path: pending.destination.path.clone(),
            participants: pending
                .destination
                .snapshot
                .wallet
                .participants()
                .keys()
                .copied()
                .collect(),
            review: pending.plan.preview(ImportWarnings::default())?,
            requires_unlock: authorized.is_none(),
            default_recipient: authorized.map(|session| session.encryption.id()),
        }))
    }

    pub(super) fn scan_copy_devices(&mut self, events: &mpsc::Sender<Event>) -> Result<()> {
        let pending = self.pending_copy.as_ref().ok_or("Preview the copy first")?;
        if pending.target_session.is_some() {
            return Err("The destination key is already unlocked".into());
        }
        self.release_source_key_for_copy();
        events.send(Event::Locked)?;
        events.send(Event::Devices(usb::devices()?))?;
        if let Some(preview) = self.copy_preview()? {
            events.send(Event::CopyPreview(preview))?;
        }
        Ok(())
    }

    fn release_source_key_for_copy(&mut self) {
        self.session = None;
        self.session_device = None;
        self.index = None;
        self.prepared = None;
        self.pending = None;
        self.pending_duplicates = None;
        self.pending_access = None;
    }

    pub(super) fn preview_copy(
        &mut self,
        path: PathBuf,
        ids: Vec<EntryId>,
        events: &mpsc::Sender<Event>,
    ) -> Result<()> {
        self.pending_copy = None;
        let source = self.store.as_ref().ok_or("Open the source wallet first")?;
        if fs::canonicalize(&path)? == fs::canonicalize(&source.path)? {
            return Err("Choose a different destination wallet".into());
        }
        let trust = trust_path(&path)?;
        if !trust.exists() {
            return Err("Open and verify the destination wallet once before copying to it".into());
        }
        let value: serde_json::Value = serde_json::from_slice(&fs::read(trust)?)?;
        let root = PublicKey::from_pem(
            value["root"]
                .as_str()
                .ok_or("Invalid destination trust record")?,
        )?;
        let checkpoint = kagitaba_store::parse_oid(
            value["checkpoint"]
                .as_str()
                .ok_or("Invalid destination checkpoint")?,
        )?;
        let destination = Store::open(&path, root, Some(checkpoint))?;
        let session = self
            .session
            .as_ref()
            .ok_or("Unlock the source wallet first")?;
        let authorized =
            verify_destination(&destination.snapshot, &session.encryption, &session.signing)
                .is_ok();
        let mut namespace = Sha256::new();
        namespace.update(b"Kagitaba/copy-source-namespace/v1\0");
        namespace.update(source.root_signer.id().as_bytes());
        namespace.update(fs::canonicalize(&source.path)?.as_os_str().as_encoded_bytes());
        let namespace = namespace.finalize();
        let mut plan = block_on(copy::prepare(
            &source.snapshot,
            &destination.snapshot,
            &ids,
            &namespace,
            &session.encryption,
            session,
        ))?;
        if authorized {
            block_on(plan.scan_existing(
                &destination.snapshot,
                &destination.head.to_string(),
                &session.encryption,
                session,
            ))?;
        }
        let preview = CopyPreview {
            path: destination.path.clone(),
            participants: destination
                .snapshot
                .wallet
                .participants()
                .keys()
                .copied()
                .collect(),
            review: plan.preview(ImportWarnings::default())?,
            requires_unlock: !authorized,
            default_recipient: authorized.then_some(session.encryption.id()),
        };
        self.pending_copy = Some(PendingCopy {
            destination,
            plan,
            source_path: source.path.clone(),
            source_head: source.head.to_string(),
            target_session: None,
        });
        events.send(Event::CopyPreview(preview))?;
        Ok(())
    }

    pub(super) fn unlock_copy(
        &mut self,
        device: Device,
        slots: Slots,
        pin: Zeroizing<String>,
        events: &mpsc::Sender<Event>,
    ) -> Result<()> {
        if self.pending_copy.is_none() {
            return Err("Preview the copy first".into());
        }
        // One physical card connection at a time. Target authority must never be
        // confused with the source wallet's unlocked participant.
        self.release_source_key_for_copy();
        let pending = self.pending_copy.as_mut().expect("checked above");
        pending.target_session = None;
        events.send(Event::Locked)?;
        let mut card = Piv::new(Usb::open(&device)?)?;
        let hint = device_hint(&mut card, slots)?;
        let session = Session::unlock_with_slots(card, &pin, slots)?;
        verify_destination(
            &pending.destination.snapshot,
            &session.encryption,
            &session.signing,
        )?;
        if let Some(hint) = hint {
            verify_device_hint(
                &pending.destination.snapshot,
                &hint,
                &session.encryption,
                &session.signing,
            )?;
        }
        block_on(pending.plan.scan_existing(
            &pending.destination.snapshot,
            &pending.destination.head.to_string(),
            &session.encryption,
            &session,
        ))?;
        let preview = CopyPreview {
            path: pending.destination.path.clone(),
            participants: pending
                .destination
                .snapshot
                .wallet
                .participants()
                .keys()
                .copied()
                .collect(),
            review: pending.plan.preview(ImportWarnings::default())?,
            requires_unlock: false,
            default_recipient: Some(session.encryption.id()),
        };
        pending.target_session = Some(session);
        events.send(Event::CopyPreview(preview))?;
        Ok(())
    }

    pub(super) fn copy_entries(
        &mut self,
        recipients: Vec<KeyId>,
        skip: bool,
        events: &mpsc::Sender<Event>,
    ) -> Result<()> {
        let mut pending = self.pending_copy.take().ok_or("Preview the copy first")?;
        let source = self.store.as_ref().ok_or("Source wallet is closed")?;
        if source.path != pending.source_path || source.head != pending.source_head.as_str() {
            return Err("Source wallet changed; preview the copy again".into());
        }
        let session = pending
            .target_session
            .as_ref()
            .or(self.session.as_ref())
            .ok_or("Unlock a destination key first")?;
        verify_destination(
            &pending.destination.snapshot,
            &session.encryption,
            &session.signing,
        )?;
        let mut next = block_on(pending.plan.apply(
            &pending.destination.snapshot,
            &pending.destination.head.to_string(),
            &recipients,
            skip,
            &session.encryption,
            session,
        ))?;
        next.prune_legacy(&mut rand::rngs::SysRng)?;
        block_on(next.complete_metadata_grants(
            &session.encryption,
            session,
            &mut rand::rngs::SysRng,
        ))?;
        // Destination caches remain hints; refresh this participant independently.
        refresh_index_for_write(&mut next, session, &mut None);
        pending
            .destination
            .save(next, &Hardware(session), "Copy entries from another wallet")?;
        save_trust(&pending.destination)?;
        events.send(Event::Copied)?;
        Ok(())
    }
}

fn verify_destination(
    snapshot: &Snapshot,
    encryption: &PublicKey,
    signing: &PublicKey,
) -> Result<()> {
    if snapshot.wallet.participants().get(&encryption.id()) != Some(encryption)
        || snapshot.signers.get(&encryption.id()) != Some(signing)
    {
        return Err("The unlocked key must be enrolled for encryption and signing in the destination wallet".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    #[test]
    fn source_authority_does_not_authorize_destination_signing() {
        let a = SoftwareIdentity::from_bytes(&[7; 32]).unwrap().public_key();
        let b = SoftwareIdentity::from_bytes(&[8; 32]).unwrap().public_key();
        let snapshot = Snapshot::empty(a.clone(), b.clone()).unwrap();
        assert!(verify_destination(&snapshot, &a, &a).is_err());
        assert!(verify_destination(&snapshot, &b, &b).is_err());
        assert!(verify_destination(&snapshot, &a, &b).is_ok());
    }
    #[test]
    fn separately_authorized_target_key_scans_and_applies_source_preparation() {
        let source_key = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let target_key = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
        let mut source = Snapshot::empty(source_key.public_key(), source_key.public_key()).unwrap();
        let target = Snapshot::empty(target_key.public_key(), target_key.public_key()).unwrap();
        let id = EntryId::from_bytes([42; 16]);
        let payload = Payload::new(
            id,
            kagitaba_cxf::PayloadKind::Item,
            br#"{"id":"KioqKioqKioqKioqKioqKg","title":"synthetic","credentials":[]}"#,
        )
        .unwrap();
        source.wallet = source
            .wallet
            .with_entry(
                payload
                    .seal(&[source_key.public_key()], &mut rand::rngs::SysRng)
                    .unwrap(),
            )
            .unwrap();
        assert!(
            verify_destination(&target, &source_key.public_key(), &source_key.public_key())
                .is_err()
        );
        let mut plan = block_on(copy::prepare(
            &source,
            &target,
            &[id],
            b"synthetic source identity",
            &source_key.public_key(),
            &source_key,
        ))
        .unwrap();
        let recipients = [target_key.public_key().id()];
        assert!(
            block_on(plan.apply(
                &target,
                "target-head",
                &recipients,
                true,
                &target_key.public_key(),
                &target_key
            ))
            .is_err()
        );
        verify_destination(&target, &target_key.public_key(), &target_key.public_key()).unwrap();
        block_on(plan.scan_existing(
            &target,
            "target-head",
            &target_key.public_key(),
            &target_key,
        ))
        .unwrap();
        // A source key cannot reuse a destination-key-bound review.
        assert!(
            block_on(plan.apply(
                &target,
                "target-head",
                &recipients,
                true,
                &source_key.public_key(),
                &source_key
            ))
            .is_err()
        );
        let copied = block_on(plan.apply(
            &target,
            "target-head",
            &recipients,
            true,
            &target_key.public_key(),
            &target_key,
        ))
        .unwrap();
        assert_eq!(copied.wallet.entries().len(), 1);
        let entry = copied.wallet.entries().values().next().unwrap();
        assert!(block_on(Payload::open(entry, &target_key.public_key(), &target_key)).is_ok());
        assert!(block_on(Payload::open(entry, &source_key.public_key(), &source_key)).is_err());
        assert!(source.wallet.entries().contains_key(&id));
        assert!(target.wallet.entries().is_empty());
    }
}

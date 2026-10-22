pub mod access;
mod files;
mod copy;
mod copy_workflow;
pub use copy_workflow::CopyPreview;
mod import_files;
#[cfg(test)]
mod import_original_tests;
mod import_duplicates;
pub mod duplicates;
pub mod import_preview;
pub use files::FilePermit;
use futures::executor::block_on;
use kagitaba_core::{EntryId, KeyId, crypto::{ContentKey, PublicKey}};
use kagitaba_cxf::{Document, ImportPlan, Payload};
use kagitaba_device::{
    AuthenticatedPiv, Piv, Session, Slots, Policies, KeyPolicy, PrivateOperation,
    usb::{self, Device, Usb},
};
use kagitaba_store::{DeviceHint, Signer, Snapshot, Store};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Hardware<'a>(&'a Session<Usb>);
impl Signer for Hardware<'_> {
    fn public_key(&self) -> &PublicKey {
        &self.0.signing
    }
    fn sign(&self, message: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.0
            .sign(message)
            .map_err(|_| kagitaba_store::Error::Signing)
    }
}
struct GatewaySigner<'a> { session: &'a Session<Usb>, permit: &'a crate::gateway::Permit }
impl Signer for GatewaySigner<'_> {
    fn public_key(&self) -> &PublicKey { &self.session.signing }
    fn sign(&self, message: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        self.permit.check().map_err(|_|kagitaba_store::Error::Signing)?;
        let signature = self.session.sign(message).map_err(|_|kagitaba_store::Error::Signing)?;
        self.permit.check().map_err(|_|kagitaba_store::Error::Signing)?;
        Ok(signature)
    }
}
pub enum Command {
    Scan,
    InspectKey(Device, Zeroizing<String>),
    UsePreparedKey(Slots),
    ProvisionPrepared(Slots, Policies, Zeroizing<String>),
    Unlock(Device, Slots, Zeroizing<String>),
    Lock,
    Close,
    DiscardImport,
    PreviewCopy(PathBuf, Vec<EntryId>),
    CopyEntries(Vec<KeyId>, bool),
    UnlockCopy(Device, Slots, Zeroizing<String>),
    ScanCopyDevices,
    DiscardCopy,
    PreviewAccess(KeyId),
    ApplyAccess,
    DiscardAccess,
    PreviewDuplicates,
    DiscardDuplicates,
    DeleteDuplicates,
    RememberDevice,
    Create(PathBuf),
    Open(PathBuf, Option<String>),
    ExportParticipant(PathBuf),
    AddParticipant(PathBuf),
    Enroll(PublicKey, PublicKey),
    RemoveParticipant(KeyId),
    NameParticipant(KeyId, String),
    Preview(PathBuf, String, Option<Zeroizing<String>>, Option<PathBuf>, bool),
    Import(Vec<KeyId>, bool),
    Read(EntryId),
    AddFile(EntryId, [u8;32], PathBuf, FilePermit),
    RemoveFile(EntryId, [u8;32], EntryId, FilePermit),
    RenameFile(EntryId, [u8;32], EntryId, Zeroizing<String>, FilePermit),
    ExportFile(EntryId, [u8;32], EntryId, PathBuf, FilePermit),
    GatewayLogin(u64, EntryId, String),
    GatewayAccounts(u64, Box<crate::gateway_passkey::Request>, crate::gateway::Permit),
    GatewayPasskey {
        id: u64,
        request: Box<crate::gateway_passkey::Request>,
        selected: Option<(EntryId, String)>,
        pin: Zeroizing<String>,
        permit: crate::gateway::Permit,
    },
    Titles,
    Save(EntryId, Zeroizing<String>, Vec<KeyId>),
    Delete(EntryId),
    Grant(EntryId, Vec<KeyId>),
    Pull(PathBuf),
    Merge(PathBuf),
    MergeOrigin,
    PullRemote(String),
    MergeRemote(String),
    Remote(crate::remote::Action),
    Backup(PathBuf),
}
pub enum Event {
    Policies(Option<KeyPolicy>, Option<KeyPolicy>),
    PrivateOperation(PrivateOperation),
    CopyPreview(CopyPreview),
    Copied,
    AccessPreview(access::AccessPreview),
    DuplicatePreview(duplicates::DuplicatePreview),
    GatewayLogin(u64, Zeroizing<String>),
    GatewayAccounts(u64, Vec<crate::gateway_passkey::Account>),
    Devices(Vec<Device>),
    KeyInspected(Vec<u8>),
    DeviceHints(BTreeMap<KeyId, DeviceHint>),
    ParticipantNames(BTreeMap<KeyId, String>),
    ParticipantNamesUnavailable,
    Unlocked(String),
    Locked,
    LockComplete,
    Closed,
    Wallet {
        path: PathBuf,
        entries: Vec<EntryId>,
        participants: Vec<KeyId>,
        head: String,
    },
    Trust(PathBuf, String),
    Participant(PublicKey, PublicKey),
    Preview(ImportPreview),
    Entry(EntryId, Zeroizing<String>, Vec<KeyId>, [u8;32]),
    Titles(Vec<(EntryId, Zeroizing<String>)>),
    SearchTerms(Vec<(EntryId, Zeroizing<String>)>),
    IndexRows {
        head: String,
        participant: KeyId,
        rows: BTreeMap<EntryId, kagitaba_store::index::Row>,
    },
    IndexWarning(&'static str),
    Done(std::result::Result<(), String>),
    Remote(crate::remote::Report),
}
pub fn start(ctx: eframe::egui::Context) -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel();
    let (events, out) = mpsc::channel();
    std::thread::spawn(move || {
        let remote = crate::remote::start(ctx.clone(), events.clone());
        let mut worker = Worker {
            ctx: ctx.clone(),
            session: None,
            prepared: None,
            index: None,
            session_device: None,
            store: None,
            pending: None,
            pending_duplicates: None,
            pending_access: None,
            pending_copy: None,
        };
        while let Ok(command) = rx.recv() {
            if let Command::Remote(action) = command {
                if let Some(store) = &worker.store {
                    let _ = remote.send(crate::remote::Request {
                        path: store.path.clone(),
                        root: store.root_signer.clone(),
                        checkpoint: store.head.to_string(),
                        action,
                    });
                }
                continue;
            }
            let action = match &command {
                Command::Create(_) => "Create wallet: ",
                Command::Open(_, _) => "Open wallet: ",
                Command::Backup(_) => "Backup wallet: ",
                Command::Pull(_) => "Pull wallet: ",
                Command::Merge(_) | Command::MergeOrigin | Command::MergeRemote(_) => "Merge wallet: ",
                Command::PullRemote(_) => "Pull remote wallet: ",
                _ => "",
            };
            let before = worker.store.as_ref().map(|store| (store.path.clone(),store.head.to_string()));
            let result = worker
                .run(command, &events)
                .map_err(|e| format!("{action}{e}"));
            if result.is_err() && let Some(store) = &worker.store
                && let Some(event) = post_error_wallet_event(before.as_ref(), &store.path, &store.head.to_string(), &store.snapshot) {
                worker.pending_duplicates = None;
                worker.pending_access = None;
                // Persistence may have succeeded before checkpoint/UI publication
                // failed. Publish only authoritative nonsecret state; keep error.
                let _ = events.send(event);
            }
            if result.is_err() && worker.session.is_none() {
                let _ = events.send(Event::Locked);
                // A failed destination unlock retains the staged copy for retry.
                if let Ok(Some(preview)) = worker.copy_preview() {
                    let _ = events.send(Event::CopyPreview(preview));
                }
            }
            let _ = events.send(Event::Done(result));
            ctx.request_repaint();
        }
    });
    (tx, out)
}
fn post_error_wallet_event(before: Option<&(PathBuf, String)>, path: &Path, head: &str, snapshot: &Snapshot) -> Option<Event> {
    let (old_path, old_head) = before?;
    if old_path != path || old_head == head { return None; }
    Some(wallet_snapshot_event(path, head, snapshot))
}
fn wallet_snapshot_event(path:&Path,head:&str,snapshot:&Snapshot)->Event {
    Event::Wallet {path:path.to_owned(),head:head.to_owned(),entries:snapshot.wallet.entries().keys().filter(|id|!snapshot.is_metadata(id)).copied().collect(),participants:snapshot.wallet.participants().keys().copied().collect()}
}
struct Worker {
    ctx: eframe::egui::Context,
    index: Option<CachedIndex>,
    prepared: Option<(AuthenticatedPiv<Usb>, String)>,
    session: Option<Session<Usb>>,
    session_device: Option<DeviceHint>,
    store: Option<Store>,
    pending: Option<import_files::PendingImport>,
    pending_duplicates: Option<duplicates::PendingDuplicates>,
    pending_access: Option<access::PendingAccess>,
    pending_copy: Option<copy_workflow::PendingCopy>,
}
impl Worker {
    fn observe_session(&self, session: &mut Session<Usb>, events: &mpsc::Sender<Event>) -> Result<()> {
        events.send(Event::Policies(session.encryption_policy, session.signing_policy))?;
        let events = events.clone();
        let ctx = self.ctx.clone();
        session.set_observer(move |event| {
            let _ = events.send(Event::PrivateOperation(event));
            ctx.request_repaint();
        });
        Ok(())
    }
    fn run(&mut self, c: Command, events: &mpsc::Sender<Event>) -> Result<()> {
        if matches!(&c, Command::Lock | Command::Close | Command::Open(..) | Command::Unlock(..)) { self.pending_duplicates = None; self.pending_copy = None; self.pending_access = None; }
        match c {
            Command::Remote(_) => unreachable!("transport is dispatched separately"),
            Command::DiscardImport => self.pending = None,
            Command::PreviewCopy(path, ids) => self.preview_copy(path, ids, events)?,
            Command::CopyEntries(recipients, skip) => self.copy_entries(recipients, skip, events)?,
            Command::UnlockCopy(device, slots, pin) => self.unlock_copy(device, slots, pin, events)?,
            Command::ScanCopyDevices => self.scan_copy_devices(events)?,
            Command::DiscardCopy => self.pending_copy = None,
            Command::DiscardAccess => self.pending_access = None,
            Command::PreviewAccess(target) => {
                self.pending_access = None;
                let store = self.store.as_ref().ok_or("Open a wallet first")?;
                let session = self.session.as_ref().ok_or("Unlock a key first")?;
                let pending = block_on(access::PendingAccess::scan(&store.snapshot, &store.head.to_string(), target, &session.encryption, session))?;
                events.send(Event::AccessPreview(pending.preview()))?;
                self.pending_access = Some(pending);
            }
            Command::ApplyAccess => {
                let store = self.store.as_ref().ok_or("Open a wallet first")?;
                let session = self.session.as_ref().ok_or("Unlock a key first")?;
                let next = block_on(self.pending_access.as_ref().ok_or("Review access first")?.apply(&store.snapshot, &store.head.to_string(), &session.encryption, session))?;
                self.commit(next, "Grant participant access to readable entries")?;
                self.pending_access = None;
                self.wallet_event(events)?;
            }
            Command::DiscardDuplicates => self.pending_duplicates=None,
            Command::PreviewDuplicates => {
                self.pending_duplicates=None;
                let store=self.store.as_ref().ok_or("Open a wallet first")?;
                let session=self.session.as_ref().ok_or("Unlock a key first")?;
                let pending=block_on(duplicates::PendingDuplicates::scan(&store.snapshot,&store.head.to_string(),&session.encryption,session))?;
                events.send(Event::DuplicatePreview(pending.preview(&store.snapshot)))?;
                self.pending_duplicates=Some(pending);
            }
            Command::DeleteDuplicates => {
                let store=self.store.as_ref().ok_or("Open a wallet first")?;
                let session=self.session.as_ref().ok_or("Unlock a key first")?;
                let next=block_on(self.pending_duplicates.as_ref().ok_or("Review duplicates first")?.apply(&store.snapshot,&store.head.to_string(),&session.encryption,session))?;
                self.commit(next,"Delete exact duplicates")?;
                self.pending_duplicates=None;
                self.wallet_event(events)?;
            }
            Command::Close => {
                self.index = None;
                self.prepared = None;
                self.session = None;
                self.session_device = None;
                self.pending = None;
                self.store = None;
                events.send(Event::LockComplete)?;
                events.send(Event::Closed)?;
            }
            Command::Scan => {
                if self.session.is_some() {
                    return Err("Lock before refreshing USB devices".into());
                }
                self.prepared = None;
                events.send(Event::Devices(usb::devices()?))?;
            }
            Command::InspectKey(device, pin) => {
                self.index = None;
                self.prepared = None;
                self.session = None;
                self.session_device = None;
                let mut card = Piv::new(Usb::open(&device)?)?;
                let serial = card.serial_number()?.to_string();
                let mut card = AuthenticatedPiv::new(card, &pin)?;
                let slots = card.p256_slots()?;
                self.prepared = Some((card, serial));
                events.send(Event::KeyInspected(slots))?;
            }
            Command::UsePreparedKey(slots) => {
                let (card, serial) = self.prepared.take().ok_or("Verify the PIV PIN first")?;
                let session = card.use_slots(slots)?;
                self.prepared_session(session, serial, slots, events)?;
            }
            Command::ProvisionPrepared(slots, policies, management) => {
                let (card, serial) = self.prepared.take().ok_or("Verify the PIV PIN first")?;
                let key = Zeroizing::new(hex::decode(management.trim())?);
                events.send(Event::PrivateOperation(PrivateOperation::Started(None)))?;
                self.ctx.request_repaint();
                let result = card.provision_with_policies(slots, &key, policies);
                events.send(Event::PrivateOperation(PrivateOperation::Finished))?;
                let session = result?;
                self.prepared_session(session, serial, slots, events)?;
            }
            Command::Pull(path) => {
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                store.pull_from(&path)?;
                save_trust(store)?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::Merge(path) => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                let candidate = store.import_candidate(&path)?;
                merge_metadata(store, candidate, s)?;
                save_trust(store)?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::MergeOrigin => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                merge_metadata(store, store.origin_head()?, s)?;
                save_trust(store)?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::MergeRemote(head) => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                merge_metadata(store, kagitaba_store::parse_oid(&head)?, s)?;
                save_trust(store)?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::PullRemote(head) => {
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                store.accept(kagitaba_store::parse_oid(&head)?)?;
                save_trust(store)?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::Backup(path) => {
                self.store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .backup_to(&path)?;
            }
            Command::Lock => {
                self.index = None;
                self.prepared = None;
                self.session = None;
                self.session_device = None;
                self.pending = None;
                events.send(Event::LockComplete)?;
            }
            Command::Unlock(d, slots, pin) => {
                self.index = None;
                self.prepared = None;
                self.session = None;
                self.session_device = None;
                let mut card = Piv::new(Usb::open(&d)?)?;
                let hint = device_hint(&mut card, slots)?;
                let mut s = Session::unlock_with_slots(card, &pin, slots)?;
                if let (Some(store), Some(hint)) = (&self.store, &hint) {
                    verify_device_hint(&store.snapshot, hint, &s.encryption, &s.signing)?;
                }
                self.observe_session(&mut s, events)?;
                events.send(Event::Unlocked(s.encryption.id().to_string()))?;
                self.session_device = hint;
                self.session = Some(s);
            }
            Command::RememberDevice => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let hint = self
                    .session_device
                    .clone()
                    .ok_or("Device serial number unavailable")?;
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                remember_device(&mut next, hint, &s.encryption, &s.signing)?;
                self.commit(next, "Remember device slots")?;
                self.wallet_event(events)?;
            }
            Command::Create(path) => {
                self.index = None;
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let mut snapshot = Snapshot::empty(s.encryption.clone(), s.signing.clone())?;
                if let Some(hint) = &self.session_device {
                    remember_device(&mut snapshot, hint.clone(), &s.encryption, &s.signing)?;
                }
                refresh_index(&mut snapshot, s, &mut self.index)?;
                let store = Store::create(&path, snapshot, &Hardware(s))?;
                save_trust(&store)?;
                self.store = Some(store);
                self.wallet_event(events)?;
            }
            Command::Open(path, confirmed) => {
                self.index = None;
                let trust = trust_path(&path)?;
                let (root, checkpoint) = if trust.exists() {
                    let v: serde_json::Value = serde_json::from_slice(&fs::read(trust)?)?;
                    (
                        PublicKey::from_pem(v["root"].as_str().ok_or("Invalid trust record")?)?,
                        Some(kagitaba_store::parse_oid(
                            v["checkpoint"].as_str().ok_or("Invalid checkpoint")?,
                        )?),
                    )
                } else {
                    let root = Store::inspect_root(&path)?;
                    match confirmed {
                        None => {
                            events.send(Event::Trust(path, root.id().to_string()))?;
                            return Ok(());
                        }
                        Some(expected) if expected == root.id().to_string() => {}
                        _ => return Err("Genesis signer changed during confirmation".into()),
                    }
                    (root, None)
                };
                let store = Store::open(&path, root, checkpoint)?;
                save_trust(&store)?;
                self.store = Some(store);
                self.pending = None;
                self.wallet_event(events)?;
                if self.session.is_none() {
                    events.send(Event::Devices(usb::devices()?))?;
                }
            }
            Command::ExportParticipant(path) => {
                let s = self
                    .session
                    .as_ref()
                    .ok_or("Unlock the device to export its public keys")?;
                let bytes = serde_json::to_vec_pretty(
                    &serde_json::json!({"format":"kagitaba-participant-1","encryption":s.encryption.to_pem(),"signing":s.signing.to_pem()}),
                )?;
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                std::io::Write::write_all(&mut f, &bytes)?;
            }
            Command::AddParticipant(path) => {
                let v: serde_json::Value = serde_json::from_slice(&read_limited(&path, 131072)?)?;
                if v["format"] != "kagitaba-participant-1" {
                    return Err("Invalid participant file".into());
                }
                let enc =
                    PublicKey::from_pem(v["encryption"].as_str().ok_or("Missing encryption key")?)?;
                let sign =
                    PublicKey::from_pem(v["signing"].as_str().ok_or("Missing signing key")?)?;
                events.send(Event::Participant(enc, sign))?;
            }
            Command::Enroll(enc, sign) => {
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                if next.signers.contains_key(&enc.id()) {
                    return Err("Participant already exists".into());
                }
                next.signers.insert(enc.id(), sign);
                next.wallet = next.wallet.with_participant(enc.clone())?;
                next.provision_index_key(&enc, &mut rand::rngs::SysRng)?;
                self.commit(next, "Enroll participant")?;
                self.wallet_event(events)?;
            }
            Command::RemoveParticipant(id) => {
                let s = self
                    .session
                    .as_ref()
                    .ok_or("Unlock a remaining key first")?;
                if s.encryption.id() == id {
                    return Err("Use a different participant to revoke this device".into());
                }
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                if !next.signers.contains_key(&id) {
                    return Err("Unknown participant".into());
                }
                let mut entries = Vec::new();
                let removed_metadata = next.metadata.remove(&id);
                for entry in next.wallet.entries().values() {
                    if Some(entry.primary().entry_id()) == removed_metadata { continue; }
                    if entry.grants().contains_key(&id) {
                        if !entry.grants().contains_key(&s.encryption.id()) {
                            return Err("This key cannot rotate every affected entry. Grant it access first, or explicitly delete inaccessible entries.".into());
                        }
                        let recipients: Vec<_> = entry
                            .grants()
                            .keys()
                            .filter(|p| **p != id)
                            .map(|p| next.wallet.participants()[p].clone())
                            .collect();
                        if let Some((participant, _)) = next.metadata.iter().find(|(_, entry_id)| **entry_id == entry.primary().entry_id()) {
                            let payload = block_on(kagitaba_cxf::ParticipantMetadata::open(entry, *participant, &s.encryption, s))?;
                            entries.push(payload.seal(&recipients, &mut rand::rngs::SysRng)?);
                        } else {
                            let payload = block_on(Payload::open(entry, &s.encryption, s))?;
                            let owner = entry.primary().entry_id();
                            let (payload, blobs) = files::rekey_payload(payload, next.attachments.get(&owner))?;
                            if blobs.is_empty() { next.attachments.remove(&owner); } else { next.attachments.insert(owner, blobs); }
                            entries.push(payload.seal(&recipients, &mut rand::rngs::SysRng)?);
                        }
                    } else {
                        entries.push(entry.clone());
                    }
                }
                next.wallet = kagitaba_core::wallet::Wallet::from_parts(
                    next.wallet
                        .participants()
                        .iter()
                        .filter(|(p, _)| **p != id)
                        .map(|(_, p)| p.clone()),
                    entries,
                )?;
                next.signers.remove(&id);
                next.browsers.remove(&id);
                next.devices.remove(&id);
                next.names.remove(&id);
                next.index_keys.remove(&id);
                next.indexes.remove(&id);
                self.commit(next, "Revoke participant and rotate affected entries")?;
                self.wallet_event(events)?;
            }
            Command::NameParticipant(id, name) => {
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                if !next.wallet.participants().contains_key(&id) {
                    return Err("Unknown participant".into());
                }
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                block_on(next.name_participant(id, &name, &s.encryption, s, &mut rand::rngs::SysRng))?;
                self.commit(next, "Name participant")?;
                self.wallet_event(events)?;
            }
            Command::Preview(path, format, password, keyfile, save_original) => {
                self.session
                    .as_ref()
                    .ok_or("Unlock a key before importing")?;
                self.pending = None;
                let bytes = read_limited(&path, 32 * 1024 * 1024)?;
                let mut warnings = ImportWarnings::default();
                let mut source_attachments = Vec::new();
                let mut document: Document = match format.as_str() {
                    "Bitwarden" => {
                        let c = kagitaba_cxf::bitwarden::from_json(&bytes)?;
                        let (document, report, attachments) = c.into_parts();
                        warnings = conversion_summary(&report);
                        conversion_details(&report, &document, &mut warnings);
                        source_attachments = attachments;
                        document
                    }
                    "Firefox CSV" => {
                        let c = kagitaba_cxf::firefox::from_bytes(&bytes)?;
                        let (document, report, attachments) = c.into_parts();
                        warnings = conversion_summary(&report);
                        conversion_details(&report, &document, &mut warnings);
                        source_attachments = attachments;
                        document
                    }
                    "KeePass" => {
                        let key = keyfile
                            .as_ref()
                            .map(|p| read_limited(p, 1024 * 1024))
                            .transpose()?;
                        let c = kagitaba_cxf::keepass::from_bytes(
                            &bytes,
                            password.as_deref().map(String::as_str),
                            key.as_deref().map(|v| v.as_slice()),
                        )?;
                        let (document, report, attachments) = c.into_parts();
                        warnings = conversion_summary(&report);
                        conversion_details(&report, &document, &mut warnings);
                        source_attachments = attachments;
                        document
                    }
                    _ => Document::from_json(&bytes)?,
                };
                if save_original {
                    let (with_original, source) = import_files::with_original_file(document, &path, bytes)?;
                    document = with_original;
                    source_attachments.push(source);
                }
                let mut plan = document.plan_import(
                    &self
                        .store
                        .as_ref()
                        .ok_or("Open a wallet first")?
                        .snapshot
                        .wallet,
                    &mut rand::rngs::SysRng,
                )?;
                let title = path.file_stem().and_then(|name| name.to_str()).unwrap_or("Imported entries");
                plan.wrap_collection(title, &mut rand::rngs::SysRng)?;
                let mut pending = import_files::PendingImport::prepare(plan, source_attachments)?;
                if save_original { pending.report.accounts = pending.report.accounts.saturating_sub(1); }
                let store = self.store.as_ref().ok_or("Open a wallet first")?;
                let session = self.session.as_ref().ok_or("Unlock a key first")?;
                block_on(pending.scan_existing(&store.snapshot, &store.head.to_string(), &session.encryption, session))?;
                if format == "KeePass" && pending.file_count > 0 {
                    warnings.omitted.remove("Items with attachment bytes not imported");
                }
                events.send(Event::Preview(pending.preview(warnings)?))?;
                self.pending = Some(pending);
            }
            Command::Import(ids, skip_existing) => {
                let store = self.store.as_ref().ok_or("Open a wallet first")?;
                let session = self.session.as_ref().ok_or("Unlock a key first")?;
                let next = block_on(self.pending.as_ref().ok_or("Preview an import first")?
                    .apply(&store.snapshot, &store.head.to_string(), &ids, skip_existing, &session.encryption, session))?;
                self.commit(next, "Import entries")?;
                self.pending = None;
                self.wallet_event(events)?;
            }
            Command::GatewayAccounts(id, request, permit) => {
                let session = self.session.as_ref().ok_or("Unlock a key first")?;
                let snapshot = &self.store.as_ref().ok_or("Open a wallet first")?.snapshot;
                let accounts = block_on(crate::gateway_passkey::accounts_with_index(snapshot, &session.encryption, session, &request, &permit,
                    self.index.as_ref().filter(|cache| cache.participant == session.encryption.id()).map(|cache| &cache.index)))?;
                events.send(Event::GatewayAccounts(id, accounts))?;
            }
            Command::GatewayPasskey {id, request, selected, pin, permit} => {
                permit.check()?;
                let verification = self.session.as_ref().ok_or("Unlock a key first")?.verify_pin(&pin);
                if let Err(error) = verification {
                    // One attempt only. Clear the session; never reuse cached authorization after a failed PIN.
                    self.session = None;
                    self.index = None;
                    self.session_device = None;
                    events.send(Event::GatewayLogin(id, crate::gateway::denied()))?;
                    return Err(error.into());
                }
                let result = (|| -> Result<Zeroizing<String>> {
                    permit.check()?;
                    let session = self.session.as_ref().ok_or("Unlock a key first")?;
                    let store = self.store.as_mut().ok_or("Open a wallet first")?;
                    if request.create {
                        let (mut next, response) = block_on(crate::gateway_passkey::registration(&store.snapshot, &session.encryption, session, &request, &permit))?;
                        next.prune_legacy(&mut rand::rngs::SysRng)?;
                        block_on(next.complete_metadata_grants(&session.encryption, session, &mut rand::rngs::SysRng))?;
                        refresh_index_for_write(&mut next, session, &mut self.index);
                        permit.check()?;
                        store.save(next, &GatewaySigner {session, permit: &permit}, "Register browser passkey")?;
                        save_trust(store)?;
                        permit.check()?;
                        Ok(response)
                    } else {
                        let (entry, credential) = selected.ok_or("Choose a passkey first")?;
                        Ok(block_on(crate::gateway_passkey::assertion(&store.snapshot, &session.encryption, session, &request, (entry, &credential), &permit))?)
                    }
                })();
                match result {
                    Ok(response) => { events.send(Event::GatewayLogin(id, response))?; },
                    Err(error) => {
                        events.send(Event::GatewayLogin(id, crate::gateway::denied()))?;
                        // A completed signed write remains authoritative even if cancellation suppressed its response.
                        if request.create { self.wallet_event(events)?; }
                        return Err(error);
                    }
                }
                // Deliver the authorized response before our own snapshot notification clears pending UI state.
                if request.create { self.wallet_event(events)?; }
            }
            Command::GatewayLogin(request, id, origin) => {
                let response = (|| -> Result<Zeroizing<String>> {
                    let s = self.session.as_ref().ok_or("Unlock a key first")?;
                    let snapshot = &self.store.as_ref().ok_or("Open a wallet first")?.snapshot;
                    if snapshot.is_metadata(&id) { return Err("Not a credential".into()); }
                    let entry = snapshot.wallet.entries().get(&id).ok_or("Missing entry")?;
                    let payload = block_on(Payload::open(entry, &s.encryption, s))?;
                    let json = payload.to_json()?;
                    crate::gateway::login(std::str::from_utf8(&json)?, &origin).ok_or("No matching login".into())
                })().unwrap_or_else(|_| crate::gateway::denied());
                events.send(Event::GatewayLogin(request, response))?;
            }
            Command::Read(id) => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let entry = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .wallet
                    .entries()
                    .get(&id)
                    .ok_or("Missing entry")?;
                let p = block_on(Payload::open(entry, &s.encryption, s))?;
                files::validate(&self.store.as_ref().ok_or("Open a wallet first")?.snapshot, id, &p)?;
                events.send(Event::Entry(
                    id,
                    Zeroizing::new(String::from_utf8(p.to_json()?.to_vec())?),
                    entry.grants().keys().copied().collect(),
                    entry.primary().digest(),
                ))?;
            }
            Command::AddFile(id, digest, path, permit) => {
                self.file_add(id, digest, &path, &permit)?;
                self.wallet_event(events)?;
            }
            Command::RenameFile(id, digest, attachment, name, permit) => {
                self.file_rename(id, digest, attachment, &name, &permit)?;
                self.wallet_event(events)?;
            }
            Command::RemoveFile(id, digest, attachment, permit) => {
                self.file_remove(id, digest, attachment, &permit)?;
                self.wallet_event(events)?;
            }
            Command::ExportFile(id, digest, attachment, path, permit) => {
                self.file_export(id, digest, attachment, &path, &permit)?;
            }
            Command::Titles => {
                self.session.as_ref().ok_or("Unlock a key first")?;
                self.wallet_event(events)?;
            }
            Command::Save(id, json, ids) => {
                let mut p = Payload::from_json(id, json.as_bytes())?;
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                let unique: BTreeSet<_> = ids.into_iter().collect();
                if let Some(previous) = next.wallet.entries().get(&id) {
                    let session = self.session.as_ref().ok_or("Unlock a key first")?;
                    let old = block_on(Payload::open(previous, &session.encryption, session))?;
                    p = files::prepare_edit(&mut next, id, &old, p, &unique)?;
                } else {
                    kagitaba_cxf::attachments::validate_blobs(&p, &Default::default())?;
                }
                let keys: Vec<_> = unique
                    .iter()
                    .map(|id| {
                        next.wallet
                            .participants()
                            .get(id)
                            .cloned()
                            .ok_or("Unknown participant")
                    })
                    .collect::<std::result::Result<_, _>>()?;
                let entry = p.seal(&keys, &mut rand::rngs::SysRng)?;
                next.wallet = next.wallet.with_entry(entry)?;
                self.commit(next, "Update entry")?;
                self.wallet_event(events)?;
            }
            Command::Delete(id) => {
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                next.wallet = next.wallet.without_entry(id)?;
                next.attachments.remove(&id);
                self.commit(next, "Delete entry")?;
                self.wallet_event(events)?;
            }
            Command::Grant(id, recipients) => {
                use kagitaba_core::{crypto::WrappedKey, wallet::GrantRecord};
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                let entry = next.wallet.entries().get(&id).ok_or("Missing entry")?;
                let grant = entry
                    .grants()
                    .get(&s.encryption.id())
                    .ok_or("This device has no grant")?;
                let key = block_on(WrappedKey::from_bytes(grant.body())?.unwrap(
                    &s.encryption,
                    &entry.primary().grant_context(s.encryption.id()),
                    s,
                ))?;
                let mut updated = entry.clone();
                for id in recipients {
                    if updated.grants().contains_key(&id) {
                        continue;
                    }
                    let public = next
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
                self.commit(next, "Grant entry access")?;
                self.wallet_event(events)?;
            }
        }
        Ok(())
    }
    fn prepared_session(&mut self, mut session: Session<Usb>, serial: String, slots: Slots, events: &mpsc::Sender<Event>) -> Result<()> {
        self.observe_session(&mut session, events)?;
        let hint = DeviceHint { serial, encryption_slot: slots.encryption(), signing_slot: slots.signing() };
        hint.validate()?;
        if let Some(store) = &self.store {
            verify_device_hint(&store.snapshot, &hint, &session.encryption, &session.signing)?;
        }
        events.send(Event::Unlocked(session.encryption.id().to_string()))?;
        self.session_device = Some(hint);
        self.session = Some(session);
        Ok(())
    }
    fn commit(&mut self, mut next: Snapshot, message: &str) -> Result<()> {
        let s = self.session.as_ref().ok_or("Unlock a key first")?;
        let store = self.store.as_mut().ok_or("Open a wallet first")?;
        next.prune_legacy(&mut rand::rngs::SysRng)?;
        block_on(next.complete_metadata_grants(&s.encryption, s, &mut rand::rngs::SysRng))?;
        refresh_index_for_write(&mut next, s, &mut self.index);
        store.save(next, &Hardware(s), message)?;
        save_trust(store)?;
        Ok(())
    }
    fn wallet_event(&mut self, events: &mpsc::Sender<Event>) -> Result<()> {
        self.pending_access = None;
        self.pending_duplicates=None;
        let mut warning = None;
        if let Some(session) = &self.session {
            let store = self.store.as_mut().ok_or("No wallet")?;
            if store.snapshot.wallet.participants().contains_key(&session.encryption.id()) {
                let mut next = store.snapshot.clone();
                match refresh_index(&mut next, session, &mut self.index) {
                    Ok(true) => {
                        if store.save(next, &Hardware(session), "Refresh participant index").and_then(|_| {
                            save_trust(store).map_err(|_| kagitaba_store::Error::Io)
                        }).is_err() {
                            warning = Some("Index refresh could not be saved.");
                        }
                    }
                    Ok(false) => {},
                    Err(_) => { self.index = None; warning = Some("Index unavailable; showing readable entries."); },
                }
            } else {
                self.index = None;
            }
        }
        let s = self.store.as_ref().ok_or("No wallet")?;
        events.send(Event::Wallet {
            path: s.path.clone(),
            entries: s.snapshot.wallet.entries().keys().filter(|id| !s.snapshot.is_metadata(id)).copied().collect(),
            participants: s.snapshot.wallet.participants().keys().copied().collect(),
            head: s.head.to_string(),
        })?;
        events.send(Event::DeviceHints(s.snapshot.devices.clone()))?;
        if let Some(session) = &self.session {
            let event = match block_on(s.snapshot.participant_names(&session.encryption, session)) {
                Ok(names) => Event::ParticipantNames(names),
                Err(_) => Event::ParticipantNamesUnavailable,
            };
            events.send(event)?;
        }
        if let Some(cached) = &self.index {
            if let Some(session) = &self.session
                && cached.index.is_current(&s.snapshot, session.encryption.id())
            {
                events.send(Event::IndexRows {
                    head: s.head.to_string(),
                    participant: session.encryption.id(),
                    rows: cached.index.rows().clone(),
                })?;
            }
            events.send(Event::Titles(cached.index.rows().iter().map(|(id, row)| (*id, Zeroizing::new(row.title.clone()))).collect()))?;
            events.send(Event::SearchTerms(cached.index.rows().iter().map(|(id, row)| {
                let mut terms = Zeroizing::new(row.title.to_lowercase());
                for value in row.usernames.iter().chain(&row.scopes) {
                    terms.push('\n');
                    terms.push_str(&value.to_lowercase());
                }
                (*id, terms)
            }).collect()))?;
        } else if let Some(session) = &self.session {
            let mut titles = Vec::new();
            for (id, entry) in s.snapshot.wallet.entries() {
                if s.snapshot.is_metadata(id) || !entry.grants().contains_key(&session.encryption.id()) { continue; }
                if let Ok(payload) = block_on(Payload::open(entry, &session.encryption, session)) {
                    titles.push((*id, Zeroizing::new(payload.entity()["title"].as_str().unwrap_or("Untitled").to_owned())));
                }
            }
            events.send(Event::Titles(titles))?;
        }
        if let Some(warning) = warning {
            events.send(Event::IndexWarning(warning))?;
        }
        Ok(())
    }
}

struct CachedIndex {
    participant: KeyId,
    wrapped: Vec<u8>,
    key: ContentKey,
    index: kagitaba_store::index::Index,
}
fn refresh_index_for_write(snapshot: &mut Snapshot, session: &Session<Usb>, cached: &mut Option<CachedIndex>) {
    refresh_index_for_write_with(snapshot, &session.encryption, session, cached);
}
fn refresh_index_for_write_with(snapshot: &mut Snapshot, recipient: &PublicKey, backend: &impl kagitaba_core::crypto::KeyAgreement, cached: &mut Option<CachedIndex>) {
    if refresh_index_with(snapshot, recipient, backend, cached).is_err() {
        *cached = None;
        snapshot.indexes.remove(&recipient.id());
    }
}
/// Refresh only new/changed accessible rows. The key survives cache invalidation;
/// corrupt disposable ciphertext is rebuilt, but a bad key wrapper is an error.
fn refresh_index(snapshot: &mut Snapshot, session: &Session<Usb>, cached: &mut Option<CachedIndex>) -> Result<bool> {
    refresh_index_with(snapshot, &session.encryption, session, cached)
}
fn refresh_index_with(snapshot: &mut Snapshot, recipient: &PublicKey, backend: &impl kagitaba_core::crypto::KeyAgreement, cached: &mut Option<CachedIndex>) -> Result<bool> {
    let participant = recipient.id();
    let old = cached.take().filter(|state| state.participant == participant
        && snapshot.index_keys.get(&participant) == Some(&state.wrapped));
    let mut changed = false;
    let (key, previous) = if let Some(old) = old {
        (old.key, Some(old.index))
    } else {
        let key = match snapshot.provision_index_key(recipient, &mut rand::rngs::SysRng)? {
            Some(key) => {changed = true; key},
            None => block_on(snapshot.open_index_key(recipient, backend))?,
        };
        let previous = snapshot.indexes.get(&participant)
            .and_then(|bytes| kagitaba_store::index::Index::open(bytes, &key, participant).ok());
        (key, previous)
    };
    let index = match previous {
        Some(previous) if previous.is_current(snapshot, participant) => previous,
        previous => block_on(kagitaba_store::index::Index::refresh(snapshot, recipient, backend, previous.as_ref()))?,
    };
    let bytes = index.seal(&key, participant)?;
    if snapshot.indexes.get(&participant) != Some(&bytes) {
        snapshot.indexes.insert(participant, bytes);
        changed = true;
    }
    *cached = Some(CachedIndex { participant, wrapped: snapshot.index_keys[&participant].clone(), key, index });
    Ok(changed)
}

fn merge_metadata(store: &mut Store, candidate: kagitaba_store::ObjectId, session: &Session<Usb>) -> Result<()> {
    store.merge_then(candidate, &Hardware(session), |next| {
        let legacy = !next.names.is_empty() || !next.browsers.is_empty();
        next.prune_legacy(&mut rand::rngs::SysRng)?;
        Ok(block_on(next.complete_metadata_grants(&session.encryption, session, &mut rand::rngs::SysRng))? || legacy)
    })?;
    Ok(())
}
#[derive(Default)]
pub struct ImportPreview {
    pub report: kagitaba_cxf::ImportReport,
    pub warnings: ImportWarnings,
    pub entries: Vec<import_preview::PreviewEntry>,
    pub imported_files: usize,
    pub existing_duplicates: usize,
    pub duplicate_differences: BTreeMap<&'static str, usize>,
    pub unavailable_entries: usize,
}

impl ImportPreview {
    #[cfg(feature = "smoke")]
    pub fn from_plan(plan: &ImportPlan, warnings: ImportWarnings) -> Result<Self> {
        Ok(Self {
            report: plan.report(), warnings, imported_files: 0, existing_duplicates: 0, unavailable_entries: 0, duplicate_differences: BTreeMap::new(),
            entries: plan.entries().iter().map(import_preview::PreviewEntry::from_payload).collect::<Result<_>>()?,
        })
    }
}

#[derive(Default)]
pub struct ImportWarnings {
    pub details: Vec<ImportDiagnostic>,
    pub retained: BTreeMap<&'static str, usize>,
    pub omitted: BTreeMap<&'static str, usize>,
    pub review: BTreeMap<&'static str, usize>,
}

pub struct ImportDiagnostic {
    pub source_id: Zeroizing<String>,
    pub entry_index: Option<usize>,
    pub detail: kagitaba_cxf::WarningDetail,
}

fn conversion_details(report: &kagitaba_cxf::ConversionReport, document: &Document, warnings: &mut ImportWarnings) {
    let items: Vec<_> = document.as_json()["accounts"].as_array().into_iter().flatten()
        .flat_map(|account| account["items"].as_array().into_iter().flatten()).collect();
    for warning in &report.warnings {
        if let Some(detail) = warning.detail {
            let source_id = warning.item_index.and_then(|index| items.get(index))
                .and_then(|item| item["id"].as_str()).unwrap_or("");
            warnings.details.push(ImportDiagnostic {
                source_id: Zeroizing::new(source_id.to_owned()), entry_index: None, detail,
            });
        }
    }
}

fn conversion_summary(report: &kagitaba_cxf::ConversionReport) -> ImportWarnings {
    use kagitaba_cxf::WarningKind;
    let mut result = ImportWarnings::default();
    for warning in &report.warnings {
        let (group, label) = match warning.kind {
            WarningKind::OpaqueItem => (&mut result.retained, "Unsupported items: source data only"),
            WarningKind::OpaqueOtp => (&mut result.retained, "Unsupported one-time codes: source data only"),
            WarningKind::OpaquePasskey => (&mut result.retained, "Unsupported passkeys: source data only"),
            WarningKind::OpaqueField => (&mut result.retained, "Unsupported fields: source data only"),
            WarningKind::History => (&mut result.retained, "Old credential history: encrypted source data"),
            WarningKind::Timestamp => (&mut result.retained, "Unmapped source timestamps"),
            WarningKind::Attachments => (&mut result.omitted, "Items with attachment bytes not imported"),
            WarningKind::Deleted => (&mut result.omitted, "Trash entries"),
            WarningKind::UriPolicy => (&mut result.review, "URL matching rules retained but inactive"),
            WarningKind::MissingCollection => (&mut result.review, "Missing source collections"),
            WarningKind::Reprompt => (&mut result.review, "Additional authentication prompts not implemented"),
            WarningKind::FieldReferences => (&mut result.review, "Field references retained literally"),
        };
        *group.entry(label).or_default() += 1;
    }
    result
}

fn device_hint(card: &mut Piv<Usb>, slots: Slots) -> Result<Option<DeviceHint>> {
    let serial = card.serial_number()?.to_string();
    let hint = DeviceHint {
        serial,
        encryption_slot: slots.encryption(),
        signing_slot: slots.signing(),
    };
    hint.validate()?;
    Ok(Some(hint))
}

fn verify_device_hint(
    snapshot: &Snapshot,
    hint: &DeviceHint,
    encryption: &PublicKey,
    signing: &PublicKey,
) -> Result<()> {
    for (id, recorded) in &snapshot.devices {
        if recorded == hint && (*id != encryption.id() || snapshot.signers.get(id) != Some(signing))
        {
            return Err("Device keys do not match the wallet's recorded participant".into());
        }
    }
    Ok(())
}

fn remember_device(
    snapshot: &mut Snapshot,
    hint: DeviceHint,
    encryption: &PublicKey,
    signing: &PublicKey,
) -> Result<()> {
    if snapshot.wallet.participants().get(&encryption.id()) != Some(encryption)
        || snapshot.signers.get(&encryption.id()) != Some(signing)
    {
        return Err("Enroll this key's public participant before remembering its slots".into());
    }
    hint.validate()?;
    verify_device_hint(snapshot, &hint, encryption, signing)?;
    snapshot.devices.insert(encryption.id(), hint);
    Ok(())
}

fn read_limited(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("File exceeds size limit".into());
    }
    Ok(bytes)
}
fn trust_path(path: &Path) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .ok_or("No data directory")?;
    let canonical = fs::canonicalize(path)?;
    Ok(base.join("kagitaba/trust").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()))
    )))
}
/// Serialize app instances so local checkpoint files cannot race one another.
pub fn instance_lock() -> Result<fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .ok_or("No data directory")?
        .join("kagitaba");
    fs::create_dir_all(&base)?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(base.join("instance.lock"))?;
    f.try_lock().map_err(|_| "Kagitaba is already running")?;
    Ok(f)
}
fn save_trust(store: &Store) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = trust_path(&store.path)?;
    let parent = path.parent().ok_or("Invalid trust path")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(
        &serde_json::json!({"root":store.root_signer.to_pem(),"checkpoint":store.head.to_string()}),
    )?)?;
    file.sync_all()?;
    fs::rename(temp, &path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod device_tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;

    #[test]
    fn serial_and_slots_never_replace_public_key_identity() {
        let enc = SoftwareIdentity::from_bytes(&[1; 32]).unwrap().public_key();
        let sign = SoftwareIdentity::from_bytes(&[2; 32]).unwrap().public_key();
        let wrong = SoftwareIdentity::from_bytes(&[3; 32]).unwrap().public_key();
        let hint = DeviceHint {
            serial: "123456".into(),
            encryption_slot: 0x94,
            signing_slot: 0x95,
        };
        let mut snapshot = Snapshot::empty(enc.clone(), sign.clone()).unwrap();
        assert!(remember_device(&mut snapshot, hint.clone(), &wrong, &sign).is_err());
        assert!(remember_device(&mut snapshot, hint.clone(), &enc, &wrong).is_err());
        assert!(snapshot.devices.is_empty());
        remember_device(&mut snapshot, hint.clone(), &enc, &sign).unwrap();
        assert!(verify_device_hint(&snapshot, &hint, &enc, &sign).is_ok());
        assert!(verify_device_hint(&snapshot, &hint, &wrong, &sign).is_err());
        assert!(verify_device_hint(&snapshot, &hint, &enc, &wrong).is_err());
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;
    use std::cell::Cell;
    use kagitaba_core::crypto::{AgreementRequest, AgreementSecret, KeyAgreement, SoftwareIdentity};
    struct Counting { identity: SoftwareIdentity, calls: Cell<usize>, deny: Cell<bool> }
    impl KeyAgreement for Counting {
        fn key_id(&self) -> KeyId { self.identity.public_key().id() }
        async fn agree(&self, request: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
            self.calls.set(self.calls.get() + 1);
            if self.deny.get() { return Err(kagitaba_core::Error::KeyUnavailable); }
            self.identity.agree(request).await
        }
    }
    fn fixture() -> (Counting, Snapshot) {
        use base64::Engine;
        let backend=Counting {identity:SoftwareIdentity::from_bytes(&[31;32]).unwrap(),calls:Cell::new(0),deny:Cell::new(false)};
        let recipient=backend.identity.public_key();
        let mut snapshot=Snapshot::empty(recipient.clone(),recipient.clone()).unwrap();
        let id=EntryId::from_bytes([11;16]);
        let payload=Payload::new(id,kagitaba_cxf::PayloadKind::Item,&serde_json::to_vec(&serde_json::json!({
            "id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes()),"title":"Fixture","credentials":[]
        })).unwrap()).unwrap();
        snapshot.wallet=snapshot.wallet.with_entry(payload.seal(&[recipient],&mut rand::rngs::SysRng).unwrap()).unwrap();
        (backend,snapshot)
    }
    #[test]
    fn reopen_unwraps_once_and_unchanged_refresh_never_requests_another_commit() {
        let (backend,mut snapshot)=fixture();
        let recipient=backend.identity.public_key();
        let mut cache=None;
        assert!(refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(backend.calls.get(),1); // Initial key generated locally; only entry decrypted.
        let wrapper=snapshot.index_keys[&recipient.id()].clone();
        let bytes=snapshot.indexes[&recipient.id()].clone();
        assert!(!refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(backend.calls.get(),1);
        cache=None; // A fresh unlock/reopen has no retained index key or plaintext rows.
        assert!(!refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(backend.calls.get(),2); // One key unwrap, no entry decryption.
        assert_eq!(snapshot.index_keys[&recipient.id()],wrapper);
        assert_eq!(snapshot.indexes[&recipient.id()],bytes);
        snapshot.indexes.insert(recipient.id(),vec![0]);
        cache=None;
        assert!(refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(backend.calls.get(),4); // Corrupt ciphertext rebuild: key plus entry.
        assert_eq!(snapshot.index_keys[&recipient.id()],wrapper);
        assert_eq!(snapshot.indexes[&recipient.id()],bytes);
        assert!(!refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(backend.calls.get(),4);
    }
    #[test]
    fn cache_failure_keeps_authoritative_keys_and_does_not_block_a_write() {
        let (backend,mut snapshot)=fixture();
        let recipient=backend.identity.public_key();
        let mut cache=None;
        refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap();
        let wrapper=snapshot.index_keys[&recipient.id()].clone();
        let primary=snapshot.wallet.entries()[&EntryId::from_bytes([11;16])].primary().clone();
        cache=None;
        backend.deny.set(true);
        // The normal write path deliberately treats this error as cache invalidation.
        refresh_index_for_write_with(&mut snapshot,&recipient,&backend,&mut cache);
        assert!(cache.is_none());
        assert!(!snapshot.indexes.contains_key(&recipient.id()));
        assert_eq!(snapshot.index_keys[&recipient.id()],wrapper);
        assert_eq!(snapshot.wallet.entries()[&EntryId::from_bytes([11;16])].primary(),&primary);
        snapshot.validate().unwrap(); // Remains a valid candidate for the caller's signed save.
        backend.deny.set(false);
        assert!(refresh_index_with(&mut snapshot,&recipient,&backend,&mut cache).unwrap());
        assert_eq!(snapshot.index_keys[&recipient.id()],wrapper);
    }
}

#[cfg(test)]
mod import_preview_tests {
    use super::*;
    #[test]
    fn conversion_warnings_are_grouped_by_preservation_behavior() {
        use kagitaba_cxf::{ConversionReport, ImportWarning, WarningKind};
        let report = ConversionReport {
            warnings: [WarningKind::History, WarningKind::OpaquePasskey, WarningKind::Attachments,
                WarningKind::Deleted, WarningKind::Reprompt, WarningKind::Reprompt]
                .into_iter().map(|kind| ImportWarning { item_index: Some(0), kind, detail: None }).collect(),
            ..Default::default()
        };
        let warnings = conversion_summary(&report);
        assert_eq!(warnings.retained.values().sum::<usize>(), 2);
        assert_eq!(warnings.omitted.values().sum::<usize>(), 2);
        assert_eq!(warnings.review.values().sum::<usize>(), 2);
        assert_eq!(warnings.review.len(), 1);
        let empty = conversion_summary(&ConversionReport::default());
        assert!(empty.retained.is_empty() && empty.omitted.is_empty() && empty.review.is_empty());
    }
}

#[cfg(test)]
mod post_commit_publication_tests {
    use super::*;
    #[test]
    fn failed_checkpoint_publishes_deleted_entry_state_only_for_same_changed_wallet() {
        use kagitaba_core::crypto::SoftwareIdentity;
        let key = SoftwareIdentity::from_bytes(&[19; 32]).unwrap();
        let mut snapshot = Snapshot::empty(key.public_key(), key.public_key()).unwrap();
        let id = EntryId::from_bytes([42; 16]);
        let payload = Payload::new(id, kagitaba_cxf::PayloadKind::Item, br#"{"id":"KioqKioqKioqKioqKioqKg","title":"synthetic","credentials":[]}"#).unwrap();
        snapshot.wallet = snapshot.wallet.with_entry(payload.seal(&[key.public_key()], &mut rand::rngs::SysRng).unwrap()).unwrap();
        snapshot.wallet = snapshot.wallet.without_entry(id).unwrap();
        let before = (PathBuf::from("/synthetic-wallet"), "old-head".to_owned());
        let event = post_error_wallet_event(Some(&before), &before.0, "saved-head", &snapshot).unwrap();
        let Event::Wallet { entries, head, .. } = event else { panic!("expected wallet state") };
        assert!(entries.is_empty());
        assert_eq!(head, "saved-head");
        assert!(post_error_wallet_event(Some(&before), &before.0, "old-head", &snapshot).is_none());
        assert!(post_error_wallet_event(Some(&before), Path::new("/another-wallet"), "saved-head", &snapshot).is_none());
        assert!(post_error_wallet_event(None, &before.0, "saved-head", &snapshot).is_none());
    }
}

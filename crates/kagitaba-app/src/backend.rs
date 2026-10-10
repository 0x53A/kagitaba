use futures::executor::block_on;
use kagitaba_core::{EntryId, KeyId, crypto::PublicKey};
use kagitaba_cxf::{Document, ImportPlan, Payload};
use kagitaba_device::{
    Piv, Session,
    usb::{self, Device, Usb},
};
use kagitaba_store::{Signer, Snapshot, Store};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
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
pub enum Command {
    Scan,
    Unlock(Device, Zeroizing<String>),
    Lock,
    Provision(Device, Zeroizing<String>, Zeroizing<String>),
    Create(PathBuf),
    Open(PathBuf, Option<String>),
    ExportParticipant(PathBuf),
    AddParticipant(PathBuf),
    Enroll(PublicKey, PublicKey),
    RemoveParticipant(KeyId),
    Preview(PathBuf, String, Option<Zeroizing<String>>, Option<PathBuf>),
    Import(Vec<KeyId>),
    Read(EntryId),
    Titles,
    Save(EntryId, Zeroizing<String>, Vec<KeyId>),
    Delete(EntryId),
    Grant(EntryId, Vec<KeyId>),
    Pull(PathBuf),
    Backup(PathBuf),
}
pub enum Event {
    Devices(Vec<Device>),
    Unlocked(String),
    Locked,
    LockComplete,
    Wallet {
        path: PathBuf,
        entries: Vec<EntryId>,
        participants: Vec<KeyId>,
        head: String,
    },
    Trust(PathBuf, String),
    Participant(PublicKey, PublicKey),
    Preview(String),
    Entry(EntryId, Zeroizing<String>, Vec<KeyId>),
    Titles(Vec<(EntryId, Zeroizing<String>)>),
    Done(std::result::Result<(), String>),
}
pub fn start(ctx: eframe::egui::Context) -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel();
    let (events, out) = mpsc::channel();
    std::thread::spawn(move || {
        let mut worker = Worker {
            session: None,
            store: None,
            pending: None,
        };
        while let Ok(command) = rx.recv() {
            let result = worker.run(command, &events).map_err(|e| e.to_string());
            if result.is_err() && worker.session.is_none() {
                let _ = events.send(Event::Locked);
            }
            let _ = events.send(Event::Done(result));
            ctx.request_repaint();
        }
    });
    (tx, out)
}
struct Worker {
    session: Option<Session<Usb>>,
    store: Option<Store>,
    pending: Option<ImportPlan>,
}
impl Worker {
    fn run(&mut self, c: Command, events: &mpsc::Sender<Event>) -> Result<()> {
        match c {
            Command::Scan => events.send(Event::Devices(usb::devices()?))?,
            Command::Pull(path) => {
                let store = self.store.as_mut().ok_or("Open a wallet first")?;
                store.pull_from(&path)?;
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
                self.session = None;
                self.pending = None;
                events.send(Event::LockComplete)?;
            }
            Command::Unlock(d, pin) => {
                self.session = None;
                let s = Session::unlock(Piv::new(Usb::open(&d)?)?, &pin)?;
                events.send(Event::Unlocked(s.encryption.id().to_string()))?;
                self.session = Some(s);
            }
            Command::Provision(d, management, pin) => {
                self.session = None;
                let mut card = Piv::new(Usb::open(&d)?)?;
                // Check both slots before authenticating or generating either key.
                for slot in [0x82, 0x83] {
                    match card.public_key(slot) {
                        Err(kagitaba_device::Error::Status(0x6a88)) => {}
                        Ok(_) => {
                            return Err("A Kagitaba slot is occupied; use Unlock instead".into());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                card.verify_pin(&pin)?;
                let key = Zeroizing::new(hex::decode(management.trim())?);
                card.authenticate_management(&key)?;
                card.generate_empty(0x82, true)?;
                card.generate_empty(0x83, false)?;
                let s = Session::unlock(card, &pin)?;
                events.send(Event::Unlocked(s.encryption.id().to_string()))?;
                self.session = Some(s);
            }
            Command::Create(path) => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let store = Store::create(
                    &path,
                    Snapshot::empty(s.encryption.clone(), s.signing.clone())?,
                    &Hardware(s),
                )?;
                save_trust(&store)?;
                self.store = Some(store);
                self.wallet_event(events)?;
            }
            Command::Open(path, confirmed) => {
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
                let v: serde_json::Value = serde_json::from_slice(&read_limited(&path, 16384)?)?;
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
                next.wallet = next.wallet.with_participant(enc)?;
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
                for entry in next.wallet.entries().values() {
                    if entry.grants().contains_key(&id) {
                        if !entry.grants().contains_key(&s.encryption.id()) {
                            return Err("This key cannot rotate every affected entry. Grant it access first, or explicitly delete inaccessible entries.".into());
                        }
                        let payload = block_on(Payload::open(entry, &s.encryption, s))?;
                        let recipients: Vec<_> = entry
                            .grants()
                            .keys()
                            .filter(|p| **p != id)
                            .map(|p| next.wallet.participants()[p].clone())
                            .collect();
                        entries.push(payload.seal(&recipients, &mut rand::rngs::SysRng)?);
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
                self.commit(next, "Revoke participant and rotate affected entries")?;
                self.wallet_event(events)?;
            }
            Command::Preview(path, format, password, keyfile) => {
                self.session
                    .as_ref()
                    .ok_or("Unlock a key before importing")?;
                self.pending = None;
                let bytes = read_limited(&path, 32 * 1024 * 1024)?;
                let mut warnings = String::new();
                let document: Document = match format.as_str() {
                    "Bitwarden" => {
                        let c = kagitaba_cxf::bitwarden::from_json(&bytes)?;
                        warnings = format!("\nConversion: {:?}", c.report());
                        c.into_document()
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
                        warnings = format!("\nConversion: {:?}", c.report());
                        c.into_document()
                    }
                    _ => Document::from_json(&bytes)?,
                };
                let plan = document.plan_import(
                    &self
                        .store
                        .as_ref()
                        .ok_or("Open a wallet first")?
                        .snapshot
                        .wallet,
                    &mut rand::rngs::SysRng,
                )?;
                events.send(Event::Preview(format!("{:?}{warnings}", plan.report())))?;
                self.pending = Some(plan);
            }
            Command::Import(ids) => {
                let store = self.store.as_ref().ok_or("Open a wallet first")?;
                let mut next = store.snapshot.clone();
                next.wallet = self
                    .pending
                    .as_ref()
                    .ok_or("Preview an import first")?
                    .encrypt_into(&next.wallet, &ids, &mut rand::rngs::SysRng)?;
                self.commit(next, "Import entries")?;
                self.pending = None;
                self.wallet_event(events)?;
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
                events.send(Event::Entry(
                    id,
                    Zeroizing::new(String::from_utf8(p.to_json()?.to_vec())?),
                    entry.grants().keys().copied().collect(),
                ))?;
            }
            Command::Titles => {
                let s = self.session.as_ref().ok_or("Unlock a key first")?;
                let mut titles = Vec::new();
                for (id, e) in self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .wallet
                    .entries()
                {
                    if !e.grants().contains_key(&s.encryption.id()) {
                        continue;
                    }
                    let p = block_on(Payload::open(e, &s.encryption, s))?;
                    titles.push((
                        *id,
                        Zeroizing::new(
                            p.entity()["title"]
                                .as_str()
                                .unwrap_or("Untitled")
                                .to_owned(),
                        ),
                    ));
                }
                events.send(Event::Titles(titles))?;
            }
            Command::Save(id, json, ids) => {
                let p = Payload::from_json(id, json.as_bytes())?;
                let mut next = self
                    .store
                    .as_ref()
                    .ok_or("Open a wallet first")?
                    .snapshot
                    .clone();
                let unique: BTreeSet<_> = ids.into_iter().collect();
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
    fn commit(&mut self, next: Snapshot, message: &str) -> Result<()> {
        let s = self.session.as_ref().ok_or("Unlock a key first")?;
        let store = self.store.as_mut().ok_or("Open a wallet first")?;
        store.save(next, &Hardware(s), message)?;
        save_trust(store)?;
        Ok(())
    }
    fn wallet_event(&self, events: &mpsc::Sender<Event>) -> Result<()> {
        let s = self.store.as_ref().ok_or("No wallet")?;
        events.send(Event::Wallet {
            path: s.path.clone(),
            entries: s.snapshot.wallet.entries().keys().copied().collect(),
            participants: s.snapshot.wallet.participants().keys().copied().collect(),
            head: s.head.to_string(),
        })?;
        Ok(())
    }
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

//! Signed, linear Git wallet storage. No working tree is trusted or decrypted.
#![forbid(unsafe_code)]
mod signing;
use gix::{
    ObjectId,
    objs::{
        WriteTo,
        tree::{Entry as TreeEntry, EntryKind},
    },
    refs::transaction::PreviousValue,
};
use kagitaba_core::{
    EntryId, KeyId,
    crypto::PublicKey,
    wallet::{Entry, GrantRecord, PrimaryRecord, Wallet},
};
pub use signing::{Signer, ssh_public};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const BRANCH: &str = "refs/heads/wallet";
const MAX_FILES: usize = 100_000;
const MAX_SNAPSHOT: usize = 256 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wallet I/O failed")]
    Io,
    #[error("invalid or oversized wallet repository")]
    Invalid,
    #[error("wallet signature is missing, invalid, or unauthorized")]
    Signature,
    #[error("history is not linear or does not descend from the trusted checkpoint")]
    History,
    #[error("wallet changed in another process; reload before saving")]
    Stale,
    #[error("hardware signing failed")]
    Signing,
    #[error(transparent)]
    Core(#[from] kagitaba_core::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
pub struct Snapshot {
    pub wallet: Wallet,
    pub signers: BTreeMap<KeyId, PublicKey>,
}
impl Snapshot {
    pub fn empty(encryption: PublicKey, signing: PublicKey) -> Result<Self> {
        Ok(Self {
            signers: BTreeMap::from([(encryption.id(), signing)]),
            wallet: Wallet::from_parts([encryption], [])?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.signers.len() != self.wallet.participants().len()
            || self
                .signers
                .keys()
                .any(|k| !self.wallet.participants().contains_key(k))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub struct Store {
    repo: gix::Repository,
    pub path: PathBuf,
    pub head: ObjectId,
    pub snapshot: Snapshot,
    pub root_signer: PublicKey,
}
impl Store {
    /// Only initializes an absent or empty directory explicitly selected by caller.
    pub fn create(path: &Path, snapshot: Snapshot, signer: &impl Signer) -> Result<Self> {
        snapshot.validate()?;
        if path.exists()
            && std::fs::read_dir(path)
                .map_err(|_| Error::Io)?
                .next()
                .is_some()
        {
            return Err(Error::Invalid);
        }
        if !snapshot.signers.values().any(|p| p == signer.public_key()) {
            return Err(Error::Signature);
        }
        let repo = gix::init_bare(path).map_err(|_| Error::Io)?;
        let head = write_commit(&repo, None, &snapshot, signer, "Create wallet")?;
        repo.reference(BRANCH, head, PreviousValue::MustNotExist, "Create wallet")
            .map_err(|_| Error::Stale)?;
        // This is the newly created, app-owned bare wallet, never the source checkout.
        std::fs::write(path.join("HEAD"), format!("ref: {BRANCH}\n")).map_err(|_| Error::Io)?;
        Ok(Self {
            repo,
            path: path.to_owned(),
            head,
            snapshot,
            root_signer: signer.public_key().clone(),
        })
    }
    /// Root signer must come from a local trust record or explicit user confirmation.
    pub fn open(path: &Path, root_signer: PublicKey, checkpoint: Option<ObjectId>) -> Result<Self> {
        let repo = gix::open(path).map_err(|_| Error::Io)?;
        let head = branch(&repo)?;
        let snapshot = verify_history(&repo, head, &root_signer, checkpoint)?;
        Ok(Self {
            repo,
            path: path.to_owned(),
            head,
            snapshot,
            root_signer,
        })
    }
    pub fn save(&mut self, next: Snapshot, signer: &impl Signer, message: &str) -> Result<()> {
        next.validate()?;
        validate_transition(&self.snapshot, &next)?;
        if branch(&self.repo)? != self.head {
            return Err(Error::Stale);
        }
        if !self
            .snapshot
            .signers
            .values()
            .any(|k| k == signer.public_key())
        {
            return Err(Error::Signature);
        }
        let new = write_commit(&self.repo, Some(self.head), &next, signer, message)?;
        self.repo
            .reference(
                BRANCH,
                new,
                PreviousValue::MustExistAndMatch(gix::refs::Target::Object(self.head)),
                message,
            )
            .map_err(|_| Error::Stale)?;
        self.head = new;
        self.snapshot = next;
        Ok(())
    }
    /// Candidate objects must already be present (e.g. fetched into a quarantine ref).
    /// Verify every incoming commit before updating the accepted wallet branch.
    pub fn accept(&mut self, candidate: ObjectId) -> Result<()> {
        let next = verify_history(&self.repo, candidate, &self.root_signer, Some(self.head))?;
        self.repo
            .reference(
                BRANCH,
                candidate,
                PreviousValue::MustExistAndMatch(gix::refs::Target::Object(self.head)),
                "Accept verified updates",
            )
            .map_err(|_| Error::Stale)?;
        self.head = candidate;
        self.snapshot = next;
        Ok(())
    }
    /// Pull a local replica only after verifying authorized linear history back
    /// to this wallet's trusted checkpoint.
    pub fn pull_from(&mut self, path: &Path) -> Result<()> {
        let source = gix::open(path).map_err(|_| Error::Io)?;
        let head = branch(&source)?;
        verify_history(&source, head, &self.root_signer, Some(self.head))?;
        copy_objects(&source, &self.repo, head)?;
        self.accept(head)
    }
    /// Create an encrypted backup preserving signed history, without private keys.
    pub fn backup_to(&self, path: &Path) -> Result<()> {
        if path.exists()
            && std::fs::read_dir(path)
                .map_err(|_| Error::Io)?
                .next()
                .is_some()
        {
            return Err(Error::Invalid);
        }
        verify_history(&self.repo, self.head, &self.root_signer, Some(self.head))?;
        let target = gix::init_bare(path).map_err(|_| Error::Io)?;
        copy_objects(&self.repo, &target, self.head)?;
        target
            .reference(
                BRANCH,
                self.head,
                PreviousValue::MustNotExist,
                "Verified encrypted backup",
            )
            .map_err(|_| Error::Io)?;
        std::fs::write(path.join("HEAD"), format!("ref: {BRANCH}\n")).map_err(|_| Error::Io)?;
        Ok(())
    }
    /// Read-only preview of an untrusted genesis signing key for out-of-band comparison.
    pub fn inspect_root(path: &Path) -> Result<PublicKey> {
        let repo = gix::open(path).map_err(|_| Error::Io)?;
        let chain = history(&repo, branch(&repo)?)?;
        let (_, commit) = chain.last().ok_or(Error::Invalid)?;
        let sig = signature(commit)?;
        signing::from_ssh(sig.public_key())
    }
}
fn copy_objects(source: &gix::Repository, target: &gix::Repository, head: ObjectId) -> Result<()> {
    use gix::objs::Write;
    let mut pending = vec![head];
    let mut seen = std::collections::BTreeSet::new();
    let mut remaining = 512 * 1024 * 1024u64;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > 200_000 {
            return Err(Error::Invalid);
        }
        let header = source.find_header(id).map_err(|_| Error::Invalid)?;
        if header.size() > 16 * 1024 * 1024 || header.size() > remaining {
            return Err(Error::Invalid);
        }
        remaining -= header.size();
        let obj = source.find_object(id).map_err(|_| Error::Invalid)?;
        if gix::objs::compute_hash(gix::hash::Kind::Sha1, obj.kind, &obj.data)
            .map_err(|_| Error::Invalid)?
            != id
        {
            return Err(Error::Invalid);
        }
        match obj.kind {
            gix::objs::Kind::Commit => {
                let c = commit(source, id)?;
                pending.push(c.tree);
                pending.extend(c.parents);
            }
            gix::objs::Kind::Tree => {
                let tree = gix::objs::TreeRef::from_bytes(&obj.data, gix::hash::Kind::Sha1)
                    .map_err(|_| Error::Invalid)?;
                for e in tree.entries {
                    pending.push(e.oid.to_owned());
                }
            }
            gix::objs::Kind::Blob => {}
            _ => return Err(Error::Invalid),
        }
        let written = target
            .objects
            .write_buf(obj.kind, &obj.data)
            .map_err(|_| Error::Io)?;
        if written != id {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
pub fn parse_oid(text: &str) -> Result<ObjectId> {
    ObjectId::from_hex(text.as_bytes()).map_err(|_| Error::Invalid)
}
fn branch(repo: &gix::Repository) -> Result<ObjectId> {
    repo.find_reference(BRANCH)
        .map_err(|_| Error::Invalid)?
        .try_id()
        .map(|id| id.detach())
        .ok_or(Error::Invalid)
}
fn commit(repo: &gix::Repository, id: ObjectId) -> Result<gix::objs::Commit> {
    if repo.find_header(id).map_err(|_| Error::Invalid)?.size() > 16384 {
        return Err(Error::Invalid);
    }
    let object = repo.find_commit(id).map_err(|_| Error::Invalid)?;
    if object.data.len() > 16384 {
        return Err(Error::Invalid);
    }
    // Don't rely on the object database trusting a loose object's filename.
    if gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Commit, &object.data)
        .map_err(|_| Error::Invalid)?
        != id
    {
        return Err(Error::Invalid);
    }
    let decoded: gix::objs::Commit = object
        .decode()
        .map_err(|_| Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    if bytes(&decoded)? != object.data {
        return Err(Error::Invalid);
    }
    Ok(decoded)
}
fn history(repo: &gix::Repository, head: ObjectId) -> Result<Vec<(ObjectId, gix::objs::Commit)>> {
    let mut chain = Vec::new();
    let mut id = head;
    loop {
        if chain.len() >= 10_000 {
            return Err(Error::History);
        }
        let c = commit(repo, id)?;
        if c.parents.len() > 1 {
            return Err(Error::History);
        }
        let parent = c.parents.first().copied();
        chain.push((id, c));
        match parent {
            Some(p) => id = p,
            None => return Ok(chain),
        }
    }
}
fn verify_history(
    repo: &gix::Repository,
    head: ObjectId,
    root: &PublicKey,
    checkpoint: Option<ObjectId>,
) -> Result<Snapshot> {
    let chain = history(repo, head)?;
    if checkpoint.is_some_and(|p| !chain.iter().any(|(id, _)| *id == p)) {
        return Err(Error::History);
    }
    let mut previous: Option<Snapshot> = None;
    for (_, mut c) in chain.into_iter().rev() {
        let sig = signature(&c)?;
        let key = signing::from_ssh(sig.public_key())?;
        let authorized = match &previous {
            None => &key == root,
            Some(p) => p.signers.values().any(|k| k == &key),
        };
        if !authorized {
            return Err(Error::Signature);
        }
        c.extra_headers.clear();
        ssh_public(&key)?
            .verify("git", &bytes(&c)?, &sig)
            .map_err(|_| Error::Signature)?;
        let current = read_snapshot(repo, c.tree)?;
        if let Some(old) = &previous {
            validate_transition(old, &current)?;
        }
        if previous.is_none() && !current.signers.values().any(|k| k == root) {
            return Err(Error::Signature);
        }
        previous = Some(current);
    }
    previous.ok_or(Error::Invalid)
}
fn validate_transition(old: &Snapshot, new: &Snapshot) -> Result<()> {
    for (id, entry) in new.wallet.entries() {
        if let Some(previous) = old.wallet.entries().get(id)
            && previous.primary() != entry.primary()
            && previous.primary().revision_id() == entry.primary().revision_id()
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn signature(c: &gix::objs::Commit) -> Result<ssh_key::SshSig> {
    if c.encoding.is_some()
        || c.extra_headers.len() != 1
        || c.extra_headers[0].0.as_slice() != b"gpgsig"
    {
        return Err(Error::Signature);
    }
    ssh_key::SshSig::from_pem(c.extra_headers[0].1.as_slice()).map_err(|_| Error::Signature)
}
fn bytes(c: &gix::objs::Commit) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    c.write_to(&mut out).map_err(|_| Error::Invalid)?;
    Ok(out)
}
fn write_commit(
    repo: &gix::Repository,
    parent: Option<ObjectId>,
    snapshot: &Snapshot,
    signer: &impl Signer,
    message: &str,
) -> Result<ObjectId> {
    let tree = write_tree(repo, &files(snapshot)?)?;
    let actor = gix::actor::Signature {
        name: "Kagitaba".into(),
        email: "wallet@localhost".into(),
        time: gix::date::Time {
            seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Io)?
                .as_secs() as i64,
            offset: 0,
        },
    };
    let mut c = gix::objs::Commit {
        tree,
        parents: parent.into_iter().collect(),
        author: actor.clone(),
        committer: actor,
        encoding: None,
        message: format!("{message}\n").into(),
        extra_headers: vec![],
    };
    let sig = signing::sign(signer, &bytes(&c)?)?;
    c.extra_headers.push(("gpgsig".into(), sig.into()));
    repo.write_object(c)
        .map(|id| id.detach())
        .map_err(|_| Error::Io)
}
type Files = BTreeMap<String, Vec<u8>>;
fn files(snapshot: &Snapshot) -> Result<Files> {
    snapshot.validate()?;
    let mut files = BTreeMap::from([("kagitaba-format".into(), b"1\n".to_vec())]);
    for (id, pubkey) in snapshot.wallet.participants() {
        files.insert(
            format!("participants/{id}/pub.pem"),
            pubkey.to_pem().into_bytes(),
        );
        files.insert(
            format!("participants/{id}/sign.pem"),
            snapshot.signers[id].to_pem().into_bytes(),
        );
    }
    for (id, entry) in snapshot.wallet.entries() {
        files.insert(format!("entries/{id}/primary"), entry.primary().to_bytes());
        for (key, grant) in entry.grants() {
            files.insert(format!("entries/{id}/grants/{key}"), grant.to_bytes());
        }
    }
    if files.len() > MAX_FILES || files.values().map(Vec::len).sum::<usize>() > MAX_SNAPSHOT {
        return Err(Error::Invalid);
    }
    Ok(files)
}
fn write_tree(repo: &gix::Repository, files: &Files) -> Result<ObjectId> {
    let mut dirs: BTreeMap<String, Files> = BTreeMap::new();
    let mut entries = Vec::new();
    for (path, value) in files {
        if let Some((dir, rest)) = path.split_once('/') {
            dirs.entry(dir.into())
                .or_default()
                .insert(rest.into(), value.clone());
        } else {
            entries.push(TreeEntry {
                mode: EntryKind::Blob.into(),
                filename: path.as_str().into(),
                oid: repo.write_blob(value).map_err(|_| Error::Io)?.detach(),
            });
        }
    }
    for (name, files) in dirs {
        entries.push(TreeEntry {
            mode: EntryKind::Tree.into(),
            filename: name.into(),
            oid: write_tree(repo, &files)?,
        });
    }
    entries.sort();
    repo.write_object(gix::objs::Tree { entries })
        .map(|id| id.detach())
        .map_err(|_| Error::Io)
}
fn read_tree(
    repo: &gix::Repository,
    id: ObjectId,
    prefix: &str,
    files: &mut Files,
    budget: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth > 5 || files.len() > MAX_FILES {
        return Err(Error::Invalid);
    }
    if repo.find_header(id).map_err(|_| Error::Invalid)?.size() > 16 * 1024 * 1024 {
        return Err(Error::Invalid);
    }
    let obj = repo.find_tree(id).map_err(|_| Error::Invalid)?;
    if obj.data.len() > 16 * 1024 * 1024 {
        return Err(Error::Invalid);
    }
    if gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Tree, &obj.data)
        .map_err(|_| Error::Invalid)?
        != id
    {
        return Err(Error::Invalid);
    }
    for e in obj.decode().map_err(|_| Error::Invalid)?.entries {
        let name = std::str::from_utf8(e.filename).map_err(|_| Error::Invalid)?;
        if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
            return Err(Error::Invalid);
        }
        let path = format!("{prefix}{name}");
        match e.mode.kind() {
            EntryKind::Tree => read_tree(
                repo,
                e.oid.to_owned(),
                &(path + "/"),
                files,
                budget,
                depth + 1,
            )?,
            EntryKind::Blob => {
                let size = repo
                    .find_header(e.oid.to_owned())
                    .map_err(|_| Error::Invalid)?
                    .size();
                if size > 2 * 1024 * 1024 + 100 || size > *budget as u64 {
                    return Err(Error::Invalid);
                }
                let blob = repo
                    .find_blob(e.oid.to_owned())
                    .map_err(|_| Error::Invalid)?;
                if blob.data.len() > 2 * 1024 * 1024 + 100 || blob.data.len() > *budget {
                    return Err(Error::Invalid);
                }
                *budget -= blob.data.len();
                if gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, &blob.data)
                    .map_err(|_| Error::Invalid)?
                    .as_ref()
                    != e.oid
                {
                    return Err(Error::Invalid);
                }
                if files.insert(path, blob.data.to_vec()).is_some() {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
    }
    Ok(())
}
fn read_snapshot(repo: &gix::Repository, tree: ObjectId) -> Result<Snapshot> {
    let mut files = Files::new();
    let mut budget = MAX_SNAPSHOT;
    read_tree(repo, tree, "", &mut files, &mut budget, 0)?;
    if files.remove("kagitaba-format").as_deref() != Some(b"1\n") {
        return Err(Error::Invalid);
    }
    let mut keys = BTreeMap::new();
    let mut signers = BTreeMap::new();
    let mut primaries = BTreeMap::new();
    let mut grants: BTreeMap<EntryId, Vec<GrantRecord>> = BTreeMap::new();
    for (path, data) in files {
        let parts: Vec<_> = path.split('/').collect();
        match parts.as_slice() {
            ["participants", id, file @ ("pub.pem" | "sign.pem")] => {
                let id: KeyId = id.parse()?;
                let key =
                    PublicKey::from_pem(std::str::from_utf8(&data).map_err(|_| Error::Invalid)?)?;
                if *file == "pub.pem" {
                    if key.id() != id {
                        return Err(Error::Invalid);
                    }
                    keys.insert(id, key);
                } else {
                    signers.insert(id, key);
                }
            }
            ["entries", id, "primary"] => {
                let id: EntryId = id.parse()?;
                let primary = PrimaryRecord::from_bytes(&data)?;
                if primary.entry_id() != id {
                    return Err(Error::Invalid);
                }
                primaries.insert(id, primary);
            }
            ["entries", id, "grants", key] => {
                let id: EntryId = id.parse()?;
                let key: KeyId = key.parse()?;
                let grant = GrantRecord::from_bytes(&data)?;
                if grant.entry_id() != id || grant.recipient() != key {
                    return Err(Error::Invalid);
                }
                grants.entry(id).or_default().push(grant);
            }
            _ => return Err(Error::Invalid),
        }
    }
    let mut entries = Vec::new();
    for (id, primary) in primaries {
        entries.push(Entry::from_parts(
            primary,
            grants.remove(&id).unwrap_or_default(),
        )?);
    }
    if !grants.is_empty() {
        return Err(Error::Invalid);
    }
    let snapshot = Snapshot {
        wallet: Wallet::from_parts(keys.into_values(), entries)?,
        signers,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

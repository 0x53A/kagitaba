//! Signed Git wallet storage with conservative merges. No working tree is trusted or decrypted.
#![forbid(unsafe_code)]
mod device_hint;
mod history;
mod participant_name;
mod metadata;
#[cfg(test)]
mod history_tests;
mod signing;
mod transfer;
mod worktree;
pub use device_hint::DeviceHint;
pub use participant_name::validate_name;
use history::{history, merge_files, verify_history};
use gix::{
    objs::{
        WriteTo,
        tree::{Entry as TreeEntry, EntryKind},
    },
};
pub use gix::ObjectId;
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
    #[error(
        "destination folder is not empty; choose a new empty folder, or use Open wallet for an existing wallet"
    )]
    DestinationNotEmpty,
    #[error(
        "wallet working tree or index has local changes, conflicting files, or unsafe paths; resolve them before saving"
    )]
    DirtyWorktree,
    #[error("check out the wallet branch before saving from Kagitaba")]
    WrongBranch,
    #[error("wallet working tree is locked by another Git operation")]
    WorktreeLocked,
    #[error("wallet signature is missing, invalid, or unauthorized")]
    Signature,
    #[error("unsupported wallet history; update clients if this wallet uses newer history rules")]
    History,
    #[error("incoming history does not contain the trusted checkpoint; histories diverged or an older snapshot was offered")]
    Checkpoint,
    #[error("wallet histories have different genesis commits and cannot be merged")]
    UnrelatedHistory,
    #[error("wallet histories have multiple merge bases; automatic merging is unsupported")]
    AmbiguousMergeBase,
    #[error("participant name must be 1–128 characters, at most 512 bytes, with no surrounding whitespace, controls or bidirectional overrides")]
    InvalidName,
    #[error("wallet histories conflict; concurrent entry or participant changes require manual resolution")]
    Conflict,
    #[error("wallet changed in another process; reload before saving")]
    Stale,
    #[error("hardware signing failed")]
    Signing,
    #[error(transparent)]
    Core(#[from] kagitaba_core::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryRelation {
    pub ahead: usize,
    pub behind: usize,
}
#[derive(Clone)]
pub struct Snapshot {
    pub wallet: Wallet,
    pub signers: BTreeMap<KeyId, PublicKey>,
    pub devices: BTreeMap<KeyId, DeviceHint>,
    /// Legacy recovery packages: read for history compatibility, pruned on writes.
    pub browsers: BTreeMap<KeyId, serde_json::Value>,
    /// Legacy public labels: migrate to encrypted metadata before writing.
    pub names: BTreeMap<KeyId, String>,
    /// Public pointers to encrypted participant metadata entries.
    pub metadata: BTreeMap<KeyId, EntryId>,
}
impl Snapshot {
    pub fn empty(encryption: PublicKey, signing: PublicKey) -> Result<Self> {
        Ok(Self {
            metadata: BTreeMap::new(),
            names: BTreeMap::new(),
            devices: BTreeMap::new(),
            browsers: BTreeMap::new(),
            signers: BTreeMap::from([(encryption.id(), signing)]),
            wallet: Wallet::from_parts([encryption], [])?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for (participant, entry) in &self.metadata {
            if !self.wallet.participants().contains_key(participant)
                || !self.wallet.entries().contains_key(entry)
                || !seen.insert(entry)
                || self.names.contains_key(participant)
            {
                return Err(Error::Invalid);
            }
        }
        for (id, name) in &self.names {
            validate_name(name)?;
            if !self.wallet.participants().contains_key(id) {
                return Err(Error::Invalid);
            }
        }
        for (id, metadata) in &self.browsers {
            transfer::validate_browser(
                metadata,
                self.wallet.participants().get(id).ok_or(Error::Invalid)?,
                self.signers.get(id).ok_or(Error::Invalid)?,
            )?;
        }
        for (id, hint) in &self.devices {
            if !self.wallet.participants().contains_key(id) {
                return Err(Error::Invalid);
            }
            hint.validate()?;
        }
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
    /// Initializes a normal repository in an empty directory or unused `git init` repository.
    pub fn create(path: &Path, snapshot: Snapshot, signer: &impl Signer) -> Result<Self> {
        snapshot.validate()?;
        if !snapshot.signers.values().any(|p| p == signer.public_key()) {
            return Err(Error::Signature);
        }
        let repo = worktree::initialize(path)?;
        let head = write_commit(&repo, None, &snapshot, signer, "Create wallet")?;
        publish(&repo, None, head, "Create wallet")?;
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
        publish(&self.repo, Some(self.head), new, message)?;
        self.head = new;
        self.snapshot = next;
        Ok(())
    }
    /// Candidate objects must already be present (e.g. fetched into a quarantine ref).
    /// Verify every incoming commit before updating the accepted wallet branch.
    pub fn accept(&mut self, candidate: ObjectId) -> Result<()> {
        let next = verify_history(&self.repo, candidate, &self.root_signer, Some(self.head))?;
        if branch(&self.repo)? != self.head {
            return Err(Error::Stale);
        }
        publish(
            &self.repo,
            Some(self.head),
            candidate,
            "Accept verified updates",
        )?;
        self.head = candidate;
        self.snapshot = next;
        Ok(())
    }
    /// Pull a local replica only after verifying authorized history back
    /// to this wallet's trusted checkpoint.
    pub fn pull_from(&mut self, path: &Path) -> Result<()> {
        let source = gix::open(path).map_err(|_| Error::Io)?;
        let head = branch(&source)?;
        verify_history(&source, head, &self.root_signer, Some(self.head))?;
        copy_objects(&source, &self.repo, head)?;
        self.accept(head)
    }
    /// Explicitly merge an already-fetched commit. Independent changes only;
    /// the signer must be authorized in both parents. No plaintext is needed.
    pub fn merge(&mut self, candidate: ObjectId, signer: &impl Signer) -> Result<()> {
        self.merge_then(candidate, signer, |_| Ok(false))
    }
    /// Build a clean merge and optionally a signed application-maintenance child.
    /// Both signatures and final verification precede the single ref/checkout update.
    pub fn merge_then(&mut self, candidate: ObjectId, signer: &impl Signer, repair: impl FnOnce(&mut Snapshot) -> Result<bool>) -> Result<()> {
        verify_history(&self.repo, self.head, &self.root_signer, Some(self.head))?;
        let incoming = verify_history(&self.repo, candidate, &self.root_signer, None)?;
        let graph = history(&self.repo, candidate)?;
        if graph.iter().any(|(id, _)| *id == self.head) {
            return self.publish_repaired(candidate, incoming, signer, repair);
        }
        let local = history(&self.repo, self.head)?;
        if local.iter().any(|(id, _)| *id == candidate) {
            if branch(&self.repo)? != self.head {
                return Err(Error::Stale);
            }
            return self.publish_repaired(self.head, self.snapshot.clone(), signer, repair);
        }
        if ![&self.snapshot, &incoming].iter().all(|snapshot| {
            snapshot
                .signers
                .values()
                .any(|key| key == signer.public_key())
        }) {
            return Err(Error::Signature);
        }
        let graph = local.into_iter().chain(graph).collect();
        let merged = merge_files(&self.repo, &graph, self.head, candidate)?;
        let tree = write_tree(&self.repo, &merged)?;
        let next = read_snapshot(&self.repo, tree)?;
        validate_transition(&self.snapshot, &next)?;
        validate_transition(&incoming, &next)?;
        if branch(&self.repo)? != self.head {
            return Err(Error::Stale);
        }
        let head = write_commit_tree(
            &self.repo,
            &[self.head, candidate],
            tree,
            signer,
            "Merge independent wallet changes",
        )?;
        self.publish_repaired(head, next, signer, repair)
    }
    fn publish_repaired(&mut self, mut head: ObjectId, mut next: Snapshot, signer: &impl Signer, repair: impl FnOnce(&mut Snapshot) -> Result<bool>) -> Result<()> {
        let clean = next.clone();
        if repair(&mut next)? {
            next.validate()?;
            validate_transition(&clean, &next)?;
            if !clean.signers.values().any(|key| key == signer.public_key()) { return Err(Error::Signature); }
            head = write_commit(&self.repo, Some(head), &next, signer, "Complete participant metadata grants")?;
        }
        verify_history(&self.repo, head, &self.root_signer, Some(self.head))?;
        if head == self.head { return Ok(()); }
        publish(
            &self.repo,
            Some(self.head),
            head,
            "Merge verified histories",
        )?;
        self.head = head;
        self.snapshot = next;
        Ok(())
    }
    /// Merge a local replica after authenticating its complete history.
    pub fn merge_from(&mut self, path: &Path, signer: &impl Signer) -> Result<()> {
        let head = self.import_candidate(path)?;
        self.merge(head, signer)
    }
    /// Copy verified local history without advancing the accepted branch.
    pub fn import_candidate(&self, path: &Path) -> Result<ObjectId> {
        let source = gix::open(path).map_err(|_| Error::Io)?;
        let head = branch(&source)?;
        verify_history(&source, head, &self.root_signer, None)?;
        copy_objects(&source, &self.repo, head)?;
        Ok(head)
    }
    /// Merge the cached origin/wallet ref; performs no network fetch or push.
    pub fn merge_origin(&mut self, signer: &impl Signer) -> Result<()> {
        self.merge(self.origin_head()?, signer)
    }
    /// The cached remote ref is untrusted until verified by relation/accept/merge.
    pub fn origin_head(&self) -> Result<ObjectId> {
        self.repo
            .find_reference("refs/remotes/origin/wallet")
            .map_err(|_| Error::Invalid)?
            .try_id()
            .ok_or(Error::Invalid)
            .map(|id| id.detach())
    }
    /// Verify a candidate and compare its complete DAG with the accepted history.
    /// Separate genesis commits are unrelated even if signed by the same key.
    pub fn relation(&self, candidate: ObjectId) -> Result<HistoryRelation> {
        verify_history(&self.repo, candidate, &self.root_signer, None)?;
        let local = history(&self.repo, self.head)?;
        let remote = history(&self.repo, candidate)?;
        if local.first().map(|(id, _)| id) != remote.first().map(|(id, _)| id) {
            return Err(Error::UnrelatedHistory);
        }
        let a: std::collections::BTreeSet<_> = local.iter().map(|(id, _)| id).collect();
        let b: std::collections::BTreeSet<_> = remote.iter().map(|(id, _)| id).collect();
        Ok(HistoryRelation {
            ahead: a.difference(&b).count(),
            behind: b.difference(&a).count(),
        })
    }
    /// Create an encrypted backup preserving signed history, without private keys.
    pub fn backup_to(&self, path: &Path) -> Result<()> {
        verify_history(&self.repo, self.head, &self.root_signer, Some(self.head))?;
        let target = worktree::initialize(path)?;
        copy_objects(&self.repo, &target, self.head)?;
        publish(&target, None, self.head, "Verified encrypted backup")?;
        Ok(())
    }
    /// Read-only preview of an untrusted genesis signing key for out-of-band comparison.
    pub fn inspect_root(path: &Path) -> Result<PublicKey> {
        let repo = gix::open(path).map_err(|_| Error::Io)?;
        let chain = history(&repo, branch(&repo)?)?;
        let (_, commit) = chain.first().ok_or(Error::Invalid)?;
        let sig = signature(commit)?;
        signing::from_ssh(sig.public_key())
    }
}
fn publish(
    repo: &gix::Repository,
    old: Option<ObjectId>,
    new: ObjectId,
    message: &str,
) -> Result<()> {
    use gix::refs::{
        Target,
        transaction::{PreviousValue, RefEdit},
    };
    let name: gix::refs::FullName = BRANCH.try_into().map_err(|_| Error::Invalid)?;
    let mut edits = vec![RefEdit::update(
        name.clone(),
        new,
        match old {
            Some(id) => PreviousValue::MustExistAndMatch(Target::Object(id)),
            None => PreviousValue::MustNotExist,
        },
        message,
    )];
    if repo.workdir().is_some() {
        let head = repo
            .head_name()
            .map_err(|_| Error::WrongBranch)?
            .ok_or(Error::WrongBranch)?;
        if old.is_some() && head != name {
            return Err(Error::WrongBranch);
        }
        edits.push(RefEdit::update(
            "HEAD".try_into().map_err(|_| Error::Invalid)?,
            Target::Symbolic(name),
            PreviousValue::MustExistAndMatch(Target::Symbolic(head)),
            message,
        ));
    }
    // Lock refs before touching the working tree, including a compare-and-swap
    // check. A concurrent branch change must never leave a stale checkout behind.
    let transaction = repo
        .refs
        .transaction()
        .prepare(
            edits,
            gix::lock::acquire::Fail::Immediately,
            gix::lock::acquire::Fail::Immediately,
        )
        .map_err(|_| Error::Stale)?;
    worktree::Update::prepare(repo, old, new)?.apply()?;
    let actor = commit(repo, new)?.committer;
    transaction
        .commit(Some(actor.to_ref(&mut Default::default())))
        .map_err(|_| Error::Io)?;
    Ok(())
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
    write_commit_tree(
        repo,
        &parent.into_iter().collect::<Vec<_>>(),
        tree,
        signer,
        message,
    )
}
fn write_commit_tree(
    repo: &gix::Repository,
    parents: &[ObjectId],
    tree: ObjectId,
    signer: &impl Signer,
    message: &str,
) -> Result<ObjectId> {
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
        parents: parents.iter().copied().collect(),
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
        if let Some(hint) = snapshot.devices.get(id) {
            files.insert(format!("participants/{id}/device.json"), hint.to_json()?);
        }
        if let Some(entry) = snapshot.metadata.get(id) {
            files.insert(format!("participants/{id}/meta.entry"), format!("{entry}\n").into_bytes());
        }
        if let Some(name) = snapshot.names.get(id) {
            files.insert(
                format!("participants/{id}/name.json"),
                participant_name::to_json(name)?,
            );
        }
        if let Some(browser) = snapshot.browsers.get(id) {
            files.insert(
                format!("participants/{id}/browser.json"),
                serde_json::to_vec(browser).map_err(|_| Error::Invalid)?,
            );
        }
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
    snapshot_from_files(read_files(repo, tree)?)
}
fn read_files(repo: &gix::Repository, tree: ObjectId) -> Result<Files> {
    let mut files = Files::new();
    let mut budget = MAX_SNAPSHOT;
    read_tree(repo, tree, "", &mut files, &mut budget, 0)?;
    Ok(files)
}
fn snapshot_from_files(mut files: Files) -> Result<Snapshot> {
    if files.remove("kagitaba-format").as_deref() != Some(b"1\n") {
        return Err(Error::Invalid);
    }
    let mut keys = BTreeMap::new();
    let mut signers = BTreeMap::new();
    let mut devices = BTreeMap::new();
    let mut browsers = BTreeMap::new();
    let mut names = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    let mut primaries = BTreeMap::new();
    let mut grants: BTreeMap<EntryId, Vec<GrantRecord>> = BTreeMap::new();
    for (path, data) in files {
        let parts: Vec<_> = path.split('/').collect();
        match parts.as_slice() {
            ["participants", id, "meta.entry"] => {
                let text = std::str::from_utf8(&data).map_err(|_| Error::Invalid)?;
                let entry = text.strip_suffix('\n').ok_or(Error::Invalid)?.parse()?;
                metadata.insert(id.parse()?, entry);
            }
            ["participants", id, "name.json"] => {
                names.insert(id.parse()?, participant_name::from_json(&data)?);
            }
            ["participants", id, "browser.json"] => {
                if data.len() > 65536 {
                    return Err(Error::Invalid);
                }
                browsers.insert(
                    id.parse()?,
                    serde_json::from_slice(&data).map_err(|_| Error::Invalid)?,
                );
            }
            ["participants", id, "device.json"] => {
                devices.insert(id.parse()?, DeviceHint::from_json(&data)?);
            }
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
        metadata,
        names,
        browsers,
        devices,
        wallet: Wallet::from_parts(keys.into_values(), entries)?,
        signers,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

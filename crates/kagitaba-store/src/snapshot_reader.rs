//! Per-verification reuse of already checked immutable entry trees.
use super::*;

#[derive(Clone, Copy)]
struct TreeInfo {
    oid: ObjectId,
    files: usize,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct SnapshotReader {
    trees: BTreeMap<EntryId, TreeInfo>,
}

pub(super) struct Reuse<'a> {
    previous: Option<&'a Snapshot>,
    trees: &'a BTreeMap<EntryId, TreeInfo>,
    next: BTreeMap<EntryId, TreeInfo>,
    pub entries: Vec<Entry>,
    pub attachments: BTreeMap<EntryId, BTreeMap<String, AttachmentBlob>>,
    pub skipped_files: usize,
}

fn owner(path: &str) -> Option<EntryId> {
    let name = path.strip_prefix("entries/")?;
    let id: EntryId = name.parse().ok()?;
    (id.to_string() == name).then_some(id)
}

impl Reuse<'_> {
    pub fn reuse(&mut self, path: &str, oid: ObjectId, budget: &mut usize) -> Result<bool> {
        let Some(id) = owner(path) else {
            return Ok(false);
        };
        let Some(info) = self.trees.get(&id).filter(|info| info.oid == oid) else {
            return Ok(false);
        };
        let Some(previous) = self.previous else {
            return Ok(false);
        };
        let Some(entry) = previous.wallet.entries().get(&id) else {
            return Ok(false);
        };
        *budget = budget.checked_sub(info.bytes).ok_or(Error::Invalid)?;
        self.skipped_files += info.files;
        if self.next.insert(id, *info).is_some() {
            return Err(Error::Invalid);
        }
        self.entries.push(entry.clone());
        if let Some(blobs) = previous.attachments.get(&id) {
            self.attachments.insert(id, blobs.clone());
        }
        Ok(true)
    }

    pub fn record(&mut self, path: &str, oid: ObjectId, files: usize, bytes: usize) -> Result<()> {
        if let Some(id) = owner(path)
            && self
                .next
                .insert(id, TreeInfo { oid, files, bytes })
                .is_some()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

impl SnapshotReader {
    /// `previous` must be the snapshot returned by this reader's last call.
    /// Only ciphertext entry trees are reused; membership and all snapshot-wide
    /// invariants are validated again. Cache state never survives verification.
    pub fn read(
        &mut self,
        repo: &gix::Repository,
        tree: ObjectId,
        previous: Option<&Snapshot>,
    ) -> Result<Snapshot> {
        let mut reuse = Some(Reuse {
            previous,
            trees: &self.trees,
            next: BTreeMap::new(),
            entries: Vec::new(),
            attachments: BTreeMap::new(),
            skipped_files: 0,
        });
        let mut files = Files::new();
        let mut budget = MAX_SNAPSHOT;
        read_tree(repo, tree, "", &mut files, &mut budget, 0, &mut reuse)?;
        let reuse = reuse.expect("reader retains reuse state");
        if files.len() + reuse.skipped_files > MAX_FILES {
            return Err(Error::Invalid);
        }
        let snapshot = snapshot_from_files_with_entries(files, reuse.entries, reuse.attachments)?;
        self.trees = reuse.next;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_subtrees_still_consume_snapshot_file_and_byte_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let public = kagitaba_core::crypto::SoftwareIdentity::from_bytes(&[19; 32])
            .unwrap()
            .public_key();
        let mut source = Snapshot::empty(public.clone(), public).unwrap();
        let id = EntryId::from_bytes([1; 16]);
        source.wallet = source
            .wallet
            .with_entry(
                Entry::from_parts(
                    PrimaryRecord::new(id, kagitaba_core::RevisionId::from_bytes([1; 16]), vec![1])
                        .unwrap(),
                    [],
                )
                .unwrap(),
            )
            .unwrap();
        let tree = write_tree(&repo, &files(&source).unwrap()).unwrap();
        let mut reader = SnapshotReader::default();
        let previous = reader.read(&repo, tree, None).unwrap();
        let original = reader.trees[&id];
        reader.trees.get_mut(&id).unwrap().files = MAX_FILES;
        assert!(reader.read(&repo, tree, Some(&previous)).is_err());
        reader.trees.insert(
            id,
            TreeInfo {
                bytes: MAX_SNAPSHOT,
                ..original
            },
        );
        assert!(reader.read(&repo, tree, Some(&previous)).is_err());
        reader.trees.insert(id, original);
        assert!(reader.read(&repo, tree, Some(&previous)).is_ok());
    }
}

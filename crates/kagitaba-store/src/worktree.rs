//! A working tree is an encrypted, disposable view of the signed commit.
//! Never read wallet state from it or overwrite local edits when updating it.
use crate::{BRANCH, Error, FileData, Files, MAX_SNAPSHOT, Result, commit, read_tree};
use gix::ObjectId;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn initialize(path: &Path) -> Result<gix::Repository> {
    if path.exists() {
        for entry in fs::read_dir(path).map_err(|_| Error::Io)? {
            let entry = entry.map_err(|_| Error::Io)?;
            if entry.file_name() != ".git" || !entry.file_type().map_err(|_| Error::Io)?.is_dir() {
                return Err(Error::DestinationNotEmpty);
            }
        }
    }
    if path.join(".git").exists() {
        let repo = gix::open(path).map_err(|_| Error::DestinationNotEmpty)?;
        if repo.workdir().is_none()
            || repo.workdir().and_then(|p| fs::canonicalize(p).ok()) != fs::canonicalize(path).ok()
            || !repo
                .head()
                .map_err(|_| Error::DestinationNotEmpty)?
                .is_unborn()
            || repo
                .references()
                .map_err(|_| Error::Io)?
                .all()
                .map_err(|_| Error::Io)?
                .next()
                .is_some()
            || !repo
                .index_or_empty()
                .map_err(|_| Error::DirtyWorktree)?
                .entries()
                .is_empty()
        {
            return Err(Error::DestinationNotEmpty);
        }
        Ok(repo)
    } else {
        gix::init(path).map_err(|_| Error::Io)
    }
}

pub(crate) struct Update {
    root: Option<PathBuf>,
    old: Files,
    next: Files,
    index: Option<gix::index::File>,
    lock: Option<(PathBuf, fs::File)>,
}

impl Update {
    pub(crate) fn prepare(
        repo: &gix::Repository,
        old: Option<ObjectId>,
        next: ObjectId,
    ) -> Result<Self> {
        let mut out = Self {
            root: repo.workdir().map(Path::to_owned),
            old: Files::new(),
            next: Files::new(),
            index: None,
            lock: None,
        };
        let Some(root) = &out.root else {
            return Ok(out);
        };
        if repo.index_path() != repo.git_dir().join("index") {
            return Err(Error::DirtyWorktree);
        }
        if old.is_some()
            && repo
                .head_name()
                .map_err(|_| Error::WrongBranch)?
                .as_ref()
                .map(|n| n.as_bstr())
                != Some(BRANCH.into())
        {
            return Err(Error::WrongBranch);
        }
        let lock_path = repo.index_path().with_extension("lock");
        let lock = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::WorktreeLocked
                } else {
                    Error::Io
                }
            })?;
        out.lock = Some((lock_path, lock));
        if let Some(old) = old {
            out.old = committed_files(repo, old)?;
        }
        out.next = committed_files(repo, next)?;
        let actual = repo.index_or_empty().map_err(|_| Error::DirtyWorktree)?;
        if actual.entries().len() != out.old.len() {
            return Err(Error::DirtyWorktree);
        }
        for entry in actual.entries() {
            let path =
                std::str::from_utf8(entry.path(&actual)).map_err(|_| Error::DirtyWorktree)?;
            let bytes = out.old.get(path).ok_or(Error::DirtyWorktree)?;
            if entry.stage_raw() != 0
                || entry.mode != gix::index::entry::Mode::FILE
                || entry.flags.intersects(
                    gix::index::entry::Flags::SKIP_WORKTREE
                        | gix::index::entry::Flags::INTENT_TO_ADD
                        | gix::index::entry::Flags::ASSUME_VALID,
                )
                || entry.id != bytes.oid()?
            {
                return Err(Error::DirtyWorktree);
            }
        }
        for (path, bytes) in &out.old {
            check_file(root, path, Some(bytes))?;
        }
        for path in out.next.keys().filter(|path| !out.old.contains_key(*path)) {
            check_file(root, path, None)?;
        }
        let index = repo
            .index_from_tree(&commit(repo, next)?.tree)
            .map_err(|_| Error::Invalid)?;
        let file = &mut out.lock.as_mut().ok_or(Error::Io)?.1;
        index
            .write_to(&mut *file, Default::default())
            .map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        out.index = Some(index);
        Ok(out)
    }

    pub(crate) fn apply(mut self) -> Result<()> {
        let Some(root) = &self.root else {
            return Ok(());
        };
        // Recheck after preparation; refuse changes made while preparing the index.
        for (path, bytes) in &self.old {
            check_file(root, path, Some(bytes))?;
        }
        for (path, bytes) in &self.next {
            if self.old.get(path) == Some(bytes) {
                continue;
            }
            check_file(root, path, self.old.get(path))?;
            let destination = root.join(path);
            let parent = destination.parent().ok_or(Error::Invalid)?;
            create_parents(root, path)?;
            let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| Error::Io)?;
            std::io::copy(&mut bytes.open()?, &mut file).map_err(|_| Error::Io)?;
            file.as_file().sync_all().map_err(|_| Error::Io)?;
            file.persist(&destination).map_err(|_| Error::Io)?;
        }
        for (path, bytes) in self
            .old
            .iter()
            .filter(|(path, _)| !self.next.contains_key(*path))
        {
            check_file(root, path, Some(bytes))?;
            fs::remove_file(root.join(path)).map_err(|_| Error::Io)?;
        }
        let (path, _) = self.lock.as_ref().ok_or(Error::Io)?;
        fs::rename(path, self.index.as_ref().ok_or(Error::Io)?.path()).map_err(|_| Error::Io)?;
        self.lock = None;
        Ok(())
    }
}

impl Drop for Update {
    fn drop(&mut self) {
        if let Some((path, _)) = &self.lock {
            let _ = fs::remove_file(path);
        }
    }
}

fn committed_files(repo: &gix::Repository, id: ObjectId) -> Result<Files> {
    let mut files = Files::new();
    let mut budget = MAX_SNAPSHOT;
    read_tree(repo, commit(repo, id)?.tree, "", &mut files, &mut budget, 0)?;
    Ok(files)
}

fn check_file(root: &Path, relative: &str, expected: Option<&FileData>) -> Result<()> {
    let mut path = root.to_owned();
    let parts: Vec<_> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if index + 1 < parts.len() && meta.is_dir() => {}
            Ok(meta) if index + 1 == parts.len() && meta.is_file() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Err(Error::DirtyWorktree);
                    }
                }
                let expected = expected.ok_or(Error::DirtyWorktree)?;
                if meta.len() != expected.len() as u64 || !same_contents(&path, expected)? {
                    return Err(Error::DirtyWorktree);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && expected.is_none() => {
                return Ok(());
            }
            _ => return Err(Error::DirtyWorktree),
        }
    }
    Ok(())
}

fn create_parents(root: &Path, relative: &str) -> Result<()> {
    let mut path = root.to_owned();
    let parts: Vec<_> = relative.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        path.push(part);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path).map_err(|_| Error::Io)?.is_dir() => {}
            _ => return Err(Error::DirtyWorktree),
        }
    }
    Ok(())
}

fn same_contents(path: &Path, expected: &FileData) -> Result<bool> {
    let mut actual = fs::File::open(path).map_err(|_| Error::Io)?;
    let mut expected = expected.open()?;
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    loop {
        let n = actual.read(&mut a).map_err(|_| Error::Io)?;
        if n == 0 {
            return Ok(expected.read(&mut b[..1]).map_err(|_| Error::Io)? == 0);
        }
        if expected.read_exact(&mut b[..n]).is_err() || a[..n] != b[..n] {
            return Ok(false);
        }
    }
}

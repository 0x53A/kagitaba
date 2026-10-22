//! Application history policy. Merge trees are checked, not trusted on signature alone.
use super::*;
use std::collections::BTreeSet;

type Graph = BTreeMap<ObjectId, gix::objs::Commit>;

/// Iterative postorder: all parents precede their children, including shared ancestors.
pub(super) fn history(
    repo: &gix::Repository,
    head: ObjectId,
) -> Result<Vec<(ObjectId, gix::objs::Commit)>> {
    let mut pending = vec![(head, false)];
    let mut visiting = Graph::new();
    let mut done = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut roots = 0;
    while let Some((id, expanded)) = pending.pop() {
        if done.contains(&id) {
            continue;
        }
        if expanded {
            let c = visiting.remove(&id).ok_or(Error::History)?;
            roots += usize::from(c.parents.is_empty());
            done.insert(id);
            ordered.push((id, c));
            continue;
        }
        if visiting.contains_key(&id) || visiting.len() + done.len() >= 10_000 {
            return Err(Error::History);
        }
        let c = commit(repo, id)?;
        if c.parents.len() > 2 || (c.parents.len() == 2 && c.parents[0] == c.parents[1]) {
            return Err(Error::History);
        }
        pending.push((id, true));
        pending.extend(c.parents.iter().rev().map(|p| (*p, false)));
        visiting.insert(id, c);
    }
    if roots != 1 {
        return Err(Error::History);
    }
    Ok(ordered)
}

fn ancestors(graph: &Graph, head: ObjectId) -> Result<BTreeSet<ObjectId>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![head];
    while let Some(id) = pending.pop() {
        if seen.insert(id) {
            pending.extend(&graph.get(&id).ok_or(Error::History)?.parents);
        }
    }
    Ok(seen)
}

fn merge_base(graph: &Graph, left: ObjectId, right: ObjectId) -> Result<ObjectId> {
    let a = ancestors(graph, left)?;
    let b = ancestors(graph, right)?;
    // Redundant parents are not merges; use a fast-forward instead.
    if a.contains(&right) || b.contains(&left) {
        return Err(Error::History);
    }
    let common: BTreeSet<_> = a.intersection(&b).copied().collect();
    let mut best = common.clone();
    for id in &common {
        for parent in &graph[id].parents {
            best.remove(parent);
        }
    }
    if best.is_empty() {
        return Err(Error::UnrelatedHistory);
    }
    if best.len() != 1 {
        return Err(Error::AmbiguousMergeBase);
    }
    Ok(*best.first().ok_or(Error::History)?)
}

/// Group raw committed bytes: an entry and its grants, or a participant and all
/// metadata, must travel together. Never splice two revisions or ACL changes.
fn units(files: Files) -> Result<BTreeMap<String, Files>> {
    let mut units: BTreeMap<String, Files> = BTreeMap::new();
    for (path, value) in files {
        let parts: Vec<_> = path.split('/').collect();
        let unit = match parts.as_slice() {
            ["kagitaba-format"] => path.clone(),
            ["entries" | "participants" | "cache", id, ..] => format!("{}/{id}", parts[0]),
            _ => return Err(Error::Invalid),
        };
        units.entry(unit).or_default().insert(path, value);
    }
    Ok(units)
}

pub(super) fn merge_files(
    repo: &gix::Repository,
    graph: &Graph,
    left: ObjectId,
    right: ObjectId,
) -> Result<Files> {
    let base = merge_base(graph, left, right)?;
    let base_files = read_files(repo, graph[&base].tree)?;
    let left_files = read_files(repo, graph[&left].tree)?;
    let right_files = read_files(repo, graph[&right].tree)?;
    let metadata: BTreeSet<_> = [&base_files, &left_files, &right_files]
        .into_iter()
        .map(|files| super::snapshot_from_files(files.clone()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flat_map(|snapshot| snapshot.metadata.into_values())
        .collect();
    let base = units(base_files)?;
    let left = units(left_files)?;
    let right = units(right_files)?;
    let keys: BTreeSet<_> = base.keys().chain(left.keys()).chain(right.keys()).collect();
    let mut merged = Files::new();
    for key in keys {
        let (b, l, r) = (base.get(key), left.get(key), right.get(key));
        let additive;
        let chosen = if l == r || r == b {
            l
        } else if l == b {
            r
        } else if key.starts_with("cache/") {
            None
        } else if key
            .strip_prefix("entries/")
            .and_then(|id| id.parse().ok())
            .is_some_and(|id| metadata.contains(&id))
        {
            additive = merge_metadata_grants(b, l, r)?;
            Some(&additive)
        } else {
            return Err(Error::Conflict);
        };
        if let Some(files) = chosen {
            merged.extend(files.clone());
        }
    }
    let enrolled: BTreeSet<_> = merged
        .keys()
        .filter_map(|path| {
            path.strip_prefix("participants/")?
                .strip_suffix("/pub.pem")
                .map(str::to_owned)
        })
        .collect();
    merged.retain(|path, _| {
        !path.starts_with("cache/")
            || path
                .split('/')
                .nth(1)
                .is_some_and(|id| enrolled.contains(id))
    });
    if merged.len() > MAX_FILES || merged.values().map(FileData::len).sum::<usize>() > MAX_SNAPSHOT
    {
        return Err(Error::Invalid);
    }
    let snapshot = super::snapshot_from_files(merged.clone()).map_err(|_| Error::Conflict)?;
    for id in metadata {
        if snapshot.wallet.entries().contains_key(&id) && !snapshot.is_metadata(&id) {
            return Err(Error::Conflict);
        }
    }
    Ok(merged)
}

// Metadata is shared with everyone. Independent grant additions are a clean
// file merge only when both sides retain the exact base primary and all grants.
// Competing revisions and grant removals remain conflicts. Duplicate newly
// added wrappers are omitted here and recreated in the signed repair child.
fn merge_metadata_grants(
    base: Option<&Files>,
    left: Option<&Files>,
    right: Option<&Files>,
) -> Result<Files> {
    let (base, left, right) = (
        base.ok_or(Error::Conflict)?,
        left.ok_or(Error::Conflict)?,
        right.ok_or(Error::Conflict)?,
    );
    let only_adds = |side: &Files| {
        base.iter()
            .all(|(path, bytes)| side.get(path) == Some(bytes))
    };
    let primary = base
        .keys()
        .find(|path| path.ends_with("/primary"))
        .ok_or(Error::Conflict)?;
    if only_adds(left) && right.get(primary) != base.get(primary) {
        return Ok(right.clone());
    }
    if only_adds(right) && left.get(primary) != base.get(primary) {
        return Ok(left.clone());
    }
    if !only_adds(left) || !only_adds(right) {
        return Err(Error::Conflict);
    }
    let mut merged = left.clone();
    for (path, bytes) in right {
        if let Some(old) = merged.insert(path.clone(), bytes.clone())
            && old != *bytes
        {
            // Both added a randomized wrapper for this recipient. Keep neither
            // candidate in the clean merge; the signed child wraps it afresh.
            merged.remove(path);
        }
    }
    Ok(merged)
}

pub(super) fn verify_history(
    repo: &gix::Repository,
    head: ObjectId,
    root: &PublicKey,
    checkpoint: Option<ObjectId>,
) -> Result<Snapshot> {
    let ordered = history(repo, head)?;
    if checkpoint.is_some_and(|id| !ordered.iter().any(|(p, _)| *p == id)) {
        return Err(Error::Checkpoint);
    }
    let graph: Graph = ordered.iter().cloned().collect();
    for (_, mut c) in ordered {
        let sig = signature(&c)?;
        let key = signing::from_ssh(sig.public_key())?;
        let current = read_snapshot(repo, c.tree)?;
        if c.parents.is_empty() && (&key != root || !current.signers.values().any(|k| k == root)) {
            return Err(Error::Signature);
        }
        for parent in &c.parents {
            let old = read_snapshot(repo, graph[parent].tree)?;
            if !old.signers.values().any(|k| k == &key) {
                return Err(Error::Signature);
            }
            validate_transition(&old, &current)?;
        }
        c.extra_headers.clear();
        ssh_public(&key)?
            .verify("git", &bytes(&c)?, &sig)
            .map_err(|_| Error::Signature)?;
        if c.parents.len() == 2 {
            let expected = merge_files(repo, &graph, c.parents[0], c.parents[1])?;
            if read_files(repo, c.tree)? != expected {
                return Err(Error::Conflict);
            }
        }
    }
    read_snapshot(repo, graph[&head].tree)
}

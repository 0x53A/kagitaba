use super::*;
use futures::executor::block_on;
use kagitaba_core::{RevisionId, crypto::SoftwareIdentity};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    pkcs8::EncodePublicKey,
};
use rand_core::SeedableRng;

struct Key {
    secret: SigningKey,
    public: PublicKey,
}
impl Key {
    fn new(n: u8) -> Self {
        let secret = SigningKey::from_slice(&[n; 32]).unwrap();
        let public = PublicKey::from_der(
            secret
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        Self { secret, public }
    }
}
impl Signer for Key {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.secret.sign(bytes);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
fn encryption(n: u8) -> PublicKey {
    SoftwareIdentity::from_bytes(&[n; 32]).unwrap().public_key()
}
fn entry(id: u8, revision: u8) -> Entry {
    let primary = PrimaryRecord::new(
        EntryId::from_bytes([id; 16]),
        RevisionId::from_bytes([revision; 16]),
        vec![revision],
    )
    .unwrap();
    let grant = GrantRecord::new(&primary, encryption(8).id(), vec![revision]).unwrap();
    Entry::from_parts(primary, [grant]).unwrap()
}
fn put(store: &mut Store, key: &Key, entry: Entry, message: &str) {
    let mut next = store.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry).unwrap();
    store.save(next, key, message).unwrap();
}
fn pair() -> (tempfile::TempDir, Key, Store, Store) {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut snapshot = Snapshot::empty(encryption(8), key.public.clone()).unwrap();
    snapshot.wallet = snapshot
        .wallet
        .with_participant(encryption(9))
        .unwrap()
        .with_entry(entry(1, 1))
        .unwrap();
    snapshot
        .signers
        .insert(encryption(9).id(), Key::new(4).public);
    let left = Store::create(&dir.path().join("left"), snapshot, &key).unwrap();
    left.backup_to(&dir.path().join("right")).unwrap();
    let right = Store::open(
        &dir.path().join("right"),
        key.public.clone(),
        Some(left.head),
    )
    .unwrap();
    (dir, key, left, right)
}
fn imported(left: &Store, right: &Store) {
    copy_objects(&right.repo, &left.repo, right.head).unwrap();
}
fn signed_tree(store: &Store, parents: &[ObjectId], snapshot: &Snapshot, key: &Key) -> ObjectId {
    let tree = write_tree(&store.repo, &files(snapshot).unwrap()).unwrap();
    write_commit_tree(&store.repo, parents, tree, key, "Synthetic merge").unwrap()
}

fn name(store: &mut Store, key: &Key, participant: u8, value: &str, seed: u8) {
    let mut next = store.snapshot.clone();
    let backend = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    block_on(next.name_participant(
        encryption(participant).id(),
        value,
        &backend.public_key(),
        &backend,
        &mut rand_chacha::ChaCha20Rng::from_seed([seed; 32]),
    ))
    .unwrap();
    store.save(next, key, "Encrypted participant name").unwrap();
}
fn enroll(store: &mut Store, key: &Key, participant: u8, seed: u8) {
    let mut next = store.snapshot.clone();
    next.wallet = next
        .wallet
        .with_participant(encryption(participant))
        .unwrap();
    next.signers
        .insert(encryption(participant).id(), Key::new(participant).public);
    let backend = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    block_on(next.complete_metadata_grants(
        &backend.public_key(),
        &backend,
        &mut rand_chacha::ChaCha20Rng::from_seed([seed; 32]),
    ))
    .unwrap();
    store.save(next, key, "Enroll and share metadata").unwrap();
}
fn merge_repair(left: &mut Store, right: &Store, key: &Key) -> Result<()> {
    let candidate = left.import_candidate(&right.path)?;
    let backend = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    left.merge_then(candidate, key, |next| {
        block_on(next.complete_metadata_grants(
            &backend.public_key(),
            &backend,
            &mut rand_chacha::ChaCha20Rng::from_seed([77; 32]),
        ))
    })
}

#[test]
fn new_metadata_and_enrollment_merge_then_add_grants_in_a_separate_commit() {
    let (_dir, key, mut left, mut right) = pair();
    enroll(&mut left, &key, 10, 50);
    name(&mut right, &key, 8, "Private name", 51);
    let id = right.snapshot.metadata[&encryption(8).id()];
    let before = right.snapshot.wallet.entries()[&id].clone();
    let parents = [left.head, right.head];
    merge_repair(&mut left, &right, &key).unwrap();
    let repair = commit(&left.repo, left.head).unwrap();
    assert_eq!(repair.parents.len(), 1);
    let merge = commit(&left.repo, repair.parents[0]).unwrap();
    assert_eq!(merge.parents.as_slice(), &parents);
    let clean = read_snapshot(&left.repo, merge.tree).unwrap();
    assert_eq!(clean.wallet.entries()[&id], before);
    let after = &left.snapshot.wallet.entries()[&id];
    assert_eq!(after.primary(), before.primary());
    for (recipient, grant) in before.grants() {
        assert_eq!(after.grants()[recipient], *grant);
    }
    assert_eq!(after.grants().len(), 3);
    for n in [8, 9, 10] {
        let backend = SoftwareIdentity::from_bytes(&[n; 32]).unwrap();
        assert_eq!(
            block_on(
                left.snapshot
                    .participant_names(&backend.public_key(), &backend)
            )
            .unwrap()[&encryption(8).id()],
            "Private name"
        );
    }
    for checkpoint in parents {
        Store::open(&left.path, key.public.clone(), Some(checkpoint)).unwrap();
    }
    assert!(files(&left.snapshot).unwrap().values().all(|bytes| {
        !bytes
            .clone()
            .into_bytes()
            .unwrap()
            .windows(b"Private name".len())
            .any(|w| w == b"Private name")
    }));
    assert!(
        !left
            .path
            .join(format!("participants/{}/name.json", encryption(8).id()))
            .exists()
    );
}

#[test]
fn metadata_revision_and_concurrent_enrollment_rewrap_without_stale_grants() {
    let (_dir, key, mut left, mut right) = pair();
    name(&mut left, &key, 8, "Before", 52);
    right.pull_from(&left.path).unwrap();
    enroll(&mut left, &key, 10, 53);
    name(&mut right, &key, 8, "After", 54);
    let id = right.snapshot.metadata[&encryption(8).id()];
    let updated = right.snapshot.wallet.entries()[&id].clone();
    let stale = left.snapshot.wallet.entries()[&id].grants()[&encryption(10).id()].clone();
    merge_repair(&mut left, &right, &key).unwrap();
    let entry = &left.snapshot.wallet.entries()[&id];
    assert_eq!(entry.primary(), updated.primary());
    assert_ne!(entry.grants()[&encryption(10).id()], stale);
    let backend = SoftwareIdentity::from_bytes(&[10; 32]).unwrap();
    assert_eq!(
        block_on(
            left.snapshot
                .participant_names(&backend.public_key(), &backend)
        )
        .unwrap()[&encryption(8).id()],
        "After"
    );
    assert_eq!(commit(&left.repo, left.head).unwrap().parents.len(), 1);
}

#[test]
fn concurrent_metadata_grant_additions_are_clean_but_name_edits_conflict() {
    let (_dir, key, mut left, mut right) = pair();
    name(&mut left, &key, 8, "Shared name", 55);
    right.pull_from(&left.path).unwrap();
    enroll(&mut left, &key, 10, 56);
    enroll(&mut right, &key, 11, 57);
    merge_repair(&mut left, &right, &key).unwrap();
    assert_eq!(commit(&left.repo, left.head).unwrap().parents.len(), 2);
    let id = left.snapshot.metadata[&encryption(8).id()];
    assert_eq!(left.snapshot.wallet.entries()[&id].grants().len(), 4);
    right.pull_from(&left.path).unwrap();
    name(&mut left, &key, 8, "Left name", 58);
    name(&mut right, &key, 8, "Right name", 59);
    let head = left.head;
    assert!(matches!(
        merge_repair(&mut left, &right, &key),
        Err(Error::Conflict)
    ));
    assert_eq!(left.head, head);
}

#[test]
fn failed_metadata_repair_never_publishes_the_intermediate_merge() {
    let (_dir, key, mut left, mut right) = pair();
    enroll(&mut left, &key, 10, 60);
    name(&mut right, &key, 8, "Private name", 61);
    let candidate = left.import_candidate(&right.path).unwrap();
    let before = left.head;
    let backend = SoftwareIdentity::from_bytes(&[10; 32]).unwrap();
    assert!(
        left.merge_then(candidate, &key, |next| block_on(
            next.complete_metadata_grants(
                &backend.public_key(),
                &backend,
                &mut rand_chacha::ChaCha20Rng::from_seed([62; 32])
            )
        ))
        .is_err()
    );
    assert_eq!(left.head, before);
    assert_eq!(branch(&left.repo).unwrap(), before);
    assert!(left.snapshot.metadata.is_empty());
    struct FailSecond<'a> {
        key: &'a Key,
        calls: std::cell::Cell<usize>,
    }
    impl Signer for FailSecond<'_> {
        fn public_key(&self) -> &PublicKey {
            &self.key.public
        }
        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == 2 {
                return Err(Error::Signing);
            }
            self.key.sign(bytes)
        }
    }
    let signer = FailSecond {
        key: &key,
        calls: std::cell::Cell::new(0),
    };
    let backend = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    assert!(matches!(
        left.merge_then(candidate, &signer, |next| block_on(
            next.complete_metadata_grants(
                &backend.public_key(),
                &backend,
                &mut rand_chacha::ChaCha20Rng::from_seed([62; 32])
            )
        )),
        Err(Error::Signing)
    ));
    assert_eq!(branch(&left.repo).unwrap(), before);
    assert_eq!(left.head, before);
}

#[test]
fn randomized_duplicate_metadata_grants_are_recreated_after_the_clean_merge() {
    let (_dir, key, mut left, mut right) = pair();
    name(&mut left, &key, 8, "Shared name", 80);
    right.pull_from(&left.path).unwrap();
    enroll(&mut left, &key, 10, 81);
    enroll(&mut right, &key, 10, 82);
    let id = left.snapshot.metadata[&encryption(8).id()];
    let old_primary = left.snapshot.wallet.entries()[&id].primary().clone();
    merge_repair(&mut left, &right, &key).unwrap();
    let child = commit(&left.repo, left.head).unwrap();
    assert_eq!(child.parents.len(), 1);
    let merge = commit(&left.repo, child.parents[0]).unwrap();
    assert_eq!(merge.parents.len(), 2);
    let clean = read_snapshot(&left.repo, merge.tree).unwrap();
    assert!(
        !clean.wallet.entries()[&id]
            .grants()
            .contains_key(&encryption(10).id())
    );
    assert_eq!(left.snapshot.wallet.entries()[&id].primary(), &old_primary);
    let backend = SoftwareIdentity::from_bytes(&[10; 32]).unwrap();
    assert_eq!(
        block_on(
            left.snapshot
                .participant_names(&backend.public_key(), &backend)
        )
        .unwrap()[&encryption(8).id()],
        "Shared name"
    );
}

#[test]
fn metadata_pointers_are_unique_registered_and_cannot_dangle_after_merge() {
    let (_dir, key, mut left, mut right) = pair();
    name(&mut left, &key, 8, "Before", 63);
    right.pull_from(&left.path).unwrap();
    let id = left.snapshot.metadata[&encryption(8).id()];
    let mut bad = left.snapshot.clone();
    bad.metadata.insert(encryption(9).id(), id);
    assert!(bad.validate().is_err());
    bad = left.snapshot.clone();
    bad.wallet = bad.wallet.without_entry(id).unwrap();
    assert!(bad.validate().is_err());
    let mut deleted = left.snapshot.clone();
    deleted.metadata.remove(&encryption(8).id());
    deleted.wallet = deleted.wallet.without_entry(id).unwrap();
    left.save(deleted, &key, "Remove metadata").unwrap();
    name(&mut right, &key, 8, "Concurrent edit", 64);
    assert!(matches!(
        merge_repair(&mut left, &right, &key),
        Err(Error::Conflict)
    ));
}

#[test]
fn legacy_public_names_migrate_and_old_history_remains_verifiable() {
    let (_dir, key, mut left, _right) = pair();
    let mut legacy = left.snapshot.clone();
    legacy
        .names
        .insert(encryption(8).id(), "Legacy private label".into());
    left.save(legacy, &key, "Legacy public label").unwrap();
    let checkpoint = left.head;
    let backend = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    // Even an old plaintext label is not returned by the unlocked metadata API.
    assert!(
        block_on(
            left.snapshot
                .participant_names(&backend.public_key(), &backend)
        )
        .unwrap()
        .is_empty()
    );
    let mut next = left.snapshot.clone();
    next.prune_legacy(&mut rand_chacha::ChaCha20Rng::from_seed([65; 32]))
        .unwrap();
    left.save(next, &key, "Encrypt participant metadata")
        .unwrap();
    let reopened = Store::open(&left.path, key.public.clone(), Some(checkpoint)).unwrap();
    assert!(reopened.snapshot.names.is_empty());
    assert_eq!(
        block_on(
            reopened
                .snapshot
                .participant_names(&backend.public_key(), &backend)
        )
        .unwrap()[&encryption(8).id()],
        "Legacy private label"
    );
    assert!(
        !left
            .path
            .join(format!("participants/{}/name.json", encryption(8).id()))
            .exists()
    );
}

#[test]
fn independent_enrollment_and_entries_merge_preserving_both_histories_and_bytes() {
    let (dir, key, mut left, mut right) = pair();
    let genesis = left.head;
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.with_participant(encryption(10)).unwrap();
    next.signers.insert(encryption(10).id(), Key::new(5).public);
    left.save(next, &key, "Enroll").unwrap();
    put(&mut right, &key, entry(2, 2), "Add one");
    put(&mut right, &key, entry(3, 3), "Add two");
    let (a, b) = (left.head, right.head);
    let expected_entries = right.snapshot.wallet.entries().clone();
    left.merge_from(&right.path, &key).unwrap();
    assert_eq!(
        commit(&left.repo, left.head).unwrap().parents.as_slice(),
        &[a, b]
    );
    assert_eq!(left.snapshot.wallet.entries(), &expected_entries);
    assert_eq!(left.snapshot.wallet.participants().len(), 3);
    for checkpoint in [genesis, a, b] {
        assert!(Store::open(&left.path, key.public.clone(), Some(checkpoint)).is_ok());
    }
    assert_eq!(Store::inspect_root(&left.path).unwrap(), key.public);
    right
        .import_transfer(&left.export_transfer().unwrap())
        .unwrap();
    assert_eq!(right.head, left.head);
    assert!(matches!(left.accept(a), Err(Error::Checkpoint)));
    // A second divergence after a merge exercises DAG traversal and merge-base selection.
    put(&mut left, &key, entry(4, 4), "Later left");
    put(&mut right, &key, entry(5, 5), "Later right");
    left.merge_from(&right.path, &key).unwrap();
    left.backup_to(&dir.path().join("backup")).unwrap();
    assert!(Store::open(&dir.path().join("backup"), key.public, Some(b)).is_ok());
}

#[test]
fn different_revisions_delete_edit_and_concurrent_grants_conflict_atomically() {
    for case in 0..3 {
        let (_dir, key, mut left, mut right) = pair();
        let mut a = left.snapshot.clone();
        let mut b = right.snapshot.clone();
        if case < 2 {
            a.wallet = a.wallet.with_entry(entry(1, 2)).unwrap();
            b.wallet = if case == 0 {
                b.wallet.with_entry(entry(1, 3)).unwrap()
            } else {
                b.wallet
                    .without_entry(EntryId::from_bytes([1; 16]))
                    .unwrap()
            };
        } else {
            let original = entry(1, 1);
            a.wallet = a
                .wallet
                .with_entry(Entry::from_parts(original.primary().clone(), []).unwrap())
                .unwrap();
            let grant = GrantRecord::new(original.primary(), encryption(9).id(), vec![9]).unwrap();
            b.wallet = b
                .wallet
                .with_entry(original.with_grant(grant).unwrap())
                .unwrap();
        }
        left.save(a, &key, "Left").unwrap();
        right.save(b, &key, "Right").unwrap();
        let before = left.head;
        let index = std::fs::read(left.path.join(".git/index")).unwrap();
        assert!(matches!(
            left.merge_from(&right.path, &key),
            Err(Error::Conflict)
        ));
        assert_eq!(left.head, before);
        assert_eq!(branch(&left.repo).unwrap(), before);
        assert_eq!(std::fs::read(left.path.join(".git/index")).unwrap(), index);
    }
}

#[test]
fn identical_changes_and_one_sided_deletion_are_preserved() {
    let (_dir, key, mut left, mut right) = pair();
    put(&mut left, &key, entry(2, 2), "Left identical");
    put(&mut right, &key, entry(2, 2), "Right identical");
    let mut next = right.snapshot.clone();
    next.wallet = next
        .wallet
        .without_entry(EntryId::from_bytes([1; 16]))
        .unwrap();
    right.save(next, &key, "Delete").unwrap();
    left.merge_from(&right.path, &key).unwrap();
    assert_eq!(left.snapshot.wallet.entries().len(), 1);
    assert!(
        left.snapshot
            .wallet
            .entries()
            .contains_key(&EntryId::from_bytes([2; 16]))
    );
}

#[test]
fn signer_must_survive_on_both_sides_and_revocation_is_not_undone() {
    let (_dir, key, mut left, mut right) = pair();
    let other = Key::new(4);
    put(&mut left, &other, entry(2, 2), "Other signer before merge");
    let mut next = right.snapshot.clone();
    next.wallet =
        Wallet::from_parts([encryption(8)], next.wallet.entries().values().cloned()).unwrap();
    next.signers.remove(&encryption(9).id());
    right.save(next, &key, "Revoke other signer").unwrap();
    let before = left.head;
    assert!(matches!(
        left.merge_from(&right.path, &other),
        Err(Error::Signature)
    ));
    assert_eq!(left.head, before);
    let mut union = left.snapshot.clone();
    union.wallet =
        Wallet::from_parts([encryption(8)], union.wallet.entries().values().cloned()).unwrap();
    union.signers.remove(&encryption(9).id());
    let bad = signed_tree(&left, &[left.head, right.head], &union, &other);
    assert!(matches!(left.accept(bad), Err(Error::Signature)));
    left.merge_from(&right.path, &key).unwrap();
    assert!(!left.snapshot.signers.contains_key(&encryption(9).id()));
}

#[test]
fn conflicting_participant_metadata_and_dangling_grants_fail_closed() {
    let (_dir, key, mut left, mut right) = pair();
    for (store, serial) in [(&mut left, "123"), (&mut right, "456")] {
        let mut next = store.snapshot.clone();
        next.devices.insert(
            encryption(8).id(),
            DeviceHint {
                serial: serial.into(),
                encryption_slot: 0x82,
                signing_slot: 0x83,
            },
        );
        store.save(next, &key, "Metadata").unwrap();
    }
    assert!(matches!(
        left.merge_from(&right.path, &key),
        Err(Error::Conflict)
    ));

    let (_dir, key, mut left, mut right) = pair();
    let original = entry(2, 2);
    let grant = GrantRecord::new(original.primary(), encryption(9).id(), vec![9]).unwrap();
    put(
        &mut left,
        &key,
        original.with_grant(grant).unwrap(),
        "Grant to soon removed key",
    );
    let mut next = right.snapshot.clone();
    next.wallet =
        Wallet::from_parts([encryption(8)], next.wallet.entries().values().cloned()).unwrap();
    next.signers.remove(&encryption(9).id());
    right.save(next, &key, "Remove").unwrap();
    let before = left.head;
    assert!(left.merge_from(&right.path, &key).is_err());
    assert_eq!(left.head, before);
}

#[test]
fn signed_merge_cannot_drop_changes_add_changes_or_hide_invalid_second_parent() {
    let (_dir, key, mut left, mut right) = pair();
    put(&mut left, &key, entry(2, 2), "Left");
    put(&mut right, &key, entry(3, 3), "Right");
    imported(&left, &right);
    let before = left.head;
    let dropped = signed_tree(&left, &[left.head, right.head], &left.snapshot, &key);
    assert!(matches!(left.accept(dropped), Err(Error::Conflict)));
    let mut extra = left.snapshot.clone();
    extra.wallet = extra
        .wallet
        .with_entry(entry(3, 3))
        .unwrap()
        .with_entry(entry(4, 4))
        .unwrap();
    let added = signed_tree(&left, &[left.head, right.head], &extra, &key);
    assert!(matches!(left.accept(added), Err(Error::Conflict)));
    let unauthorized = signed_tree(&left, &[right.head], &right.snapshot, &Key::new(11));
    let hidden = signed_tree(&left, &[left.head, unauthorized], &extra, &key);
    assert!(matches!(left.accept(hidden), Err(Error::Signature)));
    assert_eq!(left.head, before);
}

#[test]
fn ambiguous_bases_unrelated_roots_and_redundant_or_extra_parents_are_rejected() {
    let (dir, key, mut left, mut right) = pair();
    let root = left.head;
    put(&mut left, &key, entry(2, 2), "Left");
    put(&mut right, &key, entry(3, 3), "Right");
    imported(&left, &right);
    let (a, b) = (left.head, right.head);
    for parents in [vec![a, a], vec![a, root], vec![a, b, root]] {
        let bad = signed_tree(&left, &parents, &left.snapshot, &key);
        assert!(matches!(left.accept(bad), Err(Error::History)));
    }
    left.merge(b, &key).unwrap();
    let reverse = signed_tree(&left, &[b, a], &left.snapshot, &key);
    assert!(verify_history(&left.repo, reverse, &key.public, Some(b)).is_ok());
    assert!(matches!(
        left.merge(reverse, &key),
        Err(Error::AmbiguousMergeBase)
    ));
    let mut separate = left.snapshot.clone();
    separate.wallet = separate.wallet.with_entry(entry(6, 6)).unwrap();
    let unrelated = Store::create(&dir.path().join("unrelated"), separate, &key).unwrap();
    assert!(matches!(
        left.merge_from(&unrelated.path, &key),
        Err(Error::UnrelatedHistory)
    ));
}

#[test]
fn fast_forward_and_already_merged_heads_need_no_new_signature() {
    let (_dir, key, mut left, mut right) = pair();
    let genesis = left.head;
    put(&mut right, &key, entry(2, 2), "Right");
    // The key is deliberately not enrolled: no merge signature is needed.
    left.merge_from(&right.path, &Key::new(11)).unwrap();
    assert_eq!(left.head, right.head);
    left.merge(genesis, &Key::new(11)).unwrap();
    assert_eq!(left.head, right.head);
}

#[test]
fn friendly_names_are_signed_preserved_and_merge_as_participant_units() {
    let (_dir, key, mut left, mut right) = pair();
    let original = left.snapshot.wallet.clone();
    let mut a = left.snapshot.clone();
    a.names.insert(encryption(8).id(), "Everyday key".into());
    left.save(a, &key, "Name first key").unwrap();
    let mut b = right.snapshot.clone();
    b.names.insert(encryption(9).id(), "Backup key".into());
    right.save(b, &key, "Name backup key").unwrap();
    left.merge_from(&right.path, &key).unwrap();
    assert_eq!(left.snapshot.wallet, original);
    let reopened = Store::open(&left.path, key.public.clone(), Some(right.head)).unwrap();
    assert_eq!(reopened.snapshot.names, left.snapshot.names);
    right
        .import_transfer(&left.export_transfer().unwrap())
        .unwrap();
    for (store, name) in [(&mut left, "Laptop"), (&mut right, "Desktop")] {
        let mut next = store.snapshot.clone();
        next.names.insert(encryption(8).id(), name.into());
        store.save(next, &key, "Concurrent rename").unwrap();
    }
    assert!(matches!(
        left.merge_from(&right.path, &key),
        Err(Error::Conflict)
    ));
    let mut invalid = left.snapshot.clone();
    invalid
        .names
        .insert(encryption(10).id(), "Not enrolled".into());
    assert!(invalid.validate().is_err());
    let mut clear = left.snapshot.clone();
    clear.names.remove(&encryption(8).id());
    left.save(clear, &key, "Remove name").unwrap();
    assert!(
        !left
            .path
            .join(format!("participants/{}/name.json", encryption(8).id()))
            .exists()
    );
}

#[test]
fn dirty_worktree_stale_store_and_signing_failure_leave_heads_unchanged() {
    struct Denied(PublicKey);
    impl Signer for Denied {
        fn public_key(&self) -> &PublicKey {
            &self.0
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Signing)
        }
    }
    let (_dir, key, mut left, mut right) = pair();
    put(&mut left, &key, entry(2, 2), "Left");
    put(&mut right, &key, entry(3, 3), "Right");
    let before = left.head;
    assert!(matches!(
        left.merge_from(&right.path, &Denied(key.public.clone())),
        Err(Error::Signing)
    ));
    assert_eq!(branch(&left.repo).unwrap(), before);
    let mut stale = Store::open(&left.path, key.public.clone(), Some(before)).unwrap();
    put(&mut left, &key, entry(4, 4), "Advance");
    assert!(matches!(
        stale.merge_from(&right.path, &key),
        Err(Error::Stale)
    ));
    let before = left.head;
    std::fs::write(left.path.join("kagitaba-format"), b"dirty").unwrap();
    assert!(matches!(
        left.merge_from(&right.path, &key),
        Err(Error::DirtyWorktree)
    ));
    assert_eq!(branch(&left.repo).unwrap(), before);
    assert_eq!(
        std::fs::read(left.path.join("kagitaba-format")).unwrap(),
        b"dirty"
    );
}

#[test]
fn participant_cache_conflicts_are_dropped_but_keys_are_authoritative() {
    for (left_value, right_value, expected) in [
        (Some(2), Some(3), None),
        (None, Some(3), None),
        (Some(2), Some(2), Some(2)),
        (Some(1), Some(3), Some(3)),
    ] {
        let (_dir, key, mut left, mut right) = pair();
        let participant = encryption(8);
        let id = participant.id();
        let mut next = left.snapshot.clone();
        next.provision_index_key(
            &participant,
            &mut rand_chacha::ChaCha20Rng::from_seed([23; 32]),
        )
        .unwrap();
        next.indexes.insert(id, vec![1]);
        left.save(next, &key, "Provision index").unwrap();
        right.pull_from(&left.path).unwrap();
        let wrapper = left.snapshot.index_keys[&id].clone();
        for (store, value) in [(&mut left, left_value), (&mut right, right_value)] {
            let mut next = store.snapshot.clone();
            match value {
                Some(value) => {
                    next.indexes.insert(id, vec![value]);
                }
                None => {
                    next.indexes.remove(&id);
                }
            }
            store.save(next, &key, "Refresh index").unwrap();
        }
        left.merge_from(&right.path, &key).unwrap();
        assert_eq!(
            left.snapshot.indexes.get(&id),
            expected.map(|v| vec![v]).as_ref()
        );
        assert_eq!(left.snapshot.index_keys[&id], wrapper);
        let opened = Store::open(&left.path, key.public.clone(), Some(right.head)).unwrap();
        assert_eq!(opened.snapshot.indexes, left.snapshot.indexes);
    }
}

#[test]
fn removed_participant_cache_is_pruned_even_if_other_branch_refreshes_it() {
    let (_dir, key, mut left, mut right) = pair();
    let participant = encryption(9);
    let id = participant.id();
    let mut next = left.snapshot.clone();
    next.provision_index_key(
        &participant,
        &mut rand_chacha::ChaCha20Rng::from_seed([24; 32]),
    )
    .unwrap();
    next.indexes.insert(id, vec![1]);
    left.save(next, &key, "Provision index").unwrap();
    right.pull_from(&left.path).unwrap();
    let mut next = left.snapshot.clone();
    next.wallet = Wallet::from_parts(
        next.wallet
            .participants()
            .values()
            .filter(|p| p.id() != id)
            .cloned(),
        next.wallet.entries().values().cloned(),
    )
    .unwrap();
    next.signers.remove(&id);
    next.index_keys.remove(&id);
    next.indexes.remove(&id);
    left.save(next, &key, "Remove participant").unwrap();
    let mut next = right.snapshot.clone();
    next.indexes.insert(id, vec![2]);
    right.save(next, &key, "Refresh departed index").unwrap();
    left.merge_from(&right.path, &key).unwrap();
    assert!(!left.snapshot.indexes.contains_key(&id));
    assert!(!left.snapshot.index_keys.contains_key(&id));
}

#[test]
fn independently_provisioned_index_keys_conflict_as_authoritative_metadata() {
    let (_dir, key, mut left, mut right) = pair();
    for (store, seed) in [(&mut left, 25), (&mut right, 26)] {
        let mut next = store.snapshot.clone();
        next.provision_index_key(
            &encryption(8),
            &mut rand_chacha::ChaCha20Rng::from_seed([seed; 32]),
        )
        .unwrap();
        store.save(next, &key, "Provision index key").unwrap();
    }
    let before = left.head;
    assert!(matches!(
        left.merge_from(&right.path, &key),
        Err(Error::Conflict)
    ));
    assert_eq!(left.head, before);
}

#[test]
fn index_paths_require_enrolled_keys_but_disposable_ciphertext_can_be_rebuilt() {
    let public = encryption(8);
    let id = public.id();
    let mut snapshot = Snapshot::empty(public.clone(), Key::new(3).public).unwrap();
    snapshot.indexes.insert(id, vec![0]);
    assert!(snapshot.validate().is_err());
    snapshot
        .provision_index_key(&public, &mut rand_chacha::ChaCha20Rng::from_seed([27; 32]))
        .unwrap();
    snapshot.validate().unwrap();
    let parsed = snapshot_from_files(files(&snapshot).unwrap()).unwrap();
    assert_eq!(parsed.indexes[&id], vec![0]);
    snapshot
        .indexes
        .insert(id, vec![0; index::MAX_INDEX_BYTES + 1]);
    assert!(snapshot.validate().is_err());
    snapshot.indexes.clear();
    let mut wrong = snapshot.index_keys.remove(&id).unwrap();
    snapshot
        .index_keys
        .insert(encryption(9).id(), wrong.clone());
    assert!(snapshot.validate().is_err());
    snapshot.index_keys.clear();
    wrong[4] ^= 1;
    snapshot.index_keys.insert(id, wrong);
    assert!(snapshot.validate().is_err());
}

fn attachment_chunks(count: usize) -> Vec<Vec<u8>> {
    use kagitaba_core::crypto::{Ciphertext, ContentKey};
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([81; 32]);
    let key = ContentKey::from_bytes([82; 32]);
    let bytes = vec![0; kagitaba_cxf::attachments::CHUNK_BYTES];
    let chunk = Ciphertext::seal(&bytes, &key, b"synthetic storage fixture", &mut rng)
        .unwrap()
        .as_bytes()
        .to_vec();
    vec![chunk; count]
}
fn attach(snapshot: &mut Snapshot, owner: u8, blob: u8, count: usize) {
    snapshot
        .attachments
        .entry(EntryId::from_bytes([owner; 16]))
        .or_default()
        .insert(
            EntryId::from_bytes([blob; 16]).to_string(),
            AttachmentBlob::from_chunks(&attachment_chunks(count)).unwrap(),
        );
}

#[test]
fn attachment_layout_and_revision_policy() {
    let (_dir, _key, left, _) = pair();
    let mut old = left.snapshot.clone();
    attach(&mut old, 1, 11, 1);
    let encoded = files(&old).unwrap();
    let decoded = snapshot_from_files(encoded.clone()).unwrap();
    assert_eq!(decoded.attachments, old.attachments);
    let path = format!(
        "entries/{}/attachments/{}",
        EntryId::from_bytes([1; 16]),
        EntryId::from_bytes([11; 16])
    );
    assert!(encoded.contains_key(&path));
    let mut bad = encoded.clone();
    bad.insert(path.clone(), FileData::Bytes(vec![0]));
    assert!(snapshot_from_files(bad).is_err());
    let mut bad = old.clone();
    attach(&mut bad, 2, 12, 1);
    assert!(bad.validate().is_err());
    let mut next = old.clone();
    attach(&mut next, 1, 12, 1);
    assert!(validate_transition(&old, &next).is_err());
    next.wallet = next.wallet.with_entry(entry(1, 2)).unwrap();
    assert!(validate_transition(&old, &next).is_ok());
    let mut modified = next.clone();
    let mut changed = attachment_chunks(1);
    changed[0][80] ^= 1;
    modified
        .attachments
        .get_mut(&EntryId::from_bytes([1; 16]))
        .unwrap()
        .insert(
            EntryId::from_bytes([11; 16]).to_string(),
            AttachmentBlob::from_chunks(&changed).unwrap(),
        );
    assert!(validate_transition(&old, &modified).is_err());
    let primary = entry(1, 3).primary().clone();
    next.wallet = next
        .wallet
        .with_entry(Entry::from_parts(primary, []).unwrap())
        .unwrap();
    assert!(validate_transition(&old, &next).is_err());
    next.attachments
        .get_mut(&EntryId::from_bytes([1; 16]))
        .unwrap()
        .remove(&EntryId::from_bytes([11; 16]).to_string());
    assert!(validate_transition(&old, &next).is_ok());
}

#[test]
fn attachments_are_atomic_with_their_owner_in_merges() {
    let (_dir, key, mut left, mut right) = pair();
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry(1, 2)).unwrap();
    attach(&mut next, 1, 11, 1);
    left.save(next, &key, "Attach synthetic file").unwrap();
    put(&mut right, &key, entry(1, 3), "Concurrent edit");
    assert!(left.merge_from(&right.path, &key).is_err());
}

#[test]
fn attachment_larger_than_sixteen_mib_survives_backup_and_transfer() {
    let (dir, key, mut left, mut right) = pair();
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry(1, 2)).unwrap();
    attach(&mut next, 1, 11, 17);
    left.save(next, &key, "Attach synthetic large file")
        .unwrap();
    left.backup_to(&dir.path().join("large-backup")).unwrap();
    let backup = Store::open(
        &dir.path().join("large-backup"),
        key.public.clone(),
        Some(left.head),
    )
    .unwrap();
    assert_eq!(backup.snapshot.attachments, left.snapshot.attachments);
    right
        .import_transfer(&left.export_transfer().unwrap())
        .unwrap();
    assert_eq!(right.snapshot.attachments, left.snapshot.attachments);
}

#[test]
fn signed_attachment_changes_cannot_bypass_transition_validation() {
    let (_dir, key, mut left, _) = pair();
    let original = left.head;
    let mut bad = left.snapshot.clone();
    attach(&mut bad, 1, 11, 1);
    let candidate = signed_tree(&left, &[left.head], &bad, &key);
    assert!(left.accept(candidate).is_err());
    assert_eq!(left.head, original);
}

#[test]
fn independent_attachment_entries_merge_and_owner_delete_removes_files() {
    let (_dir, key, mut left, mut right) = pair();
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry(1, 2)).unwrap();
    attach(&mut next, 1, 11, 1);
    left.save(next, &key, "First attachment").unwrap();
    let mut next = right.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry(2, 1)).unwrap();
    attach(&mut next, 2, 12, 1);
    right.save(next, &key, "Other owner").unwrap();
    left.merge_from(&right.path, &key).unwrap();
    assert_eq!(left.snapshot.attachments.len(), 2);
    let id = EntryId::from_bytes([1; 16]);
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.without_entry(id).unwrap();
    assert!(next.validate().is_err());
    next.attachments.remove(&id);
    left.save(next, &key, "Delete owner").unwrap();
    assert!(
        files(&left.snapshot)
            .unwrap()
            .keys()
            .all(|path| !path.starts_with(&format!("entries/{id}/")))
    );
}

#[test]
fn opening_wallet_defers_attachment_contents_until_requested() {
    let (_dir, key, mut left, _) = pair();
    let mut next = left.snapshot.clone();
    next.wallet = next.wallet.with_entry(entry(1, 2)).unwrap();
    attach(&mut next, 1, 11, 1);
    left.save(next, &key, "Lazy attachment").unwrap();
    let blob = &left.snapshot.attachments[&EntryId::from_bytes([1; 16])]
        [&EntryId::from_bytes([11; 16]).to_string()];
    let oid = blob.oid().to_string();
    let object = left
        .repo
        .git_dir()
        .join("objects")
        .join(&oid[..2])
        .join(&oid[2..]);
    let mut compressed = std::fs::read(&object).unwrap();
    *compressed.last_mut().unwrap() ^= 1;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(object, compressed).unwrap();
    // Reading signed metadata needs only the object's header, not its payload.
    let reopened = Store::open(&left.path, key.public.clone(), Some(left.head)).unwrap();
    let lazy = &reopened.snapshot.attachments[&EntryId::from_bytes([1; 16])]
        [&EntryId::from_bytes([11; 16]).to_string()];
    // Explicit access authenticates the Git object before exposing its contents.
    let result = lazy.open().and_then(|mut reader| {
        std::io::copy(&mut reader, &mut std::io::sink()).map_err(|_| Error::Invalid)
    });
    assert!(result.is_err());
}

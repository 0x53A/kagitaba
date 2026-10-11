use gix::refs::transaction::PreviousValue;
use kagitaba_core::{
    crypto::{PublicKey, SoftwareIdentity},
    wallet::Wallet,
};
use kagitaba_store::{Error, Result, Signer, Snapshot, Store};
use rand_core::SeedableRng;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    pkcs8::EncodePublicKey,
};
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
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let s: Signature = self.secret.sign(msg);
        Ok(s.to_der().as_bytes().to_vec())
    }
}
fn snapshot(key: &Key) -> Snapshot {
    Snapshot::empty(
        SoftwareIdentity::from_bytes(&[8; 32]).unwrap().public_key(),
        key.public.clone(),
    )
    .unwrap()
}

#[test]
fn browser_transfer_preserves_signed_history_and_rejects_tampering_and_rollback() {
    let key = Key::new(12);
    let dir = tempfile::tempdir().unwrap();
    let mut source = Store::create(&dir.path().join("source"), snapshot(&key), &key).unwrap();
    let initial = source.export_transfer().unwrap();
    source.backup_to(&dir.path().join("replica")).unwrap();
    let mut replica = Store::open(
        &dir.path().join("replica"),
        key.public.clone(),
        Some(source.head),
    )
    .unwrap();
    source
        .save(source.snapshot.clone(), &key, "Update")
        .unwrap();
    let transfer = source.export_transfer().unwrap();
    let browser_backup = serde_json::json!({"wallet":serde_json::from_slice::<serde_json::Value>(&transfer).unwrap(), "installation":{"ignored":"unsigned outer metadata"}});
    replica
        .import_transfer(&serde_json::to_vec(&browser_backup).unwrap())
        .unwrap();
    assert_eq!(source.head, replica.head);
    assert!(replica.import_transfer(&initial).is_err());
    let mut tampered: serde_json::Value = serde_json::from_slice(&transfer).unwrap();
    tampered["objects"][0]["data"] = serde_json::json!("YWJj");
    assert!(
        replica
            .import_transfer(&serde_json::to_vec(&tampered).unwrap())
            .is_err()
    );
    assert_eq!(source.head, replica.head);
}

#[test]
fn legacy_browser_packages_are_verified_then_pruned_without_rewriting_history() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = Key::new(13);
    let mut snapshot = snapshot(&key);
    let (id, encryption) = snapshot.wallet.participants().first_key_value().unwrap();
    let id = *id;
    let mut envelope = [4; 144];
    envelope[..4].copy_from_slice(b"KTC1");
    let metadata = serde_json::json!({
        "format":"kagitaba-browser-installation", "version":1,
        "participantPem":encryption.to_pem(), "participantId":id.to_string(),
        "signingPem":key.public.to_pem(), "signingId":key.public.id().to_string(),
        "installationId":"01010101010101010101010101010101",
        "unlock":{"rpId":"kagitaba.local", "prfInput":URL_SAFE_NO_PAD.encode([2;32]), "credentialId":URL_SAFE_NO_PAD.encode([3;32])},
        "envelope":URL_SAFE_NO_PAD.encode(envelope)
    });
    snapshot.browsers.insert(id, metadata.clone());
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(&dir.path().join("wallet"), snapshot.clone(), &key).unwrap();
    let loaded = Store::open(&store.path, key.public.clone(), Some(store.head)).unwrap();
    assert_eq!(loaded.snapshot.browsers[&id], metadata);
    let legacy_head = store.head;
    let mut next = loaded.snapshot.clone();
    next.prune_legacy(&mut rand_chacha::ChaCha20Rng::from_seed([90;32])).unwrap();
    store.save(next, &key, "Prune installation recovery data").unwrap();
    assert!(!store.path.join(format!("participants/{id}/browser.json")).exists());
    assert!(Store::open(&store.path, key.public.clone(), Some(legacy_head)).unwrap().snapshot.browsers.is_empty());
    snapshot.browsers.get_mut(&id).unwrap()["identity"] = serde_json::json!("must never persist");
    assert!(snapshot.validate().is_err());
}

fn git(path: &std::path::Path, args: &[&str]) -> Vec<u8> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn normal_repo_adopts_empty_git_init_and_keeps_index_and_worktree_current() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main"]);
    git(
        dir.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/wallet.git",
        ],
    );
    let key = Key::new(3);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    assert!(dir.path().join(".git").is_dir());
    assert_eq!(
        std::fs::read(dir.path().join("kagitaba-format")).unwrap(),
        b"1\n"
    );
    assert_eq!(git(dir.path(), &["branch", "--show-current"]), b"wallet\n");
    assert_eq!(
        git(dir.path(), &["remote", "get-url", "origin"]),
        b"https://example.invalid/wallet.git\n"
    );
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
    let id = *store.snapshot.wallet.participants().keys().next().unwrap();
    let path = dir.path().join(format!("participants/{id}/device.json"));
    let mut next = store.snapshot.clone();
    next.devices.insert(
        id,
        kagitaba_store::DeviceHint {
            serial: "123456".into(),
            encryption_slot: 0x84,
            signing_slot: 0x85,
        },
    );
    store.save(next, &key, "Remember device").unwrap();
    assert!(path.is_file());
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
    let mut next = store.snapshot.clone();
    next.devices.clear();
    store.save(next, &key, "Remove hint").unwrap();
    assert!(!path.exists());
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
}

#[test]
fn initialized_repositories_with_staged_files_or_history_are_not_repurposed() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main"]);
    let head = std::fs::read(dir.path().join(".git/HEAD")).unwrap();
    let key = Key::new(3);
    std::fs::write(dir.path().join("staged"), "keep staged content").unwrap();
    git(dir.path(), &["add", "staged"]);
    std::fs::remove_file(dir.path().join("staged")).unwrap();
    let index = std::fs::read(dir.path().join(".git/index")).unwrap();
    assert!(matches!(
        Store::create(dir.path(), snapshot(&key), &key),
        Err(Error::DestinationNotEmpty)
    ));
    assert_eq!(std::fs::read(dir.path().join(".git/index")).unwrap(), index);
    assert_eq!(std::fs::read(dir.path().join(".git/HEAD")).unwrap(), head);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@localhost",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Existing history",
        ],
    );
    assert!(matches!(
        Store::create(dir.path(), snapshot(&key), &key),
        Err(Error::DestinationNotEmpty)
    ));
    assert_eq!(std::fs::read(dir.path().join(".git/HEAD")).unwrap(), head);
}

#[test]
fn reference_lock_failure_does_not_change_the_checkout() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    let index = std::fs::read(dir.path().join(".git/index")).unwrap();
    let lock = dir.path().join(".git/refs/heads/wallet.lock");
    std::fs::write(&lock, "other writer").unwrap();
    let mut next = store.snapshot.clone();
    let enc = SoftwareIdentity::from_bytes(&[9; 32]).unwrap().public_key();
    let id = enc.id();
    next.wallet = next.wallet.with_participant(enc).unwrap();
    next.signers.insert(id, key.public.clone());
    assert!(matches!(
        store.save(next, &key, "Blocked"),
        Err(Error::Stale)
    ));
    assert!(!dir.path().join(format!("participants/{id}")).exists());
    assert_eq!(std::fs::read(dir.path().join(".git/index")).unwrap(), index);
    assert_eq!(std::fs::read(lock).unwrap(), b"other writer");
}

#[test]
fn dirty_or_staged_files_are_preserved_and_never_used_as_wallet_state() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    let head = store.head;
    let format = dir.path().join("kagitaba-format");
    std::fs::write(&format, "local edit\n").unwrap();
    assert!(Store::open(dir.path(), key.public.clone(), Some(head)).is_ok());
    assert!(matches!(
        store.save(store.snapshot.clone(), &key, "No overwrite"),
        Err(Error::DirtyWorktree)
    ));
    assert_eq!(std::fs::read(&format).unwrap(), b"local edit\n");
    git(dir.path(), &["add", "kagitaba-format"]);
    let index = std::fs::read(dir.path().join(".git/index")).unwrap();
    std::fs::write(&format, "1\n").unwrap();
    assert!(matches!(
        store.save(store.snapshot.clone(), &key, "No staged overwrite"),
        Err(Error::DirtyWorktree)
    ));
    assert_eq!(std::fs::read(dir.path().join(".git/index")).unwrap(), index);
    assert_eq!(
        git(dir.path(), &["rev-parse", "HEAD"]),
        format!("{head}\n").as_bytes()
    );
    assert!(!dir.path().join(".git/index.lock").exists());
}

#[test]
fn conflicting_untracked_paths_wrong_branch_and_index_locks_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    let id = *store.snapshot.wallet.participants().keys().next().unwrap();
    let path = dir.path().join(format!("participants/{id}/device.json"));
    std::fs::write(&path, "keep me").unwrap();
    let mut next = store.snapshot.clone();
    next.devices.insert(
        id,
        kagitaba_store::DeviceHint {
            serial: "123456".into(),
            encryption_slot: 0x84,
            signing_slot: 0x85,
        },
    );
    assert!(matches!(
        store.save(next, &key, "Conflict"),
        Err(Error::DirtyWorktree)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    git(dir.path(), &["checkout", "-b", "other"]);
    assert!(matches!(
        store.save(store.snapshot.clone(), &key, "Wrong branch"),
        Err(Error::WrongBranch)
    ));
    git(dir.path(), &["checkout", "wallet"]);
    std::fs::write(dir.path().join(".git/index.lock"), "other process").unwrap();
    assert!(matches!(
        store.save(store.snapshot.clone(), &key, "Locked"),
        Err(Error::WorktreeLocked)
    ));
    assert_eq!(
        std::fs::read(dir.path().join(".git/index.lock")).unwrap(),
        b"other process"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_wallet_paths_are_not_followed_when_saving() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    std::fs::rename(
        dir.path().join("participants"),
        outside.path().join("participants"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("participants"),
        dir.path().join("participants"),
    )
    .unwrap();
    assert!(matches!(
        store.save(store.snapshot.clone(), &key, "Symlink"),
        Err(Error::DirtyWorktree)
    ));
    assert!(
        std::fs::symlink_metadata(dir.path().join("participants"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn bare_wallets_and_normal_clones_exchange_verified_commits() {
    let source = tempfile::tempdir().unwrap();
    let clones = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let store = Store::create(source.path(), snapshot(&key), &key).unwrap();
    git(
        clones.path(),
        &["clone", "--bare", source.path().to_str().unwrap(), "bare"],
    );
    let bare = clones.path().join("bare");
    let mut legacy = Store::open(&bare, key.public.clone(), Some(store.head)).unwrap();
    legacy
        .save(legacy.snapshot.clone(), &key, "Bare edit")
        .unwrap();
    git(clones.path(), &["clone", bare.to_str().unwrap(), "normal"]);
    let normal = clones.path().join("normal");
    let mut cloned = Store::open(&normal, key.public.clone(), Some(legacy.head)).unwrap();
    cloned
        .save(cloned.snapshot.clone(), &key, "Normal edit")
        .unwrap();
    legacy.pull_from(&normal).unwrap();
    assert_eq!(cloned.head, legacy.head);
    legacy
        .save(legacy.snapshot.clone(), &key, "Another bare edit")
        .unwrap();
    cloned.pull_from(&bare).unwrap();
    assert!(git(&normal, &["status", "--porcelain"]).is_empty());
}
#[test]
fn device_metadata_survives_signed_reopen_backup_and_pull() {
    use kagitaba_store::DeviceHint;
    let dir = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut initial = snapshot(&key);
    let id = *initial.wallet.participants().keys().next().unwrap();
    let hint = DeviceHint {
        serial: "12345678".into(),
        encryption_slot: 0x94,
        signing_slot: 0x95,
    };
    initial.devices.insert(id, hint.clone());
    let mut store = Store::create(dir.path(), initial, &key).unwrap();
    store.backup_to(backup.path()).unwrap();
    let mut replica = Store::open(backup.path(), key.public.clone(), Some(store.head)).unwrap();
    assert_eq!(replica.snapshot.devices.get(&id), Some(&hint));
    let mut next = store.snapshot.clone();
    next.devices.get_mut(&id).unwrap().signing_slot = 0x93;
    store.save(next, &key, "Update device slots").unwrap();
    replica.pull_from(dir.path()).unwrap();
    assert_eq!(replica.snapshot.devices[&id].signing_slot, 0x93);
    let reopened = Store::open(dir.path(), key.public.clone(), Some(store.head)).unwrap();
    assert_eq!(reopened.snapshot.devices, replica.snapshot.devices);
    let mut invalid = store.snapshot.clone();
    invalid.devices.insert(key.public.id(), hint);
    assert!(invalid.validate().is_err());
}
#[test]
fn replicas_fast_forward_only_and_backups_need_no_decryption() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let mut first = Store::create(a.path(), snapshot(&key), &key).unwrap();
    first.backup_to(b.path()).unwrap();
    let root = first.head;
    let mut second = Store::open(b.path(), key.public.clone(), Some(root)).unwrap();
    second
        .save(second.snapshot.clone(), &key, "Remote edit")
        .unwrap();
    first.pull_from(b.path()).unwrap();
    assert_eq!(first.head, second.head);
    first
        .save(first.snapshot.clone(), &key, "Local edit")
        .unwrap();
    second
        .save(second.snapshot.clone(), &key, "Conflicting edit")
        .unwrap();
    let before = first.head;
    assert!(matches!(first.pull_from(b.path()), Err(Error::Checkpoint)));
    assert_eq!(first.head, before);
}
#[test]
fn persists_signed_snapshots_and_rejects_stale_writes_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let s = snapshot(&key);
    let mut a = Store::create(dir.path(), s.clone(), &key).unwrap();
    let root = a.head;
    let mut b = Store::open(dir.path(), key.public.clone(), Some(root)).unwrap();
    assert_eq!(a.snapshot.wallet, b.snapshot.wallet);
    a.save(s.clone(), &key, "Update").unwrap();
    assert!(matches!(b.save(s, &key, "Stale"), Err(Error::Stale)));
    let latest = a.head;
    assert!(Store::open(dir.path(), key.public.clone(), Some(latest)).is_ok());
    let repo = gix::open(dir.path()).unwrap();
    repo.reference(
        "refs/heads/wallet",
        root,
        PreviousValue::Any,
        "test rollback",
    )
    .unwrap();
    assert!(matches!(
        Store::open(dir.path(), key.public, Some(latest)),
        Err(Error::Checkpoint)
    ));
}
#[test]
fn signer_must_be_authorized_by_parent_and_bootstrap_is_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let other = Key::new(4);
    let mut store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    assert!(Store::open(dir.path(), other.public.clone(), None).is_err());
    assert!(matches!(
        store.save(store.snapshot.clone(), &other, "Unauthorized"),
        Err(Error::Signature)
    ));
    let mut next = store.snapshot.clone();
    let encryption = SoftwareIdentity::from_bytes(&[9; 32]).unwrap().public_key();
    next.signers.insert(encryption.id(), other.public.clone());
    next.wallet = next.wallet.with_participant(encryption).unwrap();
    store.save(next.clone(), &key, "Enroll").unwrap();
    store.save(next, &other, "New signer").unwrap();
    assert!(Store::open(dir.path(), key.public.clone(), None).is_ok());
    assert_eq!(Store::inspect_root(dir.path()).unwrap(), key.public);
}
#[test]
fn unsigned_and_duplicate_parent_commits_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(3);
    let store = Store::create(dir.path(), snapshot(&key), &key).unwrap();
    let repo = gix::open(dir.path()).unwrap();
    let obj = repo.find_commit(store.head).unwrap();
    let mut c: gix::objs::Commit = obj.decode().unwrap().try_into().unwrap();
    c.parents.push(store.head);
    c.extra_headers.clear();
    let unsigned = repo.write_object(c.clone()).unwrap().detach();
    repo.reference(
        "refs/heads/wallet",
        unsigned,
        PreviousValue::Any,
        "unsigned",
    )
    .unwrap();
    assert!(matches!(
        Store::open(dir.path(), key.public.clone(), None),
        Err(Error::Signature)
    ));
    c.parents.push(store.head);
    let merge = repo.write_object(c).unwrap().detach();
    repo.reference("refs/heads/wallet", merge, PreviousValue::Any, "merge")
        .unwrap();
    assert!(matches!(
        Store::open(dir.path(), key.public, None),
        Err(Error::History)
    ));
}
#[test]
fn inconsistent_participant_sets_and_nonempty_destinations_rejected() {
    let key = Key::new(3);
    let dir = tempfile::tempdir().unwrap();
    let mut s = snapshot(&key);
    s.wallet = Wallet::default();
    assert!(Store::create(dir.path(), s, &key).is_err());
    std::fs::write(dir.path().join("keep"), "existing").unwrap();
    assert!(matches!(
        Store::create(dir.path(), snapshot(&key), &key),
        Err(Error::DestinationNotEmpty)
    ));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("keep")).unwrap(),
        "existing"
    );
}

#[test]
fn encrypted_import_survives_reopen_and_recipient_rotation() {
    use futures::executor::block_on;
    use kagitaba_cxf::{Payload, bitwarden};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    let dir = tempfile::tempdir().unwrap();
    let signing = Key::new(3);
    let first = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
    let second = SoftwareIdentity::from_bytes(&[9; 32]).unwrap();
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let mut store = Store::create(dir.path(), snapshot(&signing), &signing).unwrap();
    let conversion=bitwarden::from_json(br#"{"encrypted":false,"items":[{"id":"fixture","type":1,"name":"Mail","login":{"username":"alice","password":"synthetic-password"}}]}"#).unwrap();
    let plan = conversion
        .document()
        .plan_import(&store.snapshot.wallet, &mut rng)
        .unwrap();
    let mut next = store.snapshot.clone();
    next.wallet = plan
        .encrypt_into(&next.wallet, &[first.public_key().id()], &mut rng)
        .unwrap();
    store.save(next, &signing, "Import").unwrap();
    let imported = store.head;
    let id = *store.snapshot.wallet.entries().keys().next().unwrap();
    let mut reopened = Store::open(dir.path(), signing.public.clone(), Some(imported)).unwrap();
    let payload = block_on(Payload::open(
        &reopened.snapshot.wallet.entries()[&id],
        &first.public_key(),
        &first,
    ))
    .unwrap();
    assert_eq!(payload.entity()["title"], "Mail");
    let mut next = reopened.snapshot.clone();
    next.wallet = next.wallet.with_participant(second.public_key()).unwrap();
    next.signers
        .insert(second.public_key().id(), signing.public.clone());
    let entry = payload.seal(&[second.public_key()], &mut rng).unwrap();
    next.wallet = next.wallet.with_entry(entry).unwrap();
    reopened.save(next, &signing, "Rotate recipients").unwrap();
    let final_store = Store::open(dir.path(), signing.public.clone(), Some(imported)).unwrap();
    let entry = &final_store.snapshot.wallet.entries()[&id];
    assert!(block_on(Payload::open(entry, &first.public_key(), &first)).is_err());
    assert!(block_on(Payload::open(entry, &second.public_key(), &second)).is_ok());
    // Check interoperability with the independent OpenSSH verifier used by Git.
    let allowed = dir.path().join("allowed-signers");
    std::fs::write(
        &allowed,
        format!(
            "wallet@localhost {}\n",
            kagitaba_store::ssh_public(&signing.public)
                .unwrap()
                .to_openssh()
                .unwrap()
        ),
    )
    .unwrap();
    let output = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(dir.path().join(".git"))
        .args(["-c", "gpg.format=ssh", "-c"])
        .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
        .arg("verify-commit")
        .arg(final_store.head.to_string())
        .output()
        .expect("Git/OpenSSH are required for signature interoperability test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

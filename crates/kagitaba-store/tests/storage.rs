use gix::refs::transaction::PreviousValue;
use kagitaba_core::{
    crypto::{PublicKey, SoftwareIdentity},
    wallet::Wallet,
};
use kagitaba_store::{Error, Result, Signer, Snapshot, Store};
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
    assert!(matches!(first.pull_from(b.path()), Err(Error::History)));
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
        Err(Error::History)
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
fn unsigned_and_merge_commits_are_rejected() {
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
    assert!(Store::create(dir.path(), snapshot(&key), &key).is_err());
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
        .arg(dir.path())
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

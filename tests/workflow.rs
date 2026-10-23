//! Application-side composition: the middle layer never decrypts/interprets data.
use futures::executor::block_on;
use kagitaba_core::{
    EntryId, Error, RevisionId,
    crypto::{Ciphertext, ContentKey, KeyAgreement, PublicKey, SoftwareIdentity, WrappedKey},
    wallet::{Entry, GrantRecord, PrimaryRecord, Wallet},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([42; 32])
}

// These are application operations, deliberately not methods on Wallet.
fn encrypt_revision(
    id: EntryId,
    bytes: &[u8],
    recipients: &[PublicKey],
    rng: &mut ChaCha20Rng,
) -> Entry {
    let revision = RevisionId::generate(rng).unwrap();
    let key = ContentKey::generate(rng).unwrap();
    let ciphertext = Ciphertext::seal(
        bytes,
        &key,
        &PrimaryRecord::content_context(id, revision),
        rng,
    )
    .unwrap();
    let primary = PrimaryRecord::new(id, revision, ciphertext.as_bytes().to_vec()).unwrap();
    let grants = recipients
        .iter()
        .map(|recipient| {
            let wrapped =
                WrappedKey::wrap(&key, recipient, &primary.grant_context(recipient.id()), rng)
                    .unwrap();
            GrantRecord::new(&primary, recipient.id(), wrapped.as_bytes().to_vec()).unwrap()
        })
        .collect::<Vec<_>>();
    Entry::from_parts(primary, grants).unwrap()
}

fn open(entry: &Entry, identity: &SoftwareIdentity) -> kagitaba_core::Result<Vec<u8>> {
    let grant = entry
        .grants()
        .get(&identity.key_id())
        .ok_or(Error::NotFound)?;
    let primary = entry.primary();
    grant.validate_for(primary)?;
    let key = block_on(WrappedKey::from_bytes(grant.body())?.unwrap(
        &identity.public_key(),
        &primary.grant_context(identity.key_id()),
        identity,
    ))?;
    let plaintext = Ciphertext::from_bytes(primary.body())?.open(
        &key,
        &PrimaryRecord::content_context(primary.entry_id(), primary.revision_id()),
    )?;
    Ok(plaintext.as_bytes().to_vec()) // Only a test/application chooses to copy plaintext.
}

#[test]
fn three_participants_read_one_entry_and_snapshots_are_immutable() {
    let mut rng = rng();
    let identities = (0..3)
        .map(|_| SoftwareIdentity::generate(&mut rng).unwrap())
        .collect::<Vec<_>>();
    let keys = identities
        .iter()
        .map(SoftwareIdentity::public_key)
        .collect::<Vec<_>>();
    let base = Wallet::from_parts(keys.clone(), []).unwrap();
    let id = EntryId::generate(&mut rng).unwrap();
    let contents = br#"{"url":"https://example.org","username":"lukas","password":"example-only"}"#;
    let entry = encrypt_revision(id, contents, &keys, &mut rng);
    let updated = base.with_entry(entry.clone()).unwrap();
    assert!(base.entries().is_empty());
    for identity in &identities {
        assert_eq!(open(&updated.entries()[&id], identity).unwrap(), contents);
    }

    // Independent record serialization, no combined catalogue/manifest.
    let loaded = Entry::from_parts(
        PrimaryRecord::from_bytes(&entry.primary().to_bytes()).unwrap(),
        entry
            .grants()
            .values()
            .map(|g| GrantRecord::from_bytes(&g.to_bytes()).unwrap()),
    )
    .unwrap();
    assert_eq!(entry, loaded);
    let restored = Wallet::from_parts(
        keys.iter()
            .map(|key| PublicKey::from_pem(&key.to_pem()).unwrap()),
        [loaded],
    )
    .unwrap();
    assert_eq!(updated, restored);
}

#[test]
fn enrolment_rewraps_without_changing_or_opening_the_primary() {
    let mut rng = rng();
    let alice = SoftwareIdentity::generate(&mut rng).unwrap();
    let bob = SoftwareIdentity::generate(&mut rng).unwrap();
    let id = EntryId::generate(&mut rng).unwrap();
    let entry = encrypt_revision(id, b"secret", &[alice.public_key()], &mut rng);
    let base = Wallet::from_parts([alice.public_key()], [entry.clone()]).unwrap();
    let registered = base.with_participant(bob.public_key()).unwrap();
    assert!(
        !registered.entries()[&id]
            .grants()
            .contains_key(&bob.key_id())
    );
    let primary_before = entry.primary().to_bytes();
    let alice_before = entry.grants()[&alice.key_id()].to_bytes();
    let key = block_on(
        WrappedKey::from_bytes(entry.grants()[&alice.key_id()].body())
            .unwrap()
            .unwrap(
                &alice.public_key(),
                &entry.primary().grant_context(alice.key_id()),
                &alice,
            ),
    )
    .unwrap();
    let bob_wrap = WrappedKey::wrap(
        &key,
        &bob.public_key(),
        &entry.primary().grant_context(bob.key_id()),
        &mut rng,
    )
    .unwrap();
    let shared = entry
        .with_grant(
            GrantRecord::new(entry.primary(), bob.key_id(), bob_wrap.as_bytes().to_vec()).unwrap(),
        )
        .unwrap();
    let updated = registered.with_entry(shared).unwrap();
    assert_eq!(updated.entries()[&id].primary().to_bytes(), primary_before);
    assert_eq!(
        updated.entries()[&id].grants()[&alice.key_id()].to_bytes(),
        alice_before
    );
    assert_eq!(open(&updated.entries()[&id], &bob).unwrap(), b"secret");
    assert_eq!(base.entries()[&id].grants().len(), 1);
}

#[test]
fn revision_rotation_excludes_removed_recipient_and_rejects_stale_grants() {
    let mut rng = rng();
    let alice = SoftwareIdentity::generate(&mut rng).unwrap();
    let bob = SoftwareIdentity::generate(&mut rng).unwrap();
    let id = EntryId::generate(&mut rng).unwrap();
    let old = encrypt_revision(
        id,
        b"old password",
        &[alice.public_key(), bob.public_key()],
        &mut rng,
    );
    let old_key = block_on(
        WrappedKey::from_bytes(old.grants()[&bob.key_id()].body())
            .unwrap()
            .unwrap(
                &bob.public_key(),
                &old.primary().grant_context(bob.key_id()),
                &bob,
            ),
    )
    .unwrap();
    let new = encrypt_revision(id, b"new password", &[alice.public_key()], &mut rng);
    assert_ne!(new.primary().revision_id(), old.primary().revision_id());
    assert!(matches!(
        Ciphertext::from_bytes(new.primary().body()).unwrap().open(
            &old_key,
            &PrimaryRecord::content_context(id, new.primary().revision_id()),
        ),
        Err(Error::Authentication)
    ));
    assert_eq!(open(&old, &bob).unwrap(), b"old password");
    assert_eq!(open(&new, &bob), Err(Error::NotFound));
    assert_eq!(open(&new, &alice).unwrap(), b"new password");
    assert_eq!(
        new.with_grant(old.grants()[&bob.key_id()].clone()),
        Err(Error::StaleGrant)
    );

    // Relabelling old envelope metadata is insufficient: inner AEAD context binds it.
    let relabelled = GrantRecord::new(
        new.primary(),
        bob.key_id(),
        old.grants()[&bob.key_id()].body().to_vec(),
    )
    .unwrap();
    let forged = new.with_grant(relabelled).unwrap();
    assert_eq!(open(&forged, &bob), Err(Error::Authentication));
}

#[test]
fn content_changes_need_a_new_revision_and_complete_grant_set() {
    let mut rng = rng();
    let owner = SoftwareIdentity::generate(&mut rng).unwrap();
    let id = EntryId::generate(&mut rng).unwrap();
    let original = encrypt_revision(id, b"original", &[owner.public_key()], &mut rng);
    let wallet = Wallet::from_parts([owner.public_key()], [original.clone()]).unwrap();
    let changed =
        PrimaryRecord::new(id, original.primary().revision_id(), b"changed".to_vec()).unwrap();
    assert_eq!(
        Entry::from_parts(changed.clone(), original.grants().values().cloned()),
        Err(Error::StaleGrant)
    );
    let no_grants = Entry::from_parts(changed, []).unwrap();
    assert_eq!(wallet.with_entry(no_grants), Err(Error::ReusedRevision));
    let updated = encrypt_revision(id, b"updated", &[owner.public_key()], &mut rng);
    let next = wallet.with_entry(updated).unwrap();
    assert_eq!(open(&wallet.entries()[&id], &owner).unwrap(), b"original");
    assert_eq!(open(&next.entries()[&id], &owner).unwrap(), b"updated");
    assert!(next.without_entry(id).unwrap().entries().is_empty());
    assert_eq!(next.entries().len(), 1);
}

#[test]
fn middle_layer_accepts_opaque_descriptors_without_interpreting_them() {
    let mut rng = rng();
    let bytes = b"opaque application-defined retrieval descriptor, not ciphertext".to_vec();
    let primary = PrimaryRecord::new(
        EntryId::generate(&mut rng).unwrap(),
        RevisionId::generate(&mut rng).unwrap(),
        bytes.clone(),
    )
    .unwrap();
    let entry = Entry::from_parts(primary, []).unwrap();
    let wallet = Wallet::from_parts([], [entry.clone()]).unwrap();
    assert_eq!(
        wallet.entries()[&entry.primary().entry_id()]
            .primary()
            .body(),
        bytes
    );
    assert_eq!(
        Entry::from_parts(
            PrimaryRecord::from_bytes(&entry.primary().to_bytes()).unwrap(),
            []
        )
        .unwrap(),
        entry
    );
}

#[test]
fn snapshot_loading_rejects_duplicate_and_unknown_records() {
    let mut rng = rng();
    let owner = SoftwareIdentity::generate(&mut rng).unwrap();
    let id = EntryId::generate(&mut rng).unwrap();
    let entry = encrypt_revision(id, b"secret", &[owner.public_key()], &mut rng);
    assert_eq!(
        Wallet::from_parts([], [entry.clone()]),
        Err(Error::NotFound)
    );
    assert_eq!(
        Wallet::from_parts([owner.public_key(), owner.public_key()], []),
        Err(Error::Duplicate)
    );
    assert_eq!(
        Wallet::from_parts([owner.public_key()], [entry.clone(), entry.clone()]),
        Err(Error::Duplicate)
    );
    let grant = entry.grants()[&owner.key_id()].clone();
    assert_eq!(
        Entry::from_parts(entry.primary().clone(), [grant.clone(), grant]),
        Err(Error::Duplicate)
    );
}

#[test]
fn cached_primary_digest_matches_wire_and_batch_updates_remain_atomic() {
    use sha2::{Digest, Sha256};
    let mut rng = rng();
    let identity = SoftwareIdentity::from_bytes(&[17; 32]).unwrap();
    let key = identity.public_key();
    let first = encrypt_revision(EntryId::from_bytes([1; 16]), b"first", std::slice::from_ref(&key), &mut rng);
    let second = encrypt_revision(EntryId::from_bytes([2; 16]), b"second", std::slice::from_ref(&key), &mut rng);
    let wire = first.primary().to_bytes();
    let expected: [u8; 32] = Sha256::digest(&wire).into();
    assert_eq!(first.primary().digest(), expected);
    assert_eq!(PrimaryRecord::from_bytes(&wire).unwrap().digest(), expected);
    let original = Wallet::from_parts([key], [first.clone()]).unwrap();
    assert_eq!(original.with_entries([second.clone()]).unwrap(), original.with_entry(second.clone()).unwrap());
    assert!(matches!(original.with_entries([second.clone(), second.clone()]), Err(Error::Duplicate)));
    let reused = PrimaryRecord::new(first.primary().entry_id(), first.primary().revision_id(), b"changed".to_vec()).unwrap();
    assert!(matches!(original.with_entries([second.clone(), Entry::from_parts(reused, []).unwrap()]), Err(Error::ReusedRevision)));
    assert_eq!(original.entries().len(), 1);
    let batch = original.with_entries([second]).unwrap();
    assert!(batch.without_entries([EntryId::from_bytes([1; 16]), EntryId::from_bytes([9; 16])]).is_err());
    assert_eq!(batch.entries().len(), 2);
    assert!(batch.without_entries(batch.entries().keys().copied()).unwrap().entries().is_empty());
}

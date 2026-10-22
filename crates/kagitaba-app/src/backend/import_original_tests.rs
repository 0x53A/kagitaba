use super::*;
use kagitaba_core::{crypto::SoftwareIdentity, wallet::Wallet};
use kagitaba_cxf::{PayloadKind, attachments};
use std::io::Read;

fn source_document() -> Document {
    kagitaba_cxf::bitwarden::from_json(br#"{"encrypted":false,"folders":[{"id":"folder","name":"Existing folder"}],"items":[{"id":"account","folderId":"folder","type":1,"name":"Synthetic account","login":{"username":"test","password":"synthetic-password"}}]}"#)
        .unwrap().into_document()
}

#[test]
fn saved_original_is_an_owned_encrypted_file_in_the_import_collection() {
    let identity = SoftwareIdentity::from_bytes(&[71; 32]).unwrap();
    let other = SoftwareIdentity::from_bytes(&[72; 32]).unwrap();
    let public = identity.public_key();
    let mut snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
    snapshot.wallet = Wallet::from_parts([public.clone(), other.public_key()], []).unwrap();
    snapshot
        .signers
        .insert(other.public_key().id(), other.public_key());
    let marker = b"SYNTHETIC-ORIGINAL-ENCRYPTED-KDBX-BYTES";
    let mut original = vec![93; attachments::CHUNK_BYTES + 31];
    original[..marker.len()].copy_from_slice(marker);
    let (document, source) = import_files::with_original_file(
        source_document(),
        Path::new("synthetic.kdbx"),
        Zeroizing::new(original.clone()),
    )
    .unwrap();
    let mut plan = document
        .plan_import(&snapshot.wallet, &mut rand::rngs::SysRng)
        .unwrap();
    let root = plan
        .wrap_collection("Synthetic import", &mut rand::rngs::SysRng)
        .unwrap();
    let pending = import_files::PendingImport::prepare(plan, vec![source]).unwrap();
    assert_eq!(pending.file_count, 1);
    let next = pending.encrypt_into(&snapshot, &[public.id()]).unwrap();
    assert!(snapshot.wallet.entries().is_empty() && snapshot.attachments.is_empty());
    assert_eq!(next.attachments.len(), 1);
    let owner = *next.attachments.keys().next().unwrap();
    let entry = &next.wallet.entries()[&owner];
    assert_eq!(
        entry.grants().keys().copied().collect::<Vec<_>>(),
        vec![public.id()]
    );
    assert!(block_on(Payload::open(entry, &other.public_key(), &other)).is_err());
    let payload = block_on(Payload::open(entry, &public, &identity)).unwrap();
    assert_eq!(payload.kind(), PayloadKind::Item);
    assert_eq!(payload.entity()["title"], "Original file: synthetic.kdbx");
    let encoded = payload.to_json().unwrap();
    assert!(!encoded.windows(marker.len()).any(|window| window == marker));
    let files = attachments::list(&payload).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "synthetic.kdbx");
    assert_eq!(files[0].size, original.len() as u64);
    let blob = &next.attachments[&owner][&files[0].blob_id];
    let mut ciphertext = Vec::new();
    blob.open().unwrap().read_to_end(&mut ciphertext).unwrap();
    assert!(ciphertext.starts_with(b"KAF1"));
    assert!(
        !ciphertext
            .windows(marker.len())
            .any(|window| window == marker)
    );
    let mut restored = Zeroizing::new(Vec::new());
    attachments::decrypt_stream(owner, &files[0], &mut blob.open().unwrap(), &mut *restored)
        .unwrap();
    assert_eq!(*restored, original);
    let collection = block_on(Payload::open(
        &next.wallet.entries()[&root],
        &public,
        &identity,
    ))
    .unwrap();
    assert_eq!(collection.entity()["title"], "Synthetic import");
    assert_eq!(
        collection.entity()["subCollections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(collection.entity()["items"].as_array().unwrap().len(), 2);
    assert!(
        collection.entity()["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|link| link["item"] == data_encoding::BASE64URL_NOPAD.encode(owner.as_bytes()))
    );
    for entry in next.wallet.entries().values() {
        assert_eq!(
            entry.grants().keys().copied().collect::<Vec<_>>(),
            vec![public.id()]
        );
    }
}

#[test]
fn not_adding_original_file_produces_only_imported_items_and_wrapper() {
    let identity = SoftwareIdentity::from_bytes(&[73; 32]).unwrap();
    let public = identity.public_key();
    let snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
    let mut plan = source_document()
        .plan_import(&snapshot.wallet, &mut rand::rngs::SysRng)
        .unwrap();
    plan.wrap_collection("Synthetic import", &mut rand::rngs::SysRng)
        .unwrap();
    let pending = import_files::PendingImport::prepare(plan, vec![]).unwrap();
    assert_eq!(pending.file_count, 0);
    assert_eq!(
        pending
            .entries
            .iter()
            .filter(|entry| entry.kind() == PayloadKind::Item)
            .count(),
        1
    );
    let next = pending.encrypt_into(&snapshot, &[public.id()]).unwrap();
    assert!(next.attachments.is_empty());
}

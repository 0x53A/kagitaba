//! Explicit synthetic diagnostics. No wallet files, USB devices or secrets are read.
use super::*;
use kagitaba_core::crypto::{AgreementRequest, AgreementSecret, KeyAgreement, SoftwareIdentity};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

struct Counting {
    identity: SoftwareIdentity,
    calls: Cell<usize>,
    elapsed: Cell<Duration>,
}
impl KeyAgreement for Counting {
    fn key_id(&self) -> KeyId {
        self.identity.public_key().id()
    }
    async fn agree(&self, request: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
        self.calls.set(self.calls.get() + 1);
        let start = Instant::now();
        let result = self.identity.agree(request).await;
        self.elapsed.set(self.elapsed.get() + start.elapsed());
        result
    }
}
fn measure<T>(name: &str, key: &Counting, operation: impl FnOnce() -> T) -> T {
    key.calls.set(0);
    key.elapsed.set(Duration::ZERO);
    let start = Instant::now();
    let result = operation();
    eprintln!(
        "{name}: total={:?}, private calls={}, software ECDH={:?}",
        start.elapsed(),
        key.calls.get(),
        key.elapsed.get()
    );
    result
}

#[test]
#[ignore = "synthetic bulk timing and private-operation counts; run explicitly"]
fn benchmark_bulk_operations() {
    let key = Counting {
        identity: SoftwareIdentity::from_bytes(&[31; 32]).unwrap(),
        calls: Cell::new(0),
        elapsed: Cell::new(Duration::ZERO),
    };
    let public = key.identity.public_key();
    let other = SoftwareIdentity::from_bytes(&[29; 32])
        .unwrap()
        .public_key();
    let mut snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
    snapshot.wallet = snapshot.wallet.with_participant(other.clone()).unwrap();
    snapshot.signers.insert(other.id(), other.clone());
    let payloads: Vec<_> = (1..=64).map(|n| {
        let id = EntryId::from_bytes([n;16]);
        Payload::new(id, kagitaba_cxf::PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
            "id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()), "title":"Synthetic duplicate",
            "credentials":[{"type":"note", "content":{"fieldType":"string", "value":"x".repeat(32*1024)}}]
        })).unwrap()).unwrap()
    }).collect();
    let pending = import_files::PendingImport::from_prepared(payloads, BTreeMap::new()).unwrap();
    snapshot = measure("import encrypt", &key, || {
        pending.encrypt_into(&snapshot, &[public.id()]).unwrap()
    });
    let mut cached = None;
    measure("index initial", &key, || {
        refresh_index_with(&mut snapshot, &public, &key, &mut cached).unwrap()
    });
    assert_eq!(key.calls.get(), 64);
    measure("index current in memory", &key, || {
        assert!(!refresh_index_with(&mut snapshot, &public, &key, &mut cached).unwrap())
    });
    assert_eq!(key.calls.get(), 0);
    cached = None;
    measure("index reopen", &key, || {
        assert!(!refresh_index_with(&mut snapshot, &public, &key, &mut cached).unwrap())
    });
    assert_eq!(key.calls.get(), 1);
    let access = measure("access scan", &key, || {
        block_on(access::PendingAccess::scan(
            &snapshot,
            "head",
            other.id(),
            &public,
            &key,
        ))
        .unwrap()
    });
    assert_eq!(key.calls.get(), 64);
    measure("access apply", &key, || {
        block_on(access.apply(&snapshot, "head", &public, &key)).unwrap()
    });
    assert_eq!(key.calls.get(), 64);
    let duplicates = measure("duplicates scan", &key, || {
        block_on(duplicates::PendingDuplicates::scan(
            &snapshot, "head", &public, &key,
        ))
        .unwrap()
    });
    measure("duplicates apply", &key, || {
        block_on(duplicates.apply(&snapshot, "head", &public, &key)).unwrap()
    });
    let destination = Snapshot::empty(public.clone(), public.clone()).unwrap();
    let ids: Vec<_> = snapshot.wallet.entries().keys().copied().collect();
    let mut copied = measure("copy prepare", &key, || {
        block_on(copy::prepare(
            &snapshot,
            &destination,
            &ids,
            b"synthetic",
            &public,
            &key,
        ))
        .unwrap()
    });
    measure("import duplicate scan", &key, || {
        block_on(copied.scan_existing(&snapshot, "head", &public, &key)).unwrap()
    });
    measure("import duplicate apply", &key, || {
        block_on(copied.apply(&snapshot, "head", &[public.id()], true, &public, &key)).unwrap()
    });
    measure("revocation decrypt/reseal (no attachments)", &key, || {
        let entries = snapshot
            .wallet
            .entries()
            .values()
            .map(|entry| {
                block_on(Payload::open(entry, &public, &key))
                    .unwrap()
                    .seal(std::slice::from_ref(&public), &mut rand::rngs::SysRng)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        snapshot.wallet.with_entries(entries).unwrap()
    });
    assert_eq!(key.calls.get(), 64);
}

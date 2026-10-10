use kagitaba_core::{
    EntryId, Error, RevisionId,
    crypto::{Ciphertext, PublicKey, WrappedKey},
    wallet::{GrantRecord, MAX_GRANT_BYTES, MAX_PRIMARY_BYTES, PrimaryRecord},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

#[test]
fn arbitrary_untrusted_bytes_do_not_panic_in_record_parsers() {
    let mut rng = ChaCha20Rng::from_seed([11; 32]);
    for size in 0..512 {
        let mut bytes = vec![0; size];
        rng.fill_bytes(&mut bytes);
        let _ = Ciphertext::from_bytes(&bytes);
        let _ = WrappedKey::from_bytes(&bytes);
        let _ = PrimaryRecord::from_bytes(&bytes);
        let _ = GrantRecord::from_bytes(&bytes);
        let _ = PublicKey::from_der(&bytes);
        let _ = PublicKey::from_pem(&String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn middle_layer_bounds_and_version_checks_are_explicit() {
    let id = EntryId::from_bytes([1; 16]);
    let rev = RevisionId::from_bytes([2; 16]);
    assert_eq!(
        PrimaryRecord::new(id, rev, vec![0; MAX_PRIMARY_BYTES + 1]),
        Err(Error::SizeLimit)
    );
    assert_eq!(
        PrimaryRecord::from_bytes(&vec![0; MAX_PRIMARY_BYTES + 37]),
        Err(Error::SizeLimit)
    );
    assert_eq!(
        GrantRecord::from_bytes(&vec![0; MAX_GRANT_BYTES + 101]),
        Err(Error::SizeLimit)
    );
    let record = PrimaryRecord::new(id, rev, vec![]).unwrap();
    let mut bytes = record.to_bytes();
    bytes[3] = b'2';
    assert_eq!(
        PrimaryRecord::from_bytes(&bytes),
        Err(Error::UnsupportedFormat)
    );
    for length in 0..36 {
        assert!(PrimaryRecord::from_bytes(&record.to_bytes()[..length]).is_err());
    }
}

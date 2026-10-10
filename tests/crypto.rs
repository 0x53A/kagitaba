use futures::executor::block_on;
use kagitaba_core::{
    Error, KeyId, Result,
    crypto::{
        AgreementRequest, AgreementSecret, Ciphertext, ContentKey, KeyAgreement,
        MAX_PLAINTEXT_BYTES, PublicKey, SoftwareIdentity, WrappedKey,
    },
};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};
use std::cell::Cell;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([9; 32])
}

#[test]
fn symmetric_roundtrip_empty_binary_and_maximum() {
    let mut rng = rng();
    let key = ContentKey::generate(&mut rng).unwrap();
    for bytes in [vec![], vec![0, 255, 0, 42], vec![11; MAX_PLAINTEXT_BYTES]] {
        let encrypted = Ciphertext::seal(&bytes, &key, b"context", &mut rng).unwrap();
        let loaded = Ciphertext::from_bytes(encrypted.as_bytes()).unwrap();
        assert_eq!(loaded.open(&key, b"context").unwrap().as_bytes(), bytes);
        assert!(matches!(
            loaded.open(&key, b"other context"),
            Err(Error::Authentication)
        ));
    }
    assert_eq!(
        Ciphertext::seal(&vec![0; MAX_PLAINTEXT_BYTES + 1], &key, b"", &mut rng),
        Err(Error::SizeLimit)
    );
    assert_eq!(
        Ciphertext::seal(b"a", &key, &vec![0; 65537], &mut rng),
        Err(Error::SizeLimit)
    );
}

#[test]
fn payload_rejects_every_single_byte_mutation_and_every_truncation() {
    let mut rng = rng();
    let key = ContentKey::generate(&mut rng).unwrap();
    let encrypted = Ciphertext::seal(b"do not leak this", &key, b"ctx", &mut rng).unwrap();
    for index in 0..encrypted.as_bytes().len() {
        let mut corrupt = encrypted.as_bytes().to_vec();
        corrupt[index] ^= 1;
        if let Ok(parsed) = Ciphertext::from_bytes(&corrupt) {
            assert!(parsed.open(&key, b"ctx").is_err(), "offset {index}");
        }
        if let Ok(parsed) = Ciphertext::from_bytes(&encrypted.as_bytes()[..index]) {
            assert!(parsed.open(&key, b"ctx").is_err());
        }
    }
    let other_key = ContentKey::generate(&mut rng).unwrap();
    assert!(matches!(
        encrypted.open(&other_key, b"ctx"),
        Err(Error::Authentication)
    ));
    let mut appended = encrypted.as_bytes().to_vec();
    appended.push(0);
    assert!(
        Ciphertext::from_bytes(&appended)
            .unwrap()
            .open(&key, b"ctx")
            .is_err()
    );
}

#[test]
fn envelope_rejects_every_single_byte_mutation_truncation_and_append() {
    let mut rng = rng();
    let identity = SoftwareIdentity::generate(&mut rng).unwrap();
    let public = identity.public_key();
    let key = ContentKey::generate(&mut rng).unwrap();
    let envelope = WrappedKey::wrap(&key, &public, b"ctx", &mut rng).unwrap();
    assert_eq!(
        block_on(envelope.unwrap(&public, b"ctx", &identity))
            .unwrap()
            .as_bytes(),
        key.as_bytes()
    );
    for index in 0..envelope.as_bytes().len() {
        let mut corrupt = envelope.as_bytes().to_vec();
        corrupt[index] ^= 1;
        if let Ok(parsed) = WrappedKey::from_bytes(&corrupt) {
            assert!(
                block_on(parsed.unwrap(&public, b"ctx", &identity)).is_err(),
                "offset {index}"
            );
        }
        assert!(WrappedKey::from_bytes(&envelope.as_bytes()[..index]).is_err());
    }
    let mut appended = envelope.as_bytes().to_vec();
    appended.push(0);
    assert!(WrappedKey::from_bytes(&appended).is_err());
}

struct Device {
    // Simulation only: real adapters keep this scalar in their device.
    identity: SoftwareIdentity,
    calls: Cell<usize>,
    available: bool,
}

impl KeyAgreement for Device {
    fn key_id(&self) -> KeyId {
        self.identity.key_id()
    }
    async fn agree(&self, request: &AgreementRequest) -> Result<AgreementSecret> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(request.recipient(), self.key_id());
        assert_eq!(request.peer_public_key()[0], 4);
        if !self.available {
            return Err(Error::KeyUnavailable);
        }
        self.identity.agree(request).await
    }
}

#[test]
fn backend_is_async_and_receives_only_validated_public_key_operations() {
    let mut rng = rng();
    let device = Device {
        identity: SoftwareIdentity::generate(&mut rng).unwrap(),
        calls: Cell::new(0),
        available: true,
    };
    let public = device.identity.public_key();
    let key = ContentKey::generate(&mut rng).unwrap();
    let grant = WrappedKey::wrap(&key, &public, b"ctx", &mut rng).unwrap();
    assert_eq!(device.calls.get(), 0); // Encryption needs no private-key operation.
    assert!(block_on(grant.unwrap(&public, b"wrong", &device)).is_err());
    assert_eq!(device.calls.get(), 0); // Reject context mismatch before prompting.
    let other = SoftwareIdentity::generate(&mut rng).unwrap();
    assert!(matches!(
        block_on(grant.unwrap(&public, b"ctx", &other)),
        Err(Error::WrongRecipient)
    ));
    assert_eq!(
        block_on(grant.unwrap(&public, b"ctx", &device))
            .unwrap()
            .as_bytes(),
        key.as_bytes()
    );
    assert_eq!(device.calls.get(), 1);
    let unavailable = Device {
        available: false,
        ..device
    };
    assert!(matches!(
        block_on(grant.unwrap(&public, b"ctx", &unavailable)),
        Err(Error::KeyUnavailable)
    ));
    let mut off_curve = grant.as_bytes().to_vec();
    off_curve[69..133].fill(0);
    assert_eq!(
        WrappedKey::from_bytes(&off_curve),
        Err(Error::InvalidPublicKey)
    );
}

#[test]
fn public_keys_have_stable_spki_fingerprints() {
    let mut rng = rng();
    let public = SoftwareIdentity::generate(&mut rng).unwrap().public_key();
    let pem = public.to_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert_eq!(PublicKey::from_der(&public.to_der()).unwrap(), public);
    assert_eq!(
        PublicKey::from_pem(&pem.replace('\n', "\r\n"))
            .unwrap()
            .id(),
        public.id()
    );
    assert_eq!(
        public.id().to_string().parse::<KeyId>().unwrap(),
        public.id()
    );
    assert!(
        public
            .id()
            .to_string()
            .to_uppercase()
            .parse::<KeyId>()
            .is_err()
    );
    assert!(PublicKey::from_der(b"nonsense").is_err());
    assert!(
        PublicKey::from_pem("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----")
            .is_err()
    );
}

struct BrokenRng;
impl TryRng for BrokenRng {
    type Error = Error;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Err(Error::Randomness)
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Err(Error::Randomness)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> core::result::Result<(), Self::Error> {
        Err(Error::Randomness)
    }
}
impl TryCryptoRng for BrokenRng {}

#[test]
fn randomness_failure_is_returned_instead_of_panic_or_fallback() {
    assert!(matches!(
        ContentKey::generate(&mut BrokenRng),
        Err(Error::Randomness)
    ));
    assert!(matches!(
        SoftwareIdentity::generate(&mut BrokenRng),
        Err(Error::Randomness)
    ));
    let key = ContentKey::from_bytes([1; 32]);
    assert_eq!(
        Ciphertext::seal(b"x", &key, b"ctx", &mut BrokenRng),
        Err(Error::Randomness)
    );
    let public = SoftwareIdentity::generate(&mut rng()).unwrap().public_key();
    assert_eq!(
        WrappedKey::wrap(&key, &public, b"ctx", &mut BrokenRng),
        Err(Error::Randomness)
    );
}

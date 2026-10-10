use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::{Generate, sec1::ToSec1Point},
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, KeyId, Result};

/// A P-256 encryption/key-agreement public key, independent of its device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(super) p256::PublicKey);

impl PublicKey {
    /// Parse a PEM `PUBLIC KEY` containing P-256 SubjectPublicKeyInfo.
    pub fn from_pem(pem: &str) -> Result<Self> {
        if pem.len() > 2048 {
            return Err(Error::SizeLimit);
        }
        p256::PublicKey::from_public_key_pem(pem)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Parse DER SubjectPublicKeyInfo. Unsupported algorithms are rejected.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        if der.len() > 512 {
            return Err(Error::SizeLimit);
        }
        p256::PublicKey::from_public_key_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Canonical DER SPKI, always using an uncompressed P-256 public point.
    pub fn to_der(&self) -> Vec<u8> {
        // A validated P-256 key is always encodable as SPKI.
        self.0
            .to_public_key_der()
            .expect("validated P-256 key")
            .as_bytes()
            .to_vec()
    }

    /// Standard PEM with LF line endings and a `PUBLIC KEY` label.
    pub fn to_pem(&self) -> String {
        self.0
            .to_public_key_pem(LineEnding::LF)
            .expect("validated P-256 key")
    }

    /// Fingerprint of the canonical DER encoding; PEM whitespace is irrelevant.
    pub fn id(&self) -> KeyId {
        KeyId::from_bytes(Sha256::digest(self.to_der()).into())
    }

    pub(super) fn point(&self) -> [u8; 65] {
        self.0
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 point")
    }
}

/// Public input to a private-key operation. Created only from a validated point.
///
/// A hardware adapter selects the key/slot from `recipient()`, performs P-256
/// ECDH with `peer_public_key()`, and returns the 32-byte big-endian shared x
/// coordinate. It must NOT apply its own KDF. It handles PIN/touch/UI itself.
pub struct AgreementRequest {
    pub(super) recipient: KeyId,
    pub(super) peer: [u8; 65],
}

impl AgreementRequest {
    /// Fingerprint of the private key requested from the backend.
    pub fn recipient(&self) -> KeyId {
        self.recipient
    }

    /// Validated uncompressed SEC1 P-256 point (`04 || x || y`).
    pub fn peer_public_key(&self) -> &[u8; 65] {
        &self.peer
    }
}

/// A raw ECDH result. Zeroized on drop, with no `Debug` or `Clone` implementation.
pub struct AgreementSecret(pub(super) Zeroizing<[u8; 32]>);

impl AgreementSecret {
    /// Wrap a backend's raw 32-byte P-256 ECDH result.
    /// The backend is responsible for clearing any copies it made.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Asynchronous private-key adapter; a device need never export its private key.
///
/// Futures intentionally need not be `Send`, allowing browser/mobile adapters.
/// No transport, OS API, thread, runtime, or prompt is implemented by this crate.
#[allow(async_fn_in_trait)]
pub trait KeyAgreement {
    /// The key this backend owns.
    fn key_id(&self) -> KeyId;

    /// Perform raw P-256 ECDH or return `Error::KeyUnavailable` on denial/failure.
    async fn agree(&self, request: &AgreementRequest) -> Result<AgreementSecret>;
}

/// Software P-256 backend for software participants and integration tests.
/// Hardware participants should implement `KeyAgreement` instead.
/// Private scalar storage is zeroized by RustCrypto on drop.
pub struct SoftwareIdentity(p256::SecretKey);

impl SoftwareIdentity {
    /// Generate a private key using the caller's cryptographic random source.
    pub fn generate(rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<Self> {
        p256::SecretKey::try_generate_from_rng(rng)
            .map(Self)
            .map_err(|_| Error::Randomness)
    }

    /// Import a software scalar. The caller must clear its own input buffer.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        p256::SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    /// Return the public key, suitable for sharing or publishing.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}

impl KeyAgreement for SoftwareIdentity {
    fn key_id(&self) -> KeyId {
        self.public_key().id()
    }

    async fn agree(&self, request: &AgreementRequest) -> Result<AgreementSecret> {
        if request.recipient != self.key_id() {
            return Err(Error::WrongRecipient);
        }
        let peer =
            p256::PublicKey::from_sec1_bytes(&request.peer).map_err(|_| Error::InvalidPublicKey)?;
        let secret = diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        let mut result = AgreementSecret::from_bytes([0; 32]);
        result.0.copy_from_slice(secret.raw_secret_bytes());
        Ok(result)
    }
}

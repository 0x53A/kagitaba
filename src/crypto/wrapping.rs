use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AgreementRequest, ContentKey, KeyAgreement, PublicKey, array, context_hash};
use crate::{Error, KeyId, Result};

const MAGIC: &[u8; 4] = b"KTW1";
const HEADER_LEN: usize = 157;
const ENVELOPE_LEN: usize = HEADER_LEN + 32 + 16;

/// Detached public-key envelope containing exactly one symmetric content key.
/// The context and recipient are authenticated; ciphertext is not a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey(Vec<u8>);

impl WrappedKey {
    /// Wrap a key using ONLY the recipient's public key; no device is required.
    pub fn wrap(
        key: &ContentKey,
        recipient: &PublicKey,
        context: &[u8],
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Self> {
        let context = context_hash(context)?;
        let ephemeral =
            EphemeralSecret::try_generate_from_rng(rng).map_err(|_| Error::Randomness)?;
        let point = ephemeral.public_key().to_sec1_point(false);
        let secret = ephemeral.diffie_hellman(&recipient.0);
        let mut nonce = [0; 24];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Randomness)?;
        let mut header = Vec::with_capacity(ENVELOPE_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(recipient.id().as_bytes());
        header.extend_from_slice(&context);
        header.extend_from_slice(point.as_bytes());
        header.extend_from_slice(&nonce);
        let wrapping_key = derive_key(secret.raw_secret_bytes(), recipient, &header)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref()).expect("32-byte key");
        let mut buffer = Zeroizing::new(Vec::with_capacity(48));
        buffer.extend_from_slice(key.as_bytes());
        cipher
            .encrypt_in_place(&XNonce::from(nonce), &header, &mut *buffer)
            .map_err(|_| Error::Authentication)?;
        header.extend_from_slice(&buffer);
        Ok(Self(header))
    }

    /// Parse an exact-size envelope and validate its ephemeral P-256 point.
    /// This is a structural check, not authentication or signer verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENVELOPE_LEN {
            return Err(Error::InvalidEncoding);
        }
        if &bytes[..4] != MAGIC {
            return Err(Error::UnsupportedFormat);
        }
        // Reject noncanonical SEC1 forms and invalid/off-curve/infinity points
        // before passing anything to a hardware adapter.
        if bytes[68] != 4 {
            return Err(Error::InvalidPublicKey);
        }
        p256::PublicKey::from_sec1_bytes(&bytes[68..133]).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Public fingerprint of the recipient for this envelope.
    pub fn recipient(&self) -> KeyId {
        KeyId::from_bytes(self.0[4..36].try_into().expect("validated envelope"))
    }

    /// Recover a key using a hardware or software backend, without opening any
    /// payload. Rewrapping this result can delegate access without reading data.
    pub async fn unwrap(
        &self,
        recipient: &PublicKey,
        context: &[u8],
        backend: &(impl KeyAgreement + ?Sized),
    ) -> Result<ContentKey> {
        if recipient.id() != self.recipient() || backend.key_id() != self.recipient() {
            return Err(Error::WrongRecipient);
        }
        if self.0[36..68] != context_hash(context)? {
            return Err(Error::Authentication);
        }
        let request = AgreementRequest {
            recipient: recipient.id(),
            peer: array(&self.0[68..133])?,
        };
        let secret = backend.agree(&request).await?;
        let wrapping_key = derive_key(secret.0.as_ref(), recipient, &self.0[..HEADER_LEN])?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref()).expect("32-byte key");
        let mut buffer = Zeroizing::new(self.0[HEADER_LEN..].to_vec());
        let nonce = XNonce::from(array::<24>(&self.0[133..157])?);
        cipher
            .decrypt_in_place(&nonce, &self.0[..HEADER_LEN], &mut *buffer)
            .map_err(|_| Error::Authentication)?;
        let mut key = ContentKey::from_bytes([0; 32]);
        key.0.copy_from_slice(&buffer);
        Ok(key)
    }

    /// Borrow the complete detached envelope encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn derive_key(secret: &[u8], recipient: &PublicKey, header: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = Sha256::new();
    salt.update(b"Kagitaba/v1/ecdh-salt\0");
    salt.update(&header[68..133]);
    salt.update(recipient.point());
    let salt = salt.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand_multi_info(&[b"Kagitaba/v1/wrapping-key\0", header], key.as_mut())
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

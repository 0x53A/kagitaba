use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::{array, context_hash};
use crate::{Error, Result};

/// Maximum plaintext size for one small encrypted object (1 MiB).
pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"KTC1";
const HEADER_LEN: usize = 60; // magic, nonce[24], SHA256(context)[32]

/// Owned decrypted bytes, zeroized when dropped. Never formatted via `Debug`.
pub struct Plaintext(pub(super) Zeroizing<Vec<u8>>);

impl Plaintext {
    /// Expose the bytes to the application. Any copies are its responsibility.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A 256-bit symmetric content key, zeroized on drop, never implicitly cloned.
pub struct ContentKey(pub(super) Zeroizing<[u8; 32]>);

impl ContentKey {
    /// Generate a fresh key. Applications use a new key for every revision.
    pub fn generate(rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<Self> {
        let mut key = Self(Zeroizing::new([0; 32]));
        rng.try_fill_bytes(key.0.as_mut())
            .map_err(|_| Error::Randomness)?;
        Ok(key)
    }

    /// Explicitly import a key. The caller must clear its own copies.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Explicitly borrow key bytes, e.g. for an application-defined descriptor.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Versioned authenticated ciphertext. This is a byte format, not a file API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Encrypt opaque bytes, authenticating the caller's non-secret context.
    pub fn seal(
        plaintext: &[u8],
        key: &ContentKey,
        context: &[u8],
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Self> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::SizeLimit);
        }
        let mut nonce = [0; 24];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Randomness)?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&context_hash(context)?);
        let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
        buffer.extend_from_slice(plaintext);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key");
        cipher
            .encrypt_in_place(&XNonce::from(nonce), &header, &mut *buffer)
            .map_err(|_| Error::Authentication)?;
        header.extend_from_slice(&buffer);
        Ok(Self(header))
    }

    /// Check structural validity and bounds. This does NOT authenticate bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > HEADER_LEN + MAX_PLAINTEXT_BYTES + 16 {
            return Err(Error::SizeLimit);
        }
        if bytes.len() < HEADER_LEN + 16 {
            return Err(Error::InvalidEncoding);
        }
        if &bytes[..4] != MAGIC {
            return Err(Error::UnsupportedFormat);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Authenticate and decrypt using exactly the original context.
    pub fn open(&self, key: &ContentKey, context: &[u8]) -> Result<Plaintext> {
        if self.0[28..60] != context_hash(context)? {
            return Err(Error::Authentication);
        }
        let nonce = array::<24>(&self.0[4..28])?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key");
        let mut buffer = Zeroizing::new(self.0[HEADER_LEN..].to_vec());
        cipher
            .decrypt_in_place(&XNonce::from(nonce), &self.0[..HEADER_LEN], &mut *buffer)
            .map_err(|_| Error::Authentication)?;
        Ok(Plaintext(buffer))
    }

    /// Borrow the complete serialized ciphertext, including its header and tag.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//! Byte-oriented encryption with no knowledge of wallet records or storage.
//!
//! Suite 1: XChaCha20-Poly1305 payloads and ephemeral-static P-256 ECDH,
//! HKDF-SHA-256, XChaCha20-Poly1305 key envelopes. This is Kagitaba's envelope
//! construction, not age, HPKE, or a claim of independent cryptographic review.

mod keys;
mod symmetric;
mod wrapping;

pub use keys::{AgreementRequest, AgreementSecret, KeyAgreement, PublicKey, SoftwareIdentity};
pub use symmetric::{Ciphertext, ContentKey, MAX_PLAINTEXT_BYTES, Plaintext};
pub use wrapping::WrappedKey;

use crate::{Error, Result};
use sha2::{Digest, Sha256};

const MAX_CONTEXT_BYTES: usize = 64 * 1024;

fn context_hash(context: &[u8]) -> Result<[u8; 32]> {
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::SizeLimit);
    }
    Ok(Sha256::digest(context).into())
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::InvalidEncoding)
}

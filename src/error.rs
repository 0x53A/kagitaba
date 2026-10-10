//! Errors deliberately contain no plaintext, key material, or backend details.

/// A core operation's result.
pub type Result<T> = core::result::Result<T, Error>;

/// Failure to parse, authenticate, or construct a wallet operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// An encoding is malformed, truncated, or contains trailing data.
    #[error("invalid encoding")]
    InvalidEncoding,
    /// An object exceeds the format's size limit.
    #[error("size limit exceeded")]
    SizeLimit,
    /// The format version or cipher suite is unsupported.
    #[error("unsupported format or cipher suite")]
    UnsupportedFormat,
    /// The public key is invalid or unsupported by this backend.
    #[error("invalid or unsupported public key")]
    InvalidPublicKey,
    /// A software private key is invalid.
    #[error("invalid private key")]
    InvalidPrivateKey,
    /// Ciphertext, wrapping, or the supplied context did not authenticate.
    #[error("authentication failed")]
    Authentication,
    /// A key agreement implementation does not own the requested key.
    #[error("wrong recipient")]
    WrongRecipient,
    /// A device refused, cancelled, or failed a private-key operation.
    #[error("private-key operation unavailable")]
    KeyUnavailable,
    /// The random source could not provide fresh random bytes.
    #[error("randomness unavailable")]
    Randomness,
    /// An entry, grant, or participant identifier was supplied twice.
    #[error("duplicate identifier")]
    Duplicate,
    /// The referenced entry or participant is absent.
    #[error("record not found")]
    NotFound,
    /// A grant refers to a different primary record or revision.
    #[error("grant does not match the primary record")]
    StaleGrant,
    /// A replacement primary record reused its preceding revision identifier.
    #[error("a replacement requires a fresh revision identifier")]
    ReusedRevision,
}

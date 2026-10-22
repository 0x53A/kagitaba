//! Application-level CXF payloads. The cryptographic core remains schema-free.
//!
//! Import accepts plaintext CXF JSON bytes, including CXF obtained after a CXP
//! ceremony. Encrypted CXP responses require a separate protocol/session adapter.
//! No filesystem, network, Git, or device I/O is performed here.
//!
//! ```no_run
//! use kagitaba_cxf::{Document, Result};
//! use kagitaba_core::{KeyId, wallet::Wallet};
//! use rand_core::TryCryptoRng;
//!
//! fn import(input: impl std::io::Read, wallet: &Wallet, recipients: &[KeyId],
//!           rng: &mut impl TryCryptoRng) -> Result<Wallet> {
//!     let document = Document::from_reader(input)?;
//!     let plan = document.plan_import(wallet, rng)?;
//!     // The application can display plan.report() for review before encryption.
//!     plan.encrypt_into(wallet, recipients, rng)
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attachments;
pub mod password;
pub mod otp;
pub mod bitwarden;
pub mod firefox;
mod conversion;
mod document;
mod import;
mod json;
#[cfg(feature = "keepass")]
pub mod keepass;
mod payload;
mod participant;

pub use conversion::{Conversion, ConversionReport, ImportWarning, SourceAttachment, WarningKind, WarningDetail};
pub use credential_exchange_format as model;
pub use document::{Document, MAX_DOCUMENT_BYTES};
pub use import::{ImportPlan, ImportReport};
pub use payload::{Payload, PayloadKind};
pub use participant::ParticipantMetadata;

/// Failures contain neither source JSON nor credential values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Encrypted Bitwarden JSON requires a different decryption adapter.
    #[error("choose Bitwarden's unencrypted JSON export for this importer")]
    EncryptedExport,
    /// Wrong KeePass credentials, corruption, or an unsupported database feature.
    #[error("could not unlock or parse KeePass database")]
    KeePassUnlock,
    /// A caller-provided input stream could not be read.
    #[error("could not read credential input")]
    Read,
    /// A caller-provided attachment staging sink could not be written.
    #[error("could not write attachment staging output")]
    Write,
    /// Malformed JSON, duplicate object members, or invalid CXF structure.
    #[error("invalid credential document")]
    InvalidDocument,
    /// Incompatible document or application payload version.
    #[error("unsupported credential format version")]
    UnsupportedVersion,
    /// Encrypted CXP is a protocol response, not plaintext CXF.
    #[error("CXP response requires its exchange session and protocol decoder")]
    CxpSessionRequired,
    /// Plain CXF JSON has no transport for owner-bound Kagitaba attachment blobs.
    #[error("owned Kagitaba attachments require a wallet backup; plain CXF imports cannot carry their file data")]
    OwnedAttachmentsUnsupported,
    /// A bounded input or payload limit was exceeded.
    #[error("credential document exceeds a size or nesting limit")]
    SizeLimit,
    /// Duplicate or ambiguous account/entity identifiers.
    #[error("duplicate credential identifier")]
    DuplicateId,
    /// Encryption requires a nonempty explicit set of registered recipients.
    #[error("invalid import recipients")]
    InvalidRecipients,
    /// Envelope identity and entry identity disagree.
    #[error("credential payload does not match its entry")]
    WrongEntry,
    /// The cryptographic or immutable-wallet operation failed.
    #[error(transparent)]
    Core(#[from] kagitaba_core::Error),
}

/// Result of an application schema/import operation.
pub type Result<T> = std::result::Result<T, Error>;

//! Kagitaba's two in-memory layers:
//!
//! * [`crypto`] encrypts bytes and wraps symmetric keys. It knows no entries,
//!   paths, storage, Git, network, or credential schema.
//! * [`wallet`] holds immutable snapshots of opaque primary records and grants.
//!   It supplies authenticated context but never interprets a record's contents.
//!
//! The application owns randomness, hardware transports, credential schemas,
//! large-object/chunk storage, persistence, history verification, and trust.
//! This is a prototype format, not a reviewed production password manager.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
mod error;
mod ids;
pub mod wallet;

pub use error::{Error, Result};
pub use ids::{EntryId, KeyId, RevisionId};

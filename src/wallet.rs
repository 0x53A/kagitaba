//! Immutable logical snapshots, independent of Git and storage paths.
//!
//! Primary records and grant bodies are opaque. They may contain ciphertext,
//! retrieval instructions, or another application-defined representation. This
//! module checks associations and revisions, not cryptographic authenticity.
//! The application validates signatures/trust before constructing a snapshot.

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

use crate::{EntryId, Error, KeyId, Result, RevisionId, crypto::PublicKey};

/// Maximum size of an opaque primary record's body (2 MiB).
pub const MAX_PRIMARY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum size of one opaque grant body (64 KiB).
pub const MAX_GRANT_BYTES: usize = 64 * 1024;
const PRIMARY_HEADER: usize = 36;
const GRANT_HEADER: usize = 100;

/// The single authoritative opaque primary record for an entry revision.
#[derive(Clone, PartialEq, Eq)]
pub struct PrimaryRecord {
    entry: EntryId,
    revision: RevisionId,
    body: Vec<u8>,
}

impl PrimaryRecord {
    /// Build a record without interpreting its contents.
    pub fn new(entry: EntryId, revision: RevisionId, body: Vec<u8>) -> Result<Self> {
        if body.len() > MAX_PRIMARY_BYTES {
            return Err(Error::SizeLimit);
        }
        Ok(Self {
            entry,
            revision,
            body,
        })
    }

    /// Stable identity of the entry.
    pub fn entry_id(&self) -> EntryId {
        self.entry
    }
    /// Identity of this primary-record revision.
    pub fn revision_id(&self) -> RevisionId {
        self.revision
    }
    /// Opaque application-owned contents.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Domain-separated encryption context, available before encrypting a body.
    /// The crypto layer receives these bytes without understanding their fields.
    pub fn content_context(entry: EntryId, revision: RevisionId) -> Vec<u8> {
        let mut context = b"Kagitaba/v1/content\0".to_vec();
        context.extend_from_slice(entry.as_bytes());
        context.extend_from_slice(revision.as_bytes());
        context
    }

    /// SHA-256 of the complete canonical primary record, including its identity.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Context binding a cryptographic grant to this primary and recipient.
    /// Applications MUST pass this to both wrapping and unwrapping operations.
    pub fn grant_context(&self, recipient: KeyId) -> Vec<u8> {
        binding_context(self.entry, self.revision, recipient, &self.digest())
    }

    /// Serialize a primary record. No paths, filenames, or external I/O.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PRIMARY_HEADER + self.body.len());
        bytes.extend_from_slice(b"KTP1");
        bytes.extend_from_slice(self.entry.as_bytes());
        bytes.extend_from_slice(self.revision.as_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parse a bounded record. Its body is deliberately not parsed/decrypted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_record(bytes, b"KTP1", PRIMARY_HEADER, MAX_PRIMARY_BYTES)?;
        Self::new(
            EntryId::from_bytes(read_array(&bytes[4..20])?),
            RevisionId::from_bytes(read_array(&bytes[20..36])?),
            bytes[PRIMARY_HEADER..].to_vec(),
        )
    }
}

impl fmt::Debug for PrimaryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimaryRecord")
            .field("entry", &self.entry)
            .field("revision", &self.revision)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Detached grant metadata plus opaque application-defined grant bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct GrantRecord {
    entry: EntryId,
    revision: RevisionId,
    recipient: KeyId,
    primary_digest: [u8; 32],
    body: Vec<u8>,
}

impl GrantRecord {
    /// Associate a grant body with a primary. This does not authenticate it.
    pub fn new(primary: &PrimaryRecord, recipient: KeyId, body: Vec<u8>) -> Result<Self> {
        if body.len() > MAX_GRANT_BYTES {
            return Err(Error::SizeLimit);
        }
        Ok(Self {
            entry: primary.entry,
            revision: primary.revision,
            recipient,
            primary_digest: primary.digest(),
            body,
        })
    }

    /// Stable entry identifier.
    pub fn entry_id(&self) -> EntryId {
        self.entry
    }
    /// Revision to which this grant refers.
    pub fn revision_id(&self) -> RevisionId {
        self.revision
    }
    /// Intended recipient's key fingerprint.
    pub fn recipient(&self) -> KeyId {
        self.recipient
    }
    /// Opaque grant contents, interpreted only by the application/backend.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Check that this grant belongs to the exact primary record supplied.
    /// A passing check alone does not establish cryptographic authenticity.
    pub fn validate_for(&self, primary: &PrimaryRecord) -> Result<()> {
        if self.entry != primary.entry
            || self.revision != primary.revision
            || self.primary_digest != primary.digest()
        {
            return Err(Error::StaleGrant);
        }
        Ok(())
    }

    /// Canonical detached-record encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(GRANT_HEADER + self.body.len());
        bytes.extend_from_slice(b"KTG1");
        bytes.extend_from_slice(self.entry.as_bytes());
        bytes.extend_from_slice(self.revision.as_bytes());
        bytes.extend_from_slice(self.recipient.as_bytes());
        bytes.extend_from_slice(&self.primary_digest);
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parse a bounded opaque grant record, without decrypting its body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_record(bytes, b"KTG1", GRANT_HEADER, MAX_GRANT_BYTES)?;
        Ok(Self {
            entry: EntryId::from_bytes(read_array(&bytes[4..20])?),
            revision: RevisionId::from_bytes(read_array(&bytes[20..36])?),
            recipient: KeyId::from_bytes(read_array(&bytes[36..68])?),
            primary_digest: read_array(&bytes[68..100])?,
            body: bytes[GRANT_HEADER..].to_vec(),
        })
    }
}

impl fmt::Debug for GrantRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRecord")
            .field("entry", &self.entry)
            .field("revision", &self.revision)
            .field("recipient", &self.recipient)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A primary record and its detached grants, checked for consistent references.
/// An entry may have no grants (e.g. an application-defined retrieval backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    primary: PrimaryRecord,
    grants: BTreeMap<KeyId, GrantRecord>,
}

impl Entry {
    /// Assemble independently loaded components. Reject duplicates/stale grants.
    pub fn from_parts(
        primary: PrimaryRecord,
        grants: impl IntoIterator<Item = GrantRecord>,
    ) -> Result<Self> {
        let mut by_recipient = BTreeMap::new();
        for grant in grants {
            grant.validate_for(&primary)?;
            if by_recipient.insert(grant.recipient, grant).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(Self {
            primary,
            grants: by_recipient,
        })
    }

    /// The opaque authoritative primary record.
    pub fn primary(&self) -> &PrimaryRecord {
        &self.primary
    }
    /// Immutable detached grants, indexed by recipient.
    pub fn grants(&self) -> &BTreeMap<KeyId, GrantRecord> {
        &self.grants
    }

    /// Return a new entry with an added grant, preserving all existing bytes.
    pub fn with_grant(&self, grant: GrantRecord) -> Result<Self> {
        grant.validate_for(&self.primary)?;
        if self.grants.contains_key(&grant.recipient) {
            return Err(Error::Duplicate);
        }
        let mut next = self.clone();
        next.grants.insert(grant.recipient, grant);
        Ok(next)
    }
}

/// An immutable, structurally validated wallet snapshot. Not a Git repository.
/// No signatures, history, filesystem, merge rules, or trust are inferred here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wallet {
    participants: BTreeMap<KeyId, PublicKey>,
    entries: BTreeMap<EntryId, Entry>,
}

impl Wallet {
    /// Construct a snapshot from independently loaded public keys and entries.
    pub fn from_parts(
        participants: impl IntoIterator<Item = PublicKey>,
        entries: impl IntoIterator<Item = Entry>,
    ) -> Result<Self> {
        let mut wallet = Self::default();
        for key in participants {
            if wallet.participants.insert(key.id(), key).is_some() {
                return Err(Error::Duplicate);
            }
        }
        for entry in entries {
            wallet.validate_entry(&entry)?;
            if wallet.entries.insert(entry.primary.entry, entry).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(wallet)
    }

    /// Registered public encryption keys. Registration does not confer access.
    pub fn participants(&self) -> &BTreeMap<KeyId, PublicKey> {
        &self.participants
    }
    /// Entry records indexed by their stable identities.
    pub fn entries(&self) -> &BTreeMap<EntryId, Entry> {
        &self.entries
    }

    /// Add a public key to a new snapshot. No entry or grant is changed.
    /// The application must authorise enrolment before calling this method.
    pub fn with_participant(&self, key: PublicKey) -> Result<Self> {
        if self.participants.contains_key(&key.id()) {
            return Err(Error::Duplicate);
        }
        let mut next = self.clone();
        next.participants.insert(key.id(), key);
        Ok(next)
    }

    /// Install a new entry or replace an existing one in a new snapshot.
    /// A changed primary requires a new revision ID and matching grant records.
    /// Fresh cryptographic keys are the responsibility of the application using
    /// the crypto layer: this layer cannot interpret the opaque bodies.
    pub fn with_entry(&self, entry: Entry) -> Result<Self> {
        self.validate_entry(&entry)?;
        if let Some(old) = self.entries.get(&entry.primary.entry)
            && old.primary != entry.primary
            && old.primary.revision == entry.primary.revision
        {
            return Err(Error::ReusedRevision);
        }
        let mut next = self.clone();
        next.entries.insert(entry.primary.entry, entry);
        Ok(next)
    }

    /// Remove an entry in a new snapshot. Historical snapshots remain readable.
    pub fn without_entry(&self, id: EntryId) -> Result<Self> {
        if !self.entries.contains_key(&id) {
            return Err(Error::NotFound);
        }
        let mut next = self.clone();
        next.entries.remove(&id);
        Ok(next)
    }

    fn validate_entry(&self, entry: &Entry) -> Result<()> {
        for grant in entry.grants.values() {
            grant.validate_for(&entry.primary)?;
            if !self.participants.contains_key(&grant.recipient) {
                return Err(Error::NotFound);
            }
        }
        Ok(())
    }
}

fn binding_context(
    entry: EntryId,
    revision: RevisionId,
    recipient: KeyId,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut context = b"Kagitaba/v1/grant\0".to_vec();
    context.extend_from_slice(entry.as_bytes());
    context.extend_from_slice(revision.as_bytes());
    context.extend_from_slice(recipient.as_bytes());
    context.extend_from_slice(digest);
    context
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::InvalidEncoding)
}

fn check_record(bytes: &[u8], magic: &[u8; 4], header: usize, max_body: usize) -> Result<()> {
    if bytes.len() > header + max_body {
        return Err(Error::SizeLimit);
    }
    if bytes.len() < header {
        return Err(Error::InvalidEncoding);
    }
    if &bytes[..4] != magic {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}

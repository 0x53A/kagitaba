use std::collections::BTreeSet;

use kagitaba_core::{
    EntryId, RevisionId,
    crypto::{Ciphertext, ContentKey, KeyAgreement, PublicKey, WrappedKey},
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use rand_core::TryCryptoRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    document::{validate_collection, validate_item},
    json::{self, SecretJson},
};

const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// CXF entity stored inside an independently encrypted entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// One CXF Item containing related credentials.
    Item,
    /// One CXF root Collection and all its embedded descendants.
    Collection,
}

/// Versioned application envelope containing a CXF entity and optional provenance.
/// All fields, including metadata, are encrypted by `seal`.
pub struct Payload {
    pub(crate) raw: SecretJson,
    entry: EntryId,
    kind: PayloadKind,
}

impl Payload {
    /// Construct a native payload from a CXF entity's JSON. Its ID must encode
    /// the supplied entry's 16 bytes. Unknown fields are retained.
    pub fn new(entry: EntryId, kind: PayloadKind, entity_json: &[u8]) -> Result<Self> {
        let entity = json::parse(entity_json, MAX_PAYLOAD_BYTES)?;
        Self::build(entry, kind, entity.0.clone(), Value::Null, 0)
    }

    pub(crate) fn build(
        entry: EntryId,
        kind: PayloadKind,
        entity: Value,
        source: Value,
        minor: u8,
    ) -> Result<Self> {
        let mut raw = SecretJson(json!({
            "format": "kagitaba-cxf", "version": 1,
            "cxfVersion": {"major": 1, "minor": minor},
            "kind": match kind { PayloadKind::Item => "item", PayloadKind::Collection => "collection" },
            "entity": entity
        }));
        if !source.is_null() {
            raw.0["source"] = source;
        }
        // Enveloping also increases nesting (including imported provenance).
        // Apply exactly the reader's limits to the complete result.
        Self::from_json(entry, &json::encode(&raw.0)?)
    }

    /// Parse decrypted application bytes and bind their inner ID to the outer
    /// entry ID. Does not interpret arbitrary middle-layer record bodies.
    pub fn from_json(entry: EntryId, bytes: &[u8]) -> Result<Self> {
        Self::validated(entry, json::parse(bytes, MAX_PAYLOAD_BYTES)?)
    }

    fn validated(entry: EntryId, raw: SecretJson) -> Result<Self> {
        if raw.0["format"] != "kagitaba-cxf"
            || raw.0["version"] != 1
            || raw.0["cxfVersion"]["major"] != 1
        {
            return Err(Error::UnsupportedVersion);
        }
        if !matches!(raw.0["cxfVersion"]["minor"].as_u64(), Some(0..=255)) {
            return Err(Error::InvalidDocument);
        }
        let kind = match raw.0["kind"].as_str() {
            Some("item") => {
                validate_item(&raw.0["entity"])?;
                PayloadKind::Item
            }
            Some("collection") => {
                validate_collection(&raw.0["entity"], &mut BTreeSet::new(), 0)?;
                PayloadKind::Collection
            }
            _ => return Err(Error::UnsupportedVersion),
        };
        if json::id(&raw.0["entity"]["id"])? != entry.as_bytes() {
            return Err(Error::WrongEntry);
        }
        if json::encode(&raw.0)?.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::SizeLimit);
        }
        Ok(Self { raw, entry, kind })
    }

    /// Stable local entry identity.
    pub fn entry_id(&self) -> EntryId {
        self.entry
    }
    /// Whether this entry contains an item or an entire collection tree.
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
    /// Borrow the complete CXF entity. Contains secrets.
    pub fn entity(&self) -> &Value {
        &self.raw.0["entity"]
    }
    /// Borrow optional import provenance (header/account metadata and original ID).
    pub fn source(&self) -> Option<&Value> {
        self.raw.0.get("source")
    }
    /// Update display metadata while retaining all unsupported fields.
    pub fn set_title(&mut self, title: String, modified_at: u64) {
        self.raw.0["entity"]["title"] = title.into();
        self.raw.0["entity"]["modifiedAt"] = modified_at.into();
    }
    /// Serialize the versioned application envelope. Clears output on drop.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        json::encode(&self.raw.0)
    }

    /// Apply application edits to a lossless copy, then validate the entire
    /// envelope again. Failure leaves the original payload untouched.
    pub fn edited(&self, update: impl FnOnce(&mut Value) -> Result<()>) -> Result<Self> {
        let mut raw = SecretJson(self.raw.0.clone());
        update(&mut raw.0)?;
        Self::from_json(self.entry, &json::encode(&raw.0)?)
    }

    /// Encrypt a new revision with a fresh key and detached grants for exactly
    /// these recipients. This also implements atomic collection-tree updates.
    pub fn seal(
        &self,
        recipients: &[PublicKey],
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Entry> {
        if recipients.is_empty()
            || recipients
                .iter()
                .map(PublicKey::id)
                .collect::<BTreeSet<_>>()
                .len()
                != recipients.len()
        {
            return Err(Error::InvalidRecipients);
        }
        let bytes = self.to_json()?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::SizeLimit);
        }
        let revision = RevisionId::generate(rng)?;
        let key = ContentKey::generate(rng)?;
        let encrypted = Ciphertext::seal(
            &bytes,
            &key,
            &PrimaryRecord::content_context(self.entry, revision),
            rng,
        )?;
        let primary = PrimaryRecord::new(self.entry, revision, encrypted.as_bytes().to_vec())?;
        let mut grants = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let wrapped =
                WrappedKey::wrap(&key, recipient, &primary.grant_context(recipient.id()), rng)?;
            grants.push(GrantRecord::new(
                &primary,
                recipient.id(),
                wrapped.as_bytes().to_vec(),
            )?);
        }
        Ok(Entry::from_parts(primary, grants)?)
    }

    /// Decrypt using the existing software/hardware key agreement boundary.
    /// Caller must establish snapshot trust before calling this method.
    pub async fn open(
        entry: &Entry,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<Self> {
        let primary = entry.primary();
        let grant = entry
            .grants()
            .get(&recipient.id())
            .ok_or(kagitaba_core::Error::NotFound)?;
        grant.validate_for(primary)?;
        let key = WrappedKey::from_bytes(grant.body())?
            .unwrap(recipient, &primary.grant_context(recipient.id()), backend)
            .await?;
        let clear = Ciphertext::from_bytes(primary.body())?.open(
            &key,
            &PrimaryRecord::content_context(primary.entry_id(), primary.revision_id()),
        )?;
        Self::from_json(primary.entry_id(), clear.as_bytes())
    }
}

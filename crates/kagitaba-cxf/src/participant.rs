//! Encrypted application metadata; deliberately separate from CXF credentials.
use crate::{
    Error, Result,
    json::{self, SecretJson},
};
use kagitaba_core::{
    EntryId, KeyId, RevisionId,
    crypto::{Ciphertext, ContentKey, KeyAgreement, PublicKey, WrappedKey},
    wallet::{Entry, GrantRecord, PrimaryRecord},
};
use rand_core::TryCryptoRng;
use serde_json::json;
use zeroize::Zeroizing;

/// JSON metadata bound to one participant and one normal encrypted entry.
/// Unknown members survive name edits. No plaintext file is written.
pub struct ParticipantMetadata {
    raw: SecretJson,
    entry: EntryId,
}

impl ParticipantMetadata {
    /// Create an empty versioned metadata object.
    pub fn new(entry: EntryId, participant: KeyId) -> Self {
        Self {
            entry,
            raw: SecretJson(
                json!({"format":"kagitaba-participant-metadata", "version":1, "entryId":entry.to_string(), "participantId":participant.to_string()}),
            ),
        }
    }
    /// Parse bounded JSON, rejecting duplicate members and mismatched identities.
    pub fn from_json(entry: EntryId, participant: KeyId, bytes: &[u8]) -> Result<Self> {
        let raw = json::parse(bytes, 16384)?;
        if raw.0["format"] != "kagitaba-participant-metadata"
            || raw.0["version"].as_u64() != Some(1)
        {
            return Err(Error::UnsupportedVersion);
        }
        if raw.0["entryId"] != entry.to_string()
            || raw.0["participantId"] != participant.to_string()
        {
            return Err(Error::WrongEntry);
        }
        if let Some(name) = raw.0.get("name") {
            Self::validate_name(name.as_str().ok_or(Error::InvalidDocument)?)?;
        }
        Ok(Self { raw, entry })
    }
    /// Validate a display hint, never an authorization identity.
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty()
            || name.trim() != name
            || name.len() > 512
            || name.chars().count() > 128
            || name.chars().any(|c| {
                c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err(Error::InvalidDocument);
        }
        Ok(())
    }
    /// Optional decrypted display name.
    pub fn name(&self) -> Option<&str> {
        self.raw.0.get("name").and_then(|v| v.as_str())
    }
    /// Change just the name; an empty string removes it, preserving other fields.
    pub fn set_name(&mut self, name: &str) -> Result<()> {
        if name.is_empty() {
            self.raw
                .0
                .as_object_mut()
                .ok_or(Error::InvalidDocument)?
                .remove("name");
        } else {
            Self::validate_name(name)?;
            self.raw.0["name"] = name.into();
        }
        Ok(())
    }
    /// Serialize secret JSON into a buffer cleared on drop.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        json::encode(&self.raw.0)
    }
    /// Encrypt a fresh revision for all supplied participants.
    pub fn seal(
        &self,
        recipients: &[PublicKey],
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Entry> {
        if recipients.is_empty() {
            return Err(Error::InvalidRecipients);
        }
        let bytes = self.to_json()?;
        if bytes.len() > 16384 {
            return Err(Error::SizeLimit);
        }
        let revision = RevisionId::generate(rng)?;
        let key = ContentKey::generate(rng)?;
        let ciphertext = Ciphertext::seal(
            &bytes,
            &key,
            &PrimaryRecord::content_context(self.entry, revision),
            rng,
        )?;
        let primary = PrimaryRecord::new(self.entry, revision, ciphertext.as_bytes().to_vec())?;
        let grants = recipients
            .iter()
            .map(|p| {
                let wrapped = WrappedKey::wrap(&key, p, &primary.grant_context(p.id()), rng)?;
                GrantRecord::new(&primary, p.id(), wrapped.as_bytes().to_vec())
            })
            .collect::<kagitaba_core::Result<Vec<_>>>()?;
        Ok(Entry::from_parts(primary, grants)?)
    }
    /// Open only after verifying history; bind the pointer's participant as well.
    pub async fn open(
        entry: &Entry,
        participant: KeyId,
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
        Self::from_json(primary.entry_id(), participant, clear.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use rand_core::SeedableRng;
    #[test]
    fn encrypted_metadata_binds_ids_preserves_unknown_json_and_rotates() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([21; 32]);
        let a = SoftwareIdentity::from_bytes(&[8; 32]).unwrap();
        let b = SoftwareIdentity::from_bytes(&[9; 32]).unwrap();
        let id = EntryId::from_bytes([1; 16]);
        let participant = a.public_key().id();
        let mut raw = ParticipantMetadata::new(id, participant);
        raw.set_name("Private key name").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&raw.to_json().unwrap()).unwrap();
        value["future"] = json!({"nested":["preserved",9007199254740993u64]});
        raw = ParticipantMetadata::from_json(id, participant, &serde_json::to_vec(&value).unwrap())
            .unwrap();
        let sealed = raw
            .seal(&[a.public_key(), b.public_key()], &mut rng)
            .unwrap();
        let mut opened = futures::executor::block_on(ParticipantMetadata::open(
            &sealed,
            participant,
            &b.public_key(),
            &b,
        ))
        .unwrap();
        assert_eq!(opened.name(), Some("Private key name"));
        opened.set_name("").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&opened.to_json().unwrap()).unwrap();
        assert_eq!(value["future"]["nested"][1], 9007199254740993u64);
        assert!(value.get("name").is_none());
        let rotated = opened.seal(&[a.public_key()], &mut rng).unwrap();
        assert_ne!(
            sealed.primary().revision_id(),
            rotated.primary().revision_id()
        );
        assert!(
            futures::executor::block_on(ParticipantMetadata::open(
                &rotated,
                participant,
                &b.public_key(),
                &b
            ))
            .is_err()
        );
        assert!(
            futures::executor::block_on(ParticipantMetadata::open(
                &sealed,
                b.public_key().id(),
                &a.public_key(),
                &a
            ))
            .is_err()
        );
        assert!(
            ParticipantMetadata::from_json(
                EntryId::from_bytes([2; 16]),
                participant,
                &raw.to_json().unwrap()
            )
            .is_err()
        );
        let duplicate = format!(
            "{{\"format\":\"kagitaba-participant-metadata\",\"version\":1,\"entryId\":\"{id}\",\"participantId\":\"{participant}\",\"name\":\"one\",\"name\":\"two\"}}"
        );
        assert!(ParticipantMetadata::from_json(id, participant, duplicate.as_bytes()).is_err());
    }
}

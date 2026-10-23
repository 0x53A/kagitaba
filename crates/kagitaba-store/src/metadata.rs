use crate::{Error, Result, Snapshot};
use kagitaba_core::{
    EntryId, KeyId,
    crypto::{KeyAgreement, PublicKey, WrappedKey},
    wallet::GrantRecord,
};
use kagitaba_cxf::ParticipantMetadata;
use rand_core::TryCryptoRng;
use std::collections::BTreeMap;

impl Snapshot {
    /// Whether an entry is application metadata rather than a credential.
    pub fn is_metadata(&self, entry: &EntryId) -> bool {
        self.metadata.values().any(|id| id == entry)
    }

    /// Convert legacy names and prune obsolete browser recovery packages.
    /// Call on a candidate snapshot; publish only after the entire operation succeeds.
    pub fn prune_legacy(&mut self, rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<()> {
        let recipients = self
            .wallet
            .participants()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for (participant, name) in std::mem::take(&mut self.names) {
            let id = EntryId::generate(rng)?;
            if self.wallet.entries().contains_key(&id) {
                return Err(Error::Invalid);
            }
            let mut payload = ParticipantMetadata::new(id, participant);
            payload.set_name(&name).map_err(|_| Error::InvalidName)?;
            self.wallet = self
                .wallet
                .with_entry(payload.seal(&recipients, rng).map_err(|_| Error::Invalid)?)?;
            self.metadata.insert(participant, id);
        }
        self.browsers.clear();
        Ok(())
    }

    /// Decrypt display names only for an unlocked, enrolled participant.
    pub async fn participant_names(
        &self,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<BTreeMap<KeyId, String>> {
        let mut names = BTreeMap::new();
        if !self.wallet.participants().contains_key(&recipient.id()) {
            return Ok(names);
        }
        for (participant, id) in &self.metadata {
            let entry = &self.wallet.entries()[id];
            // A clean merge may precede its grant-repair commit.
            if !entry.grants().contains_key(&recipient.id()) {
                continue;
            }
            let payload = ParticipantMetadata::open(entry, *participant, recipient, backend)
                .await
                .map_err(|_| Error::Invalid)?;
            if let Some(name) = payload.name() {
                names.insert(*participant, name.to_owned());
            }
        }
        Ok(names)
    }

    /// Edit only the encrypted name, preserving other metadata members.
    pub async fn name_participant(
        &mut self,
        participant: KeyId,
        name: &str,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<()> {
        if !self.wallet.participants().contains_key(&participant) {
            return Err(Error::Invalid);
        }
        if !name.is_empty() {
            crate::validate_name(name)?;
        }
        self.prune_legacy(rng)?;
        let id = match self.metadata.get(&participant) {
            Some(id) => *id,
            None if name.is_empty() => return Ok(()),
            None => EntryId::generate(rng)?,
        };
        let mut payload = if let Some(entry) = self.wallet.entries().get(&id) {
            ParticipantMetadata::open(entry, participant, recipient, backend)
                .await
                .map_err(|_| Error::Invalid)?
        } else {
            ParticipantMetadata::new(id, participant)
        };
        payload.set_name(name).map_err(|_| Error::InvalidName)?;
        let recipients = self
            .wallet
            .participants()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        self.wallet = self
            .wallet
            .with_entry(payload.seal(&recipients, rng).map_err(|_| Error::Invalid)?)?;
        self.metadata.insert(participant, id);
        Ok(())
    }

    /// Add missing metadata grants without changing primary bytes or existing grants.
    /// Used after enrolment and as a separate signed commit after a clean merge.
    pub async fn complete_metadata_grants(
        &mut self,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<bool> {
        let mut updates = Vec::new();
        for id in self.metadata.values() {
            let entry = &self.wallet.entries()[id];
            let missing = self
                .wallet
                .participants()
                .values()
                .filter(|p| !entry.grants().contains_key(&p.id()))
                .collect::<Vec<_>>();
            if missing.is_empty() {
                continue;
            }
            let grant = entry
                .grants()
                .get(&recipient.id())
                .ok_or(Error::Core(kagitaba_core::Error::NotFound))?;
            let primary = entry.primary();
            let key = WrappedKey::from_bytes(grant.body())?
                .unwrap(recipient, &primary.grant_context(recipient.id()), backend)
                .await?;
            let mut updated = entry.clone();
            for public in missing {
                let wrapped =
                    WrappedKey::wrap(&key, public, &primary.grant_context(public.id()), rng)?;
                updated = updated.with_grant(GrantRecord::new(
                    primary,
                    public.id(),
                    wrapped.as_bytes().to_vec(),
                )?)?;
            }
            updates.push(updated);
        }
        let changed = !updates.is_empty();
        if changed {
            self.wallet = self.wallet.with_entries(updates)?;
        }
        Ok(changed)
    }
}

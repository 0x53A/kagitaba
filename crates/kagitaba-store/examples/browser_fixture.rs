//! Synthetic interoperability fixture. Never reads real wallet material.
use kagitaba_core::{
    EntryId, RevisionId,
    crypto::{PublicKey, SoftwareIdentity},
    wallet::{Entry, PrimaryRecord},
};
use kagitaba_store::{Signer, Snapshot, Store};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    pkcs8::EncodePublicKey,
};
use rand_core::SeedableRng;
use std::io::Write;

struct Key {
    secret: SigningKey,
    public: PublicKey,
}
impl Signer for Key {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign(&self, message: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
        let signature: Signature = self.secret.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("provide a new fixture JSON output path")?;
    let secret = SigningKey::from_slice(&[12; 32])?;
    let public = PublicKey::from_der(secret.verifying_key().to_public_key_der()?.as_bytes())?;
    let key = Key { secret, public };
    let enc = SoftwareIdentity::from_bytes(&[8; 32])?.public_key();
    let dir = tempfile::tempdir()?;
    let retained = std::env::args().nth(2).map(std::path::PathBuf::from);
    let wallet_path = retained.unwrap_or_else(|| dir.path().join("fixture"));
    let mut store = Store::create(
        &wallet_path,
        Snapshot::empty(enc, key.public.clone())?,
        &key,
    )?;
    if std::env::args().nth(3).as_deref() == Some("--attachment") {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let id = EntryId::from_bytes([7; 16]);
        let payload = kagitaba_cxf::Payload::from_json(id, br#"{"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item","entity":{"id":"BwcHBwcHBwcHBwcHBwcHBw","title":"Synthetic attached item","credentials":[]}}"#)?;
        let (payload, blobs) = kagitaba_cxf::attachments::add(&payload, "synthetic.bin", &vec![17; 17 * 1024 * 1024], &mut rng)?;
        let recipients = store.snapshot.wallet.participants().values().cloned().collect::<Vec<_>>();
        let mut next = store.snapshot.clone();
        next.wallet = next.wallet.with_entry(payload.seal(&recipients, &mut rng)?)?;
        next.attachments.insert(id, blobs.iter().map(|(id, chunks)| Ok((id.clone(), kagitaba_store::AttachmentBlob::from_chunks(chunks)?))).collect::<kagitaba_store::Result<_>>()?);
        store.save(next, &key, "Synthetic attachment")?;
    }
    if std::env::args().nth(3).as_deref() == Some("--merge") {
        let peer_path = dir.path().join("peer");
        store.backup_to(&peer_path)?;
        let mut peer = Store::open(&peer_path, key.public.clone(), Some(store.head))?;
        for (replica, id) in [(&mut store, 1), (&mut peer, 2)] {
            let mut next = replica.snapshot.clone();
            let primary = PrimaryRecord::new(
                EntryId::from_bytes([id; 16]),
                RevisionId::from_bytes([id; 16]),
                vec![id],
            )?;
            next.wallet = next.wallet.with_entry(Entry::from_parts(primary, [])?)?;
            replica.save(next, &key, "Synthetic independent entry")?;
        }
        store.merge_from(&peer_path, &key)?;
    }
    if std::env::args().nth(3).as_deref() == Some("--metadata-merge") {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let own = SoftwareIdentity::from_bytes(&[8; 32])?;
        let peer_path = dir.path().join("metadata-peer");
        store.backup_to(&peer_path)?;
        let mut peer = Store::open(&peer_path, key.public.clone(), Some(store.head))?;
        let mut next = store.snapshot.clone();
        let enc = SoftwareIdentity::from_bytes(&[9; 32])?.public_key();
        next.wallet = next.wallet.with_participant(enc.clone())?;
        next.signers.insert(enc.id(), enc);
        store.save(next, &key, "Synthetic enrolment")?;
        let mut next = peer.snapshot.clone();
        futures::executor::block_on(next.name_participant(
            own.public_key().id(),
            "Synthetic encrypted name",
            &own.public_key(),
            &own,
            &mut rng,
        ))?;
        peer.save(next, &key, "Synthetic name")?;
        let candidate = store.import_candidate(&peer_path)?;
        store.merge_then(candidate, &key, |next| {
            futures::executor::block_on(next.complete_metadata_grants(
                &own.public_key(),
                &own,
                &mut rng,
            ))
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(&store.export_transfer()?)?;
    Ok(())
}

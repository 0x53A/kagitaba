//! Immutable, owner-bound file attachments stored separately from encrypted item metadata.
mod stream;
pub use stream::{add_stream, copy_stream, decrypt_stream, expected_blob_size, rekey_stream, validate_blob_stream};

use crate::{Error, Payload, PayloadKind, Result};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use kagitaba_core::{
    EntryId,
    crypto::{Ciphertext, ContentKey},
};
use rand_core::TryCryptoRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

/// Maximum plaintext bytes in one file.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum owned files in one item.
pub const MAX_ATTACHMENTS: usize = 128;
/// Plaintext bytes per encrypted chunk.
pub const CHUNK_BYTES: usize = 1024 * 1024;
/// Maximum chunks in one file.
pub const MAX_CHUNKS: usize = 64;
/// Whether a blob revision uses the canonical 16-byte lowercase-hex encoding.
pub fn is_blob_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Ciphertext chunks keyed by fresh lowercase-hex blob revision.
pub type Blobs = BTreeMap<String, Vec<Vec<u8>>>;
/// Validated attachment descriptor. Its key is deliberately private and not Debug/Clone.
pub struct Attachment {
    /// Opaque attachment identifier, independent of its owner.
    pub id: EntryId,
    /// Display/download hint only; never a trusted path.
    pub name: String,
    /// Complete plaintext size.
    pub size: u64,
    /// Fresh opaque blob revision, changed when rekeying.
    pub blob_id: String,
    /// Number of authenticated chunks, including one for an empty file.
    pub chunk_count: u32,
    hash: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}
fn invalid<T>() -> Result<T> {
    Err(Error::InvalidDocument)
}
fn decoded<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let text = value.as_str().ok_or(Error::InvalidDocument)?;
    let bytes = Zeroizing::new(
        BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map_err(|_| Error::InvalidDocument)?,
    );
    if BASE64URL_NOPAD.encode(&bytes) != text {
        return invalid();
    }
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidDocument)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && name.chars().count() <= 255
        && name.trim() == name
        && !matches!(name, "." | "..")
        && !name.chars().any(|c| {
            c.is_control() || matches!(c,'/'|'\\'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
}
fn parse(value: &Value) -> Result<Attachment> {
    if value["type"] != "file" || value["kagitabaFile"]["version"] != 1 {
        return invalid();
    }
    let name = value["name"]
        .as_str()
        .filter(|s| valid_name(s))
        .ok_or(Error::InvalidDocument)?
        .to_owned();
    let size = value["decryptedSize"]
        .as_u64()
        .filter(|n| *n <= MAX_FILE_BYTES as u64)
        .ok_or(Error::SizeLimit)?;
    let blob_id = value["kagitabaFile"]["blobId"]
        .as_str()
        .ok_or(Error::InvalidDocument)?;
    if !is_blob_id(blob_id) {
        return invalid();
    }
    let expected = (size as usize).div_ceil(CHUNK_BYTES).max(1) as u32;
    if value["kagitabaFile"]["chunkCount"].as_u64() != Some(expected as u64) {
        return invalid();
    }
    Ok(Attachment {
        id: EntryId::from_bytes(decoded(&value["id"])?),
        name,
        size,
        blob_id: blob_id.to_owned(),
        chunk_count: expected,
        hash: decoded(&value["integrityHash"])?,
        key: Zeroizing::new(decoded(&value["kagitabaFile"]["key"])?),
    })
}
/// List only explicitly owned Kagitaba files. External CXF file references remain inert.
pub fn list(payload: &Payload) -> Result<Vec<Attachment>> {
    let mut files = Vec::new();
    let mut ids = BTreeSet::new();
    let mut blobs = BTreeSet::new();
    if let Some(credentials) = payload.entity()["credentials"].as_array() {
        for credential in credentials {
            if credential.get("kagitabaFile").is_none() {
                continue;
            }
            let attachment = parse(credential)?;
            if !ids.insert(attachment.id) || !blobs.insert(attachment.blob_id.clone()) {
                return invalid();
            }
            files.push(attachment);
            if files.len() > MAX_ATTACHMENTS {
                return Err(Error::SizeLimit);
            }
        }
    }
    if !files.is_empty() && payload.kind() != PayloadKind::Item {
        return invalid();
    }
    // A local attachment ID must not alias an inert external file descriptor.
    if let Some(credentials) = payload.entity()["credentials"].as_array() {
        for credential in credentials {
            if credential["type"] == "file"
                && credential.get("kagitabaFile").is_none()
                && let Some(text) = credential["id"].as_str()
                && let Ok(bytes) = BASE64URL_NOPAD
                    .decode(text.as_bytes())
                    .or_else(|_| data_encoding::BASE64URL.decode(text.as_bytes()))
                && let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice())
                && ids.contains(&EntryId::from_bytes(id))
            {
                return Err(Error::DuplicateId);
            }
        }
    }
    Ok(files)
}
fn context(owner: EntryId, file: &Attachment, position: u32) -> Vec<u8> {
    let mut context = b"Kagitaba/attachment/v1\0".to_vec();
    context.extend_from_slice(owner.as_bytes());
    context.extend_from_slice(file.id.as_bytes());
    context.extend_from_slice(
        &HEXLOWER
            .decode(file.blob_id.as_bytes())
            .expect("validated blob ID"),
    );
    context.extend_from_slice(&position.to_be_bytes());
    context.extend_from_slice(&file.chunk_count.to_be_bytes());
    context.extend_from_slice(&file.size.to_be_bytes());
    context
}
fn encrypt(
    owner: EntryId,
    file: &Attachment,
    bytes: &[u8],
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<Vec<Vec<u8>>> {
    let key = ContentKey::from_bytes(*file.key);
    let mut chunks = Vec::new();
    for position in 0..file.chunk_count {
        let start = position as usize * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(bytes.len());
        chunks.push(
            Ciphertext::seal(
                &bytes[start..end],
                &key,
                &context(owner, file, position),
                rng,
            )?
            .as_bytes()
            .to_vec(),
        );
    }
    Ok(chunks)
}
fn fresh(rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<[u8; 16]> {
    Ok(*EntryId::generate(rng)?.as_bytes())
}
fn credential(file: &Attachment) -> Value {
    json!({"type":"file","id":BASE64URL_NOPAD.encode(file.id.as_bytes()),"name":file.name,"decryptedSize":file.size,"integrityHash":BASE64URL_NOPAD.encode(&file.hash),"kagitabaFile":{"version":1,"blobId":file.blob_id,"key":BASE64URL_NOPAD.encode(file.key.as_ref()),"chunkCount":file.chunk_count}})
}
/// Add one file, returning the updated payload and only the new encrypted blob.
/// Caller combines blobs and publishes metadata/files in one signed transaction.
pub fn add(
    payload: &Payload,
    name: &str,
    bytes: &[u8],
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<(Payload, Blobs)> {
    if payload.kind() != PayloadKind::Item || !valid_name(name) {
        return invalid();
    }
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::SizeLimit);
    }
    let existing = list(payload)?;
    if existing.len() >= MAX_ATTACHMENTS {
        return Err(Error::SizeLimit);
    }
    let key = ContentKey::generate(rng)?;
    let file = Attachment {
        id: EntryId::generate(rng)?,
        name: name.to_owned(),
        size: bytes.len() as u64,
        blob_id: HEXLOWER.encode(&fresh(rng)?),
        chunk_count: bytes.len().div_ceil(CHUNK_BYTES).max(1) as u32,
        hash: Sha256::digest(bytes).into(),
        key: Zeroizing::new(*key.as_bytes()),
    };
    if existing
        .iter()
        .any(|old| old.id == file.id || old.blob_id == file.blob_id)
    {
        return Err(Error::DuplicateId);
    }
    let chunks = encrypt(payload.entry_id(), &file, bytes, rng)?;
    let next = payload.edited(|raw| {
        raw["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error::InvalidDocument)?
            .push(credential(&file));
        Ok(())
    })?;
    list(&next)?;
    Ok((next, BTreeMap::from([(file.blob_id.clone(), chunks)])))
}
/// Rename an owned file without changing its key, identity, ciphertext or other metadata.
pub fn rename(payload: &Payload, id: EntryId, name: &str) -> Result<Payload> {
    if !valid_name(name) || !list(payload)?.iter().any(|file| file.id == id) {
        return invalid();
    }
    let encoded = BASE64URL_NOPAD.encode(id.as_bytes());
    let next = payload.edited(|raw| {
        let file = raw["entity"]["credentials"].as_array_mut()
            .ok_or(Error::InvalidDocument)?.iter_mut()
            .find(|c| c.get("kagitabaFile").is_some() && c["id"].as_str() == Some(&encoded))
            .ok_or(Error::InvalidDocument)?;
        file["name"] = Value::String(name.to_owned());
        Ok(())
    })?;
    list(&next)?;
    Ok(next)
}
/// Remove one owned descriptor; returns its blob revision for atomic removal.
pub fn remove(payload: &Payload, id: EntryId) -> Result<(Payload, String)> {
    let file = list(payload)?
        .into_iter()
        .find(|f| f.id == id)
        .ok_or(Error::InvalidDocument)?;
    let next = payload.edited(|raw| {
        raw["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error::InvalidDocument)?
            .retain(|c| {
                !(c.get("kagitabaFile").is_some()
                    && c["id"].as_str() == Some(&BASE64URL_NOPAD.encode(id.as_bytes())))
            });
        Ok(())
    })?;
    Ok((next, file.blob_id.clone()))
}
/// Check exact blob membership, chunk counts and ciphertext sizes without decrypting.
pub fn validate_blobs(payload: &Payload, blobs: &Blobs) -> Result<()> {
    let files = list(payload)?;
    if files.len() != blobs.len() {
        return invalid();
    }
    for file in files {
        validate_file_chunks(
            &file,
            blobs.get(&file.blob_id).ok_or(Error::InvalidDocument)?,
        )?;
    }
    Ok(())
}
fn validate_file_chunks(file: &Attachment, chunks: &[Vec<u8>]) -> Result<()> {
    if file.size > MAX_FILE_BYTES as u64
        || !is_blob_id(&file.blob_id)
        || file.chunk_count != (file.size as usize).div_ceil(CHUNK_BYTES).max(1) as u32
        || chunks.len() != file.chunk_count as usize
    {
        return invalid();
    }
    for (position, chunk) in chunks.iter().enumerate() {
        let size = (file.size as usize - position * CHUNK_BYTES).min(CHUNK_BYTES);
        if chunk.len() != size + 76 {
            return invalid();
        }
        if !chunk.starts_with(b"KTC1") {
            return invalid();
        }
    }
    Ok(())
}
/// Authenticate every chunk and the final size/hash before returning any plaintext.
pub fn decrypt(
    owner: EntryId,
    file: &Attachment,
    chunks: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>> {
    validate_file_chunks(file, chunks)?;
    let key = ContentKey::from_bytes(*file.key);
    let mut bytes = Zeroizing::new(Vec::with_capacity(file.size as usize));
    for (position, chunk) in chunks.iter().enumerate() {
        let clear =
            Ciphertext::from_bytes(chunk)?.open(&key, &context(owner, file, position as u32))?;
        bytes.extend_from_slice(clear.as_bytes());
    }
    if bytes.len() != file.size as usize || Sha256::digest(&bytes).as_slice() != file.hash {
        return invalid();
    }
    Ok(bytes)
}
/// Rotate every owned file key and blob revision. Existing unknown descriptor fields survive.
/// Caller atomically publishes the returned full blob set with the updated payload.
pub fn rekey(
    payload: &Payload,
    blobs: &Blobs,
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<(Payload, Blobs)> {
    validate_blobs(payload, blobs)?;
    let mut replacements = BTreeMap::new();
    let mut next_blobs = Blobs::new();
    for mut file in list(payload)? {
        let clear = decrypt(payload.entry_id(), &file, &blobs[&file.blob_id])?;
        let old = file.blob_id.clone();
        file.blob_id = HEXLOWER.encode(&fresh(rng)?);
        file.key = Zeroizing::new(*ContentKey::generate(rng)?.as_bytes());
        if blobs.contains_key(&file.blob_id) || next_blobs.contains_key(&file.blob_id) {
            return Err(Error::DuplicateId);
        }
        next_blobs.insert(
            file.blob_id.clone(),
            encrypt(payload.entry_id(), &file, &clear, rng)?,
        );
        replacements.insert(old, file);
    }
    let next = payload.edited(|raw| {
        if let Some(credentials) = raw["entity"]["credentials"].as_array_mut() {
            for c in credentials {
                if let Some(file) = c["kagitabaFile"]["blobId"]
                    .as_str()
                    .and_then(|id| replacements.get(id))
                {
                    c["kagitabaFile"]["blobId"] = file.blob_id.clone().into();
                    c["kagitabaFile"]["key"] = BASE64URL_NOPAD.encode(file.key.as_ref()).into();
                }
            }
        }
        Ok(())
    })?;
    Ok((next, next_blobs))
}
/// Ordinary item editing must preserve complete owned descriptors. Dedicated
/// add/remove/rekey operations are the only route to changing file ownership.
pub fn validate_edit(old: &Payload, new: &Payload) -> Result<()> {
    if old.entry_id() != new.entry_id() {
        return Err(Error::WrongEntry);
    }
    list(old)?;
    list(new)?;
    let owned = |p: &Payload| -> BTreeMap<String, Value> {
        p.entity()["credentials"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c.get("kagitabaFile").is_some())
            .map(|c| (c["id"].as_str().unwrap_or("").to_owned(), c.clone()))
            .collect()
    };
    let old = crate::json::SecretJson(Value::Object(owned(old).into_iter().collect()));
    let new = crate::json::SecretJson(Value::Object(owned(new).into_iter().collect()));
    if old.0 != new.0 {
        return invalid();
    }
    Ok(())
}

/// Largest supported single KAF1 encrypted attachment container.
pub const MAX_BLOB_BYTES: usize = 8 + MAX_CHUNKS * (4 + CHUNK_BYTES + 76);
/// Encode authenticated chunks as one owner-local attachment file.
pub fn encode_blob(chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    validate_chunks(chunks)?;
    let mut bytes = b"KAF1".to_vec();
    bytes.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
    for chunk in chunks {
        bytes.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}
/// Parse one bounded KAF1 file. This checks structure, not authentication.
pub fn decode_blob(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if bytes.len() < 8 || bytes.len() > MAX_BLOB_BYTES || &bytes[..4] != b"KAF1" {
        return invalid();
    }
    let count =
        u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::InvalidDocument)?) as usize;
    if !(1..=MAX_CHUNKS).contains(&count) {
        return invalid();
    }
    let mut rest = &bytes[8..];
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let length = u32::from_be_bytes(
            rest.get(..4)
                .ok_or(Error::InvalidDocument)?
                .try_into()
                .map_err(|_| Error::InvalidDocument)?,
        ) as usize;
        rest = &rest[4..];
        if !(76..=CHUNK_BYTES + 76).contains(&length) {
            return invalid();
        }
        chunks.push(rest.get(..length).ok_or(Error::InvalidDocument)?.to_vec());
        rest = &rest[length..];
    }
    if !rest.is_empty() {
        return invalid();
    }
    validate_chunks(&chunks)?;
    Ok(chunks)
}
/// Validate ciphertext chunk lengths and headers without copying their bytes.
pub fn validate_chunks(chunks: &[Vec<u8>]) -> Result<()> {
    if !(1..=MAX_CHUNKS).contains(&chunks.len()) {
        return invalid();
    }
    for (position, chunk) in chunks.iter().enumerate() {
        if !(76..=CHUNK_BYTES + 76).contains(&chunk.len())
            || (position + 1 < chunks.len() && chunk.len() != CHUNK_BYTES + 76)
            || (chunks.len() > 1 && chunk.len() == 76)
        {
            return invalid();
        }
        if !chunk.starts_with(b"KTC1") {
            return invalid();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;
    fn payload() -> Payload {
        let id = EntryId::from_bytes([1; 16]);
        Payload::new(id,PayloadKind::Item,&serde_json::to_vec(&json!({"id":BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Example","credentials":[],"vendor":{"keep":true}})).unwrap()).unwrap()
    }
    #[test]
    fn rename_changes_only_name_and_original_ciphertext_still_decrypts() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([33;32]);
        let (with, blobs) = add(&payload(), "old.txt", b"unchanged file", &mut rng).unwrap();
        let with = with.edited(|v| {
            v["entity"]["credentials"][0]["vendor"] = json!({"keep":true});
            Ok(())
        }).unwrap();
        let id = list(&with).unwrap()[0].id;
        let renamed = rename(&with, id, "new.txt").unwrap();
        let mut expected = with.entity().clone();
        expected["credentials"][0]["name"] = json!("new.txt");
        assert_eq!(renamed.entity(), &expected);
        validate_blobs(&renamed, &blobs).unwrap();
        let file = list(&renamed).unwrap().remove(0);
        assert_eq!(&*decrypt(renamed.entry_id(), &file, &blobs[&file.blob_id]).unwrap(), b"unchanged file");
        for name in ["", "../bad", "a/b", " leading", "trailing ", "bad\nname"] {
            assert!(rename(&with, id, name).is_err());
        }
        assert!(rename(&with, EntryId::from_bytes([9;16]), "missing.txt").is_err());
    }
    #[test]
    fn roundtrip_empty_multichunk_rekey_and_ownership() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([19; 32]);
        for bytes in [vec![], vec![42; CHUNK_BYTES + 37]] {
            let original = payload();
            let (with, blobs) = add(&original, "document.bin", &bytes, &mut rng).unwrap();
            let files = list(&with).unwrap();
            let file = &files[0];
            validate_blobs(&with, &blobs).unwrap();
            let encoded = encode_blob(&blobs[&file.blob_id]).unwrap();
            let chunks = decode_blob(&encoded).unwrap();
            assert_eq!(&*decrypt(with.entry_id(), file, &chunks).unwrap(), &bytes);
            assert!(decrypt(EntryId::from_bytes([2; 16]), file, &chunks).is_err());
            assert!(validate_edit(&original, &with).is_err());
            let edited = with
                .edited(|v| {
                    v["entity"]["title"] = "Changed".into();
                    v["entity"]["credentials"][0]["vendor"] = json!({"preserve":true});
                    Ok(())
                })
                .unwrap();
            let title_only = with
                .edited(|v| {
                    v["entity"]["title"] = "Changed".into();
                    Ok(())
                })
                .unwrap();
            validate_edit(&with, &title_only).unwrap();
            let (rotated, new_blobs) = rekey(&edited, &blobs, &mut rng).unwrap();
            let new_files = list(&rotated).unwrap();
            let new_file = &new_files[0];
            assert_eq!(new_file.id, file.id);
            assert_ne!(new_file.blob_id, file.blob_id);
            assert_eq!(
                rotated.entity()["credentials"][0]["vendor"],
                json!({"preserve":true})
            );
            assert_eq!(
                &*decrypt(rotated.entry_id(), new_file, &new_blobs[&new_file.blob_id]).unwrap(),
                &bytes
            );
            assert!(decrypt(rotated.entry_id(), file, &new_blobs[&new_file.blob_id]).is_err());
            assert!(validate_edit(&with, &rotated).is_err());
            let (removed, blob) = remove(&with, file.id).unwrap();
            assert_eq!(blob, file.blob_id);
            assert!(list(&removed).unwrap().is_empty());
            assert_eq!(removed.entity()["vendor"], original.entity()["vendor"]);
        }
    }
    #[test]
    fn reject_tampering_missing_reordered_and_crossfile_chunks() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([20; 32]);
        let bytes = vec![3; CHUNK_BYTES * 2];
        let (p, blobs) = add(&payload(), "file", &bytes, &mut rng).unwrap();
        let files = list(&p).unwrap();
        let file = &files[0];
        let chunks = &blobs[&file.blob_id];
        let mut bad = chunks.clone();
        bad[0][99] ^= 1;
        assert!(decrypt(p.entry_id(), file, &bad).is_err());
        assert!(decrypt(p.entry_id(), file, &chunks[..1]).is_err());
        let mut bad = chunks.clone();
        bad.swap(0, 1);
        assert!(decrypt(p.entry_id(), file, &bad).is_err());
        let (other, other_blobs) = add(&payload(), "another", &bytes, &mut rng).unwrap();
        let other_files = list(&other).unwrap();
        assert!(decrypt(p.entry_id(), file, &other_blobs[&other_files[0].blob_id]).is_err());
        let hash_bad = p
            .edited(|v| {
                v["entity"]["credentials"][0]["integrityHash"] =
                    BASE64URL_NOPAD.encode(&[0; 32]).into();
                Ok(())
            })
            .unwrap();
        assert!(decrypt(p.entry_id(), &list(&hash_bad).unwrap()[0], chunks).is_err());
        let mut encoded = encode_blob(chunks).unwrap();
        encoded.push(0);
        assert!(decode_blob(&encoded).is_err());
        encoded.pop();
        encoded[7] = 65;
        assert!(decode_blob(&encoded).is_err());
        assert!(decode_blob(b"KAF1\0\0\0\0").is_err());
        assert!(encode_blob(&[vec![0; 76]]).is_err());
        assert!(validate_blobs(&p, &Blobs::new()).is_err());
    }
    #[test]
    fn reject_forged_descriptors_duplicate_ids_and_unsafe_names() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([21; 32]);
        for name in [
            "",
            "../file",
            "foo/bar",
            "foo\\bar",
            "file\n",
            "\u{202e}file",
            " file",
            "..",
        ] {
            assert!(add(&payload(), name, b"x", &mut rng).is_err());
        }
        let (p, _) = add(&payload(), "fine.txt", b"x", &mut rng).unwrap();
        for (member, value) in [
            ("chunkCount", json!(2)),
            ("version", json!(2)),
            ("blobId", json!("../path")),
            ("key", json!("not-a-key")),
        ] {
            let changed = p
                .edited(|v| {
                    v["entity"]["credentials"][0]["kagitabaFile"][member] = value;
                    Ok(())
                })
                .unwrap();
            assert!(list(&changed).is_err());
            assert!(validate_edit(&p, &changed).is_err());
        }
        let duplicated = p
            .edited(|v| {
                let c = v["entity"]["credentials"][0].clone();
                v["entity"]["credentials"].as_array_mut().unwrap().push(c);
                Ok(())
            })
            .unwrap();
        assert!(list(&duplicated).is_err());
        let external=payload().edited(|v|{v["entity"]["credentials"].as_array_mut().unwrap().push(json!({"type":"file","id":"Aw","name":"external","decryptedSize":3,"integrityHash":BASE64URL_NOPAD.encode(&[0;32])}));Ok(())}).unwrap();
        assert!(list(&external).unwrap().is_empty());
    }
    #[test]
    fn descriptor_and_container_bounds_fail_before_allocating_file_plaintext() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([22; 32]);
        let (p, blobs) = add(&payload(), "file", b"x", &mut rng).unwrap();
        let file = &list(&p).unwrap()[0];
        let oversized = p
            .edited(|v| {
                v["entity"]["credentials"][0]["decryptedSize"] = json!(MAX_FILE_BYTES + 1);
                Ok(())
            })
            .unwrap();
        assert!(list(&oversized).is_err());
        let aliased=p.edited(|v|{v["entity"]["credentials"].as_array_mut().unwrap().push(json!({"type":"file","id":data_encoding::BASE64URL.encode(file.id.as_bytes()),"name":"external","decryptedSize":1,"integrityHash":BASE64URL_NOPAD.encode(&[0;32])}));Ok(())}).unwrap();
        assert!(list(&aliased).is_err());
        let chunk = blobs[&file.blob_id][0].clone();
        assert!(encode_blob(&[chunk.clone(), chunk.clone()]).is_err()); // short non-last
        assert!(encode_blob(&vec![chunk.clone(); MAX_CHUNKS + 1]).is_err());
        let mut container = encode_blob(&[chunk]).unwrap();
        for cut in [0, 3, 7, 8, 11, container.len() - 1] {
            assert!(decode_blob(&container[..cut]).is_err());
        }
        container[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_blob(&container).is_err());
    }
}

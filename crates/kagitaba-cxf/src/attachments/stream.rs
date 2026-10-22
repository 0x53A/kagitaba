use super::*;
use std::io::{Read, Write};

fn read_exact(reader: &mut (impl Read + ?Sized), bytes: &mut [u8]) -> Result<()> {
    reader.read_exact(bytes).map_err(|_| Error::Read)
}
fn write_all(writer: &mut (impl Write + ?Sized), bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes).map_err(|_| Error::Write)
}
fn eof(reader: &mut (impl Read + ?Sized)) -> Result<()> {
    let mut extra = Zeroizing::new([0; 1]);
    loop {
        match reader.read(extra.as_mut()) {
            Ok(0) => return Ok(()),
            Ok(_) => return invalid(),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Read),
        }
    }
}
fn header(writer: &mut (impl Write + ?Sized), count: u32) -> Result<()> {
    write_all(writer, b"KAF1")?;
    write_all(writer, &count.to_be_bytes())
}
fn write_chunk(writer: &mut (impl Write + ?Sized), chunk: &Ciphertext) -> Result<()> {
    write_all(writer, &(chunk.as_bytes().len() as u32).to_be_bytes())?;
    write_all(writer, chunk.as_bytes())
}
fn shape(file: &Attachment) -> Result<()> {
    if file.size > MAX_FILE_BYTES as u64
        || !is_blob_id(&file.blob_id)
        || file.chunk_count != (file.size as usize).div_ceil(CHUNK_BYTES).max(1) as u32
    {
        return invalid();
    }
    Ok(())
}
/// Exact KAF1 byte length for a validated descriptor, without reading ciphertext.
/// This is structural metadata validation, not authentication.
pub fn expected_blob_size(file: &Attachment) -> Result<u64> {
    shape(file)?;
    Ok(8 + file.size + u64::from(file.chunk_count) * 80)
}
/// Encrypt a known-length input into one KAF1 stream with O(chunk) memory.
/// The sink is staging: discard it on any error. The returned descriptor is
/// finalized only after exact source length/EOF and plaintext hash are checked.
/// This function does not flush, sync, close, or publish the caller's sink.
pub fn add_stream(
    payload: &Payload,
    name: &str,
    size: u64,
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<Payload> {
    if payload.kind() != PayloadKind::Item || !valid_name(name) {
        return invalid();
    }
    if size > MAX_FILE_BYTES as u64 {
        return Err(Error::SizeLimit);
    }
    let existing = list(payload)?;
    if existing.len() >= MAX_ATTACHMENTS {
        return Err(Error::SizeLimit);
    }
    let key = ContentKey::generate(rng)?;
    let mut file = Attachment {
        id: EntryId::generate(rng)?,
        name: name.to_owned(),
        size,
        blob_id: HEXLOWER.encode(&fresh(rng)?),
        chunk_count: (size as usize).div_ceil(CHUNK_BYTES).max(1) as u32,
        hash: [0; 32],
        key: Zeroizing::new(*key.as_bytes()),
    };
    if existing
        .iter()
        .any(|old| old.id == file.id || old.blob_id == file.blob_id)
    {
        return Err(Error::DuplicateId);
    }
    header(writer, file.chunk_count)?;
    let mut hash = Sha256::new();
    let mut clear = Zeroizing::new(vec![0; CHUNK_BYTES.min(size as usize)]);
    for position in 0..file.chunk_count {
        let length = (size as usize - position as usize * CHUNK_BYTES).min(CHUNK_BYTES);
        read_exact(reader, &mut clear[..length])?;
        hash.update(&clear[..length]);
        let chunk = Ciphertext::seal(
            &clear[..length],
            &key,
            &context(payload.entry_id(), &file, position),
            rng,
        )?;
        write_chunk(writer, &chunk)?;
    }
    eof(reader)?;
    file.hash = hash.finalize().into();
    let next = payload.edited(|raw| {
        raw["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error::InvalidDocument)?
            .push(credential(&file));
        Ok(())
    })?;
    list(&next)?;
    Ok(next)
}
fn clear_chunks(
    owner: EntryId,
    file: &Attachment,
    reader: &mut (impl Read + ?Sized),
    mut use_chunk: impl FnMut(u32, &[u8]) -> Result<()>,
) -> Result<()> {
    shape(file)?;
    let mut head = [0; 8];
    read_exact(reader, &mut head)?;
    if &head[..4] != b"KAF1" || head[4..] != file.chunk_count.to_be_bytes() {
        return invalid();
    }
    let key = ContentKey::from_bytes(*file.key);
    let mut hash = Sha256::new();
    let mut encrypted = Vec::with_capacity(CHUNK_BYTES + 76);
    for position in 0..file.chunk_count {
        let expected = (file.size as usize - position as usize * CHUNK_BYTES).min(CHUNK_BYTES);
        let mut length = [0; 4];
        read_exact(reader, &mut length)?;
        if u32::from_be_bytes(length) as usize != expected + 76 {
            return invalid();
        }
        encrypted.resize(expected + 76, 0);
        read_exact(reader, &mut encrypted)?;
        let clear =
            Ciphertext::from_bytes(&encrypted)?.open(&key, &context(owner, file, position))?;
        if clear.as_bytes().len() != expected {
            return invalid();
        }
        hash.update(clear.as_bytes());
        use_chunk(position, clear.as_bytes())?;
    }
    eof(reader)?;
    if hash.finalize().as_slice() != file.hash {
        return invalid();
    }
    Ok(())
}
/// Decrypt/authenticate a KAF1 source into caller-owned staging with O(chunk) memory.
/// Authenticated chunks are written before the final hash/EOF check. Therefore
/// NEVER use a final/public destination as the writer: discard staging on every
/// error, and publish only after success. The function does not flush or sync.
pub fn decrypt_stream(
    owner: EntryId,
    file: &Attachment,
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
) -> Result<()> {
    clear_chunks(owner, file, reader, |_, bytes| write_all(writer, bytes))
}
/// Rotate one owned attachment while streaming ciphertext source to staging.
/// Unknown descriptor fields and the attachment ID are preserved. The returned
/// payload changes only this file's key/blob ID. Discard output on any error;
/// callers rotating multiple files must publish the whole set atomically.
pub fn rekey_stream(
    payload: &Payload,
    id: EntryId,
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<Payload> {
    copy_stream(payload.entry_id(), payload, id, reader, writer, rng)
}

/// Re-encrypt one attachment from its old owner to the supplied target payload.
/// The target initially retains the source descriptor; unknown fields and file
/// identity are preserved. All source chunks and the plaintext hash authenticate
/// before success. Output is encrypted staging and must be discarded on failure.
/// Calling this once per file after `Payload::with_entry_id` copies files with
/// bounded chunk memory and fresh keys/blob IDs, without plaintext disk staging.
pub fn copy_stream(
    source_owner: EntryId,
    payload: &Payload,
    id: EntryId,
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<Payload> {
    let files = list(payload)?;
    let old = files
        .iter()
        .find(|f| f.id == id)
        .ok_or(Error::InvalidDocument)?;
    let key = ContentKey::generate(rng)?;
    let file = Attachment {
        id: old.id,
        name: old.name.clone(),
        size: old.size,
        blob_id: HEXLOWER.encode(&fresh(rng)?),
        chunk_count: old.chunk_count,
        hash: old.hash,
        key: Zeroizing::new(*key.as_bytes()),
    };
    if files.iter().any(|f| f.blob_id == file.blob_id) {
        return Err(Error::DuplicateId);
    }
    header(writer, file.chunk_count)?;
    clear_chunks(source_owner, old, reader, |position, clear| {
        let chunk = Ciphertext::seal(
            clear,
            &key,
            &context(payload.entry_id(), &file, position),
            rng,
        )?;
        write_chunk(writer, &chunk)
    })?;
    payload.edited(|raw| {
        for credential in raw["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error::InvalidDocument)?
        {
            if credential["kagitabaFile"]["blobId"].as_str() == Some(&old.blob_id) {
                credential["kagitabaFile"]["blobId"] = file.blob_id.clone().into();
                credential["kagitabaFile"]["key"] =
                    BASE64URL_NOPAD.encode(file.key.as_ref()).into();
            }
        }
        Ok(())
    })
}

/// Validate a complete bounded KAF1 stream without retaining its ciphertext.
/// Returns its encoded length. This checks structure and EOF, not authentication.
pub fn validate_blob_stream(reader: &mut (impl Read + ?Sized)) -> Result<u64> {
    let mut head = [0; 8];
    read_exact(reader, &mut head)?;
    let count =
        u32::from_be_bytes(head[4..].try_into().map_err(|_| Error::InvalidDocument)?) as usize;
    if &head[..4] != b"KAF1" || !(1..=MAX_CHUNKS).contains(&count) {
        return invalid();
    }
    let mut total = 8u64;
    let mut scratch = [0u8; 64 * 1024];
    for position in 0..count {
        let mut length = [0; 4];
        read_exact(reader, &mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(76..=CHUNK_BYTES + 76).contains(&length)
            || (position + 1 < count && length != CHUNK_BYTES + 76)
            || (count > 1 && length == 76)
        {
            return invalid();
        }
        let mut magic = [0; 4];
        read_exact(reader, &mut magic)?;
        if &magic != b"KTC1" {
            return invalid();
        }
        let mut remaining = length - 4;
        while remaining > 0 {
            let take = remaining.min(scratch.len());
            read_exact(reader, &mut scratch[..take])?;
            remaining -= take;
        }
        total += 4 + length as u64;
    }
    eof(reader)?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;
    use std::io::{self, Cursor};
    struct Fragmented<R> {
        inner: R,
        calls: usize,
    }
    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(7) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let length = out.len().min(97);
            self.inner.read(&mut out[..length])
        }
    }
    fn payload() -> Payload {
        let id = EntryId::from_bytes([5; 16]);
        Payload::new(id,PayloadKind::Item,&serde_json::to_vec(&json!({"id":BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Streaming","credentials":[]})).unwrap()).unwrap()
    }
    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([34; 32])
    }
    #[test]
    fn copying_binds_new_owner_preserves_metadata_and_authenticates_source() {
        let bytes = vec![71; CHUNK_BYTES + 19];
        let (source, blobs) = add(&payload(), "copy.bin", &bytes, &mut rng()).unwrap();
        let source = source
            .edited(|raw| {
                raw["entity"]["credentials"][0]["future"] = json!({"keep":true});
                raw["source"] = json!({"vendor":"synthetic"});
                Ok(())
            })
            .unwrap();
        let file = list(&source).unwrap().pop().unwrap();
        let encrypted = encode_blob(&blobs[&file.blob_id]).unwrap();
        let target = source.with_entry_id(EntryId::from_bytes([8; 16])).unwrap();
        let mut copied_bytes = Vec::new();
        let copied = copy_stream(
            source.entry_id(),
            &target,
            file.id,
            &mut Cursor::new(&encrypted),
            &mut copied_bytes,
            &mut rand_chacha::ChaCha20Rng::from_seed([55; 32]),
        )
        .unwrap();
        assert_eq!(copied.source(), source.source());
        assert_eq!(
            copied.entity()["credentials"][0]["future"],
            source.entity()["credentials"][0]["future"]
        );
        let copied_file = list(&copied).unwrap().pop().unwrap();
        assert_eq!(copied_file.id, file.id);
        assert_ne!(copied_file.blob_id, file.blob_id);
        let mut clear = Zeroizing::new(Vec::new());
        decrypt_stream(
            copied.entry_id(),
            &copied_file,
            &mut Cursor::new(&copied_bytes),
            &mut *clear,
        )
        .unwrap();
        assert_eq!(clear.as_slice(), bytes);
        assert!(
            decrypt_stream(
                source.entry_id(),
                &copied_file,
                &mut Cursor::new(&copied_bytes),
                &mut std::io::sink()
            )
            .is_err()
        );
        let mut corrupt = encrypted;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            copy_stream(
                source.entry_id(),
                &target,
                file.id,
                &mut Cursor::new(corrupt),
                &mut Vec::new(),
                &mut rng()
            )
            .is_err()
        );
    }
    #[test]
    fn streamed_empty_and_multichunk_match_buffered_wire_with_short_reads() {
        for bytes in [vec![], vec![53; CHUNK_BYTES + 29]] {
            let original = payload();
            let mut encrypted = Vec::new();
            let mut source = Fragmented {
                inner: Cursor::new(&bytes),
                calls: 0,
            };
            let streamed = add_stream(
                &original,
                "example.bin",
                bytes.len() as u64,
                &mut source,
                &mut encrypted,
                &mut rng(),
            )
            .unwrap();
            let files = list(&streamed).unwrap();
            let file = &files[0];
            let (buffered, blobs) = add(&original, "example.bin", &bytes, &mut rng()).unwrap();
            assert_eq!(&*streamed.to_json().unwrap(), &*buffered.to_json().unwrap());
            assert_eq!(encrypted, encode_blob(&blobs[&file.blob_id]).unwrap());
            assert_eq!(expected_blob_size(file).unwrap(), encrypted.len() as u64);
            assert_eq!(
                validate_blob_stream(&mut Fragmented {
                    inner: Cursor::new(&encrypted),
                    calls: 0
                })
                .unwrap(),
                encrypted.len() as u64
            );
            let mut decrypted = Zeroizing::new(Vec::new());
            decrypt_stream(
                streamed.entry_id(),
                file,
                &mut Fragmented {
                    inner: Cursor::new(&encrypted),
                    calls: 0,
                },
                &mut *decrypted,
            )
            .unwrap();
            assert_eq!(&*decrypted, &bytes);
            let annotated = streamed
                .edited(|v| {
                    v["entity"]["credentials"][0]["extra"] = json!({"kept":true});
                    Ok(())
                })
                .unwrap();
            let mut rotated = Vec::new();
            let next = rekey_stream(
                &annotated,
                file.id,
                &mut Cursor::new(&encrypted),
                &mut rotated,
                &mut rand_chacha::ChaCha20Rng::from_seed([35; 32]),
            )
            .unwrap();
            let next_file = &list(&next).unwrap()[0];
            assert_ne!(next_file.blob_id, file.blob_id);
            assert_eq!(next_file.id, file.id);
            assert_eq!(
                next.entity()["credentials"][0]["extra"],
                json!({"kept":true})
            );
            let mut clear = Zeroizing::new(Vec::new());
            decrypt_stream(
                next.entry_id(),
                next_file,
                &mut Cursor::new(&rotated),
                &mut *clear,
            )
            .unwrap();
            assert_eq!(&*clear, &bytes);
            let mut retained_key = list(&streamed).unwrap().remove(0);
            retained_key.blob_id = next_file.blob_id.clone();
            assert!(
                decrypt_stream(
                    next.entry_id(),
                    &retained_key,
                    &mut Cursor::new(&rotated),
                    &mut io::sink()
                )
                .is_err()
            );
            assert!(
                decrypt_stream(
                    next.entry_id(),
                    file,
                    &mut Cursor::new(&rotated),
                    &mut io::sink()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn final_hash_eof_and_late_chunk_failures_require_discarding_staging() {
        let mut encrypted = Vec::new();
        let bytes = vec![7; CHUNK_BYTES + 9];
        let p = add_stream(
            &payload(),
            "file",
            bytes.len() as u64,
            &mut Cursor::new(&bytes),
            &mut encrypted,
            &mut rng(),
        )
        .unwrap();
        let files = list(&p).unwrap();
        let file = &files[0];
        let wrong_hash = p
            .edited(|v| {
                v["entity"]["credentials"][0]["integrityHash"] =
                    BASE64URL_NOPAD.encode(&[0; 32]).into();
                Ok(())
            })
            .unwrap();
        let mut staging = Zeroizing::new(Vec::new());
        assert!(
            decrypt_stream(
                p.entry_id(),
                &list(&wrong_hash).unwrap()[0],
                &mut Cursor::new(&encrypted),
                &mut *staging
            )
            .is_err()
        );
        assert_eq!(&*staging, &bytes); // Authenticated bytes are still NOT published on late failure.
        let mut output = Vec::new();
        assert!(
            rekey_stream(
                &wrong_hash,
                file.id,
                &mut Cursor::new(&encrypted),
                &mut output,
                &mut rng()
            )
            .is_err()
        );
        assert!(!output.is_empty());
        let mut trailing = encrypted.clone();
        trailing.push(0);
        assert!(
            decrypt_stream(
                p.entry_id(),
                file,
                &mut Cursor::new(&trailing),
                &mut io::sink()
            )
            .is_err()
        );
        assert!(validate_blob_stream(&mut Cursor::new(&trailing)).is_err());
        for cut in [0, 7, 11, encrypted.len() - 1] {
            assert!(
                decrypt_stream(
                    p.entry_id(),
                    file,
                    &mut Cursor::new(&encrypted[..cut]),
                    &mut io::sink()
                )
                .is_err()
            );
            assert!(validate_blob_stream(&mut Cursor::new(&encrypted[..cut])).is_err());
        }
        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        staging.clear();
        assert!(
            decrypt_stream(
                p.entry_id(),
                file,
                &mut Cursor::new(&tampered),
                &mut *staging
            )
            .is_err()
        );
        assert_eq!(staging.len(), CHUNK_BYTES);
        assert!(
            decrypt_stream(
                EntryId::from_bytes([6; 16]),
                file,
                &mut Cursor::new(&encrypted),
                &mut io::sink()
            )
            .is_err()
        );
    }
    #[test]
    fn source_length_and_sink_failures_are_explicit() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(matches!(
            add_stream(
                &payload(),
                "file",
                1,
                &mut Cursor::new(b"a"),
                &mut Broken,
                &mut rng()
            ),
            Err(Error::Write)
        ));
        for size in [0, 2] {
            assert!(
                add_stream(
                    &payload(),
                    "file",
                    size,
                    &mut Cursor::new(b"a"),
                    &mut io::sink(),
                    &mut rng()
                )
                .is_err()
            );
        }
        assert!(matches!(
            add_stream(
                &payload(),
                "file",
                MAX_FILE_BYTES as u64 + 1,
                &mut io::empty(),
                &mut io::sink(),
                &mut rng()
            ),
            Err(Error::SizeLimit)
        ));
    }
}

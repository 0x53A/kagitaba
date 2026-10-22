//! Bounded-memory Git blob access. Packed deltas use encrypted temporary files.
use crate::{Error, ObjectId, Result};
use flate2::read::ZlibDecoder;
use gix::objs::Write as _;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::NamedTempFile;

const LIMIT: u64 = 256 * 1024 * 1024;
const BUDGET: u64 = 2 * 1024 * 1024 * 1024;
// Independently bound object/alternate/index traversal, even when no payload
// bytes are materialized (cycles or missing objects consume no disk budget).
struct Lookup {
    remaining: usize,
    seen: BTreeSet<(PathBuf, ObjectId)>,
}
impl Lookup {
    fn new() -> Self {
        Self {
            remaining: 4096,
            seen: BTreeSet::new(),
        }
    }
    fn step(&mut self) -> Result<()> {
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct AttachmentBlob {
    oid: ObjectId,
    size: usize,
    source: Source,
}
#[derive(Clone)]
enum Source {
    Git(PathBuf),
    Staged(Arc<NamedTempFile>),
}
impl std::fmt::Debug for AttachmentBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentBlob")
            .field("oid", &self.oid)
            .field("size", &self.size)
            .finish()
    }
}
impl PartialEq for AttachmentBlob {
    fn eq(&self, other: &Self) -> bool {
        self.oid == other.oid && self.size == other.size
    }
}
impl Eq for AttachmentBlob {}
impl AttachmentBlob {
    pub fn len(&self) -> usize {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    pub fn oid(&self) -> ObjectId {
        self.oid
    }
    pub fn from_git(repo: &gix::Repository, oid: ObjectId, size: usize) -> Self {
        Self {
            oid,
            size,
            source: Source::Git(repo.common_dir().join("objects")),
        }
    }
    pub fn from_staged(mut file: NamedTempFile) -> Result<Self> {
        file.as_file_mut().rewind().map_err(|_| Error::Io)?;
        let size = kagitaba_cxf::attachments::validate_blob_stream(file.as_file_mut())
            .map_err(|_| Error::Invalid)? as usize;
        let oid = hash_file(file.as_file_mut(), size)?;
        Ok(Self {
            oid,
            size,
            source: Source::Staged(Arc::new(file)),
        })
    }
    pub fn from_chunks(chunks: &[Vec<u8>]) -> Result<Self> {
        let mut file = NamedTempFile::new().map_err(|_| Error::Io)?;
        file.write_all(b"KAF1")
            .and_then(|_| file.write_all(&(chunks.len() as u32).to_be_bytes()))
            .map_err(|_| Error::Io)?;
        for chunk in chunks {
            file.write_all(&(chunk.len() as u32).to_be_bytes())
                .and_then(|_| file.write_all(chunk))
                .map_err(|_| Error::Io)?;
        }
        Self::from_staged(file)
    }
    pub fn open(&self) -> Result<Box<dyn Read>> {
        match &self.source {
            Source::Staged(file) => Ok(Box::new(file.reopen().map_err(|_| Error::Io)?)),
            Source::Git(objects) => {
                let mut budget = BUDGET;
                let mut file = load(objects, self.oid, 0, &mut budget, &mut Lookup::new())?;
                if hash_file(file.as_file_mut(), self.size)? != self.oid {
                    return Err(Error::Invalid);
                }
                file.as_file_mut().rewind().map_err(|_| Error::Io)?;
                Ok(Box::new(TempReader(file)))
            }
        }
    }
    pub fn write_into(&self, repo: &gix::Repository) -> Result<ObjectId> {
        // Existing accepted objects in this repository are already addressed by
        // their verified tree. Don't re-read whole attachments for title/cache edits.
        if let Source::Git(objects) = &self.source
            && *objects == repo.common_dir().join("objects")
        {
            let header = repo.find_header(self.oid).map_err(|_| Error::Invalid)?;
            if header.kind() != gix::objs::Kind::Blob || header.size() != self.size as u64 {
                return Err(Error::Invalid);
            }
            return Ok(self.oid);
        }
        let mut reader = self.open()?;
        let oid = repo
            .objects
            .write_stream(gix::objs::Kind::Blob, self.size as u64, &mut reader)
            .map_err(|_| Error::Io)?;
        if oid != self.oid {
            return Err(Error::Invalid);
        }
        Ok(oid)
    }
}
struct TempReader(NamedTempFile);
impl Read for TempReader {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
fn hash_file(file: &mut File, size: usize) -> Result<ObjectId> {
    if size as u64 > LIMIT || file.metadata().map_err(|_| Error::Io)?.len() != size as u64 {
        return Err(Error::Invalid);
    }
    file.rewind().map_err(|_| Error::Io)?;
    let mut hash = gix::hash::hasher(gix::hash::Kind::Sha1);
    hash.update(format!("blob {size}\0").as_bytes());
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|_| Error::Io)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    hash.try_finalize().map_err(|_| Error::Invalid)
}
fn byte(reader: &mut impl Read) -> Result<u8> {
    let mut b = [0];
    reader.read_exact(&mut b).map_err(|_| Error::Invalid)?;
    Ok(b[0])
}
fn u32_at(file: &mut File, at: u64) -> Result<u32> {
    file.seek(SeekFrom::Start(at)).map_err(|_| Error::Io)?;
    let mut b = [0; 4];
    file.read_exact(&mut b).map_err(|_| Error::Invalid)?;
    Ok(u32::from_be_bytes(b))
}
fn index_offset(path: &Path, oid: ObjectId) -> Result<Option<u64>> {
    let mut file = File::open(path).map_err(|_| Error::Io)?;
    let v2 = u32_at(&mut file, 0)? == 0xff744f63;
    let start = if v2 {
        if u32_at(&mut file, 4)? != 2 {
            return Err(Error::Invalid);
        }
        8
    } else {
        0
    };
    let first = oid.as_bytes()[0] as u64;
    let count = u32_at(&mut file, start + 255 * 4)? as u64;
    let mut low = if first == 0 {
        0
    } else {
        u32_at(&mut file, start + (first - 1) * 4)? as u64
    };
    let mut high = u32_at(&mut file, start + first * 4)? as u64;
    if low > high || high > count {
        return Err(Error::Invalid);
    }
    while low < high {
        let mid = low + (high - low) / 2;
        let pos = start + 1024 + if v2 { mid * 20 } else { mid * 24 + 4 };
        file.seek(SeekFrom::Start(pos)).map_err(|_| Error::Io)?;
        let mut id = [0; 20];
        file.read_exact(&mut id).map_err(|_| Error::Invalid)?;
        match id.as_slice().cmp(oid.as_bytes()) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => {
                let offset = u32_at(
                    &mut file,
                    if v2 {
                        start + 1024 + count * 24 + mid * 4
                    } else {
                        start + 1024 + mid * 24
                    },
                )?;
                if !v2 || offset & 0x80000000 == 0 {
                    return Ok(Some(offset as u64));
                }
                file.seek(SeekFrom::Start(
                    start + 1024 + count * 28 + (offset as u64 & 0x7fffffff) * 8,
                ))
                .map_err(|_| Error::Io)?;
                let mut b = [0; 8];
                file.read_exact(&mut b).map_err(|_| Error::Invalid)?;
                return Ok(Some(u64::from_be_bytes(b)));
            }
        }
    }
    Ok(None)
}
fn load(
    objects: &Path,
    oid: ObjectId,
    depth: usize,
    budget: &mut u64,
    lookup: &mut Lookup,
) -> Result<NamedTempFile> {
    lookup.step()?;
    let canonical = std::fs::canonicalize(objects).map_err(|_| Error::Io)?;
    if !lookup.seen.insert((canonical, oid)) {
        return Err(Error::Invalid);
    }
    if depth > 64 {
        return Err(Error::Invalid);
    }
    let hex = oid.to_string();
    let loose = objects.join(&hex[..2]).join(&hex[2..]);
    if let Ok(file) = File::open(loose) {
        let mut decoder = ZlibDecoder::new(file);
        let mut header = Vec::new();
        loop {
            let b = byte(&mut decoder)?;
            if b == 0 {
                break;
            }
            if header.len() >= 64 {
                return Err(Error::Invalid);
            }
            header.push(b);
        }
        let header = std::str::from_utf8(&header).map_err(|_| Error::Invalid)?;
        let size = header
            .strip_prefix("blob ")
            .ok_or(Error::Invalid)?
            .parse::<u64>()
            .map_err(|_| Error::Invalid)?;
        return materialize(&mut decoder, size, budget);
    }
    if let Ok(entries) = std::fs::read_dir(objects.join("pack")) {
        for entry in entries {
            let path = entry.map_err(|_| Error::Io)?.path();
            lookup.step()?;
            if path.extension().is_some_and(|x| x == "idx")
                && let Some(offset) = index_offset(&path, oid)?
            {
                return packed(
                    objects,
                    &path.with_extension("pack"),
                    offset,
                    depth,
                    budget,
                    lookup,
                );
            }
        }
    }
    // Alternates are bounded and resolved relative to the containing object directory.
    if let Ok(file) = File::open(objects.join("info/alternates")) {
        let mut text = Vec::new();
        file.take(65537)
            .read_to_end(&mut text)
            .map_err(|_| Error::Io)?;
        if text.len() > 65536 {
            return Err(Error::Invalid);
        }
        let text = std::str::from_utf8(&text).map_err(|_| Error::Invalid)?;
        for line in text.lines().take(64) {
            let path = Path::new(line);
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                objects.join(path)
            };
            if let Ok(file) = load(&path, oid, depth + 1, budget, lookup) {
                return Ok(file);
            }
        }
    }
    Err(Error::Invalid)
}
fn materialize(reader: &mut impl Read, size: u64, budget: &mut u64) -> Result<NamedTempFile> {
    if size > LIMIT || size > *budget {
        return Err(Error::Invalid);
    }
    *budget -= size;
    let mut file = NamedTempFile::new().map_err(|_| Error::Io)?;
    let copied = std::io::copy(&mut reader.take(size), &mut file).map_err(|_| Error::Invalid)?;
    if copied != size || reader.read(&mut [0]).map_err(|_| Error::Invalid)? != 0 {
        return Err(Error::Invalid);
    }
    Ok(file)
}
fn varint(reader: &mut impl Read) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..63).step_by(7) {
        let b = byte(reader)?;
        value |= ((b & 127) as u64) << shift;
        if b & 128 == 0 {
            return Ok(value);
        }
    }
    Err(Error::Invalid)
}
fn packed(
    objects: &Path,
    path: &Path,
    offset: u64,
    depth: usize,
    budget: &mut u64,
    lookup: &mut Lookup,
) -> Result<NamedTempFile> {
    lookup.step()?;
    if depth > 64 || offset < 12 {
        return Err(Error::Invalid);
    }
    let mut file = File::open(path).map_err(|_| Error::Io)?;
    if u32_at(&mut file, 0)? != 0x5041434b || !matches!(u32_at(&mut file, 4)?, 2 | 3) {
        return Err(Error::Invalid);
    }
    file.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
    let first = byte(&mut file)?;
    let kind = (first >> 4) & 7;
    let mut size = (first & 15) as u64;
    let mut b = first;
    let mut shift = 4;
    while b & 128 != 0 {
        if shift > 60 {
            return Err(Error::Invalid);
        }
        b = byte(&mut file)?;
        if shift == 60 && b & 127 > 15 {
            return Err(Error::Invalid);
        }
        size |= ((b & 127) as u64) << shift;
        shift += 7;
    }
    if size > LIMIT {
        return Err(Error::Invalid);
    }
    let mut base = match kind {
        3 => return materialize(&mut ZlibDecoder::new(file), size, budget),
        6 => {
            let mut b = byte(&mut file)?;
            let mut distance = (b & 127) as u64;
            while b & 128 != 0 {
                b = byte(&mut file)?;
                distance = distance
                    .checked_add(1)
                    .and_then(|v| v.checked_mul(128))
                    .and_then(|v| v.checked_add((b & 127) as u64))
                    .ok_or(Error::Invalid)?;
            }
            let base = offset
                .checked_sub(distance)
                .filter(|v| *v < offset)
                .ok_or(Error::Invalid)?;
            packed(objects, path, base, depth + 1, budget, lookup)?
        }
        7 => {
            let mut id = [0; 20];
            file.read_exact(&mut id).map_err(|_| Error::Invalid)?;
            load(objects, ObjectId::Sha1(id), depth + 1, budget, lookup)?
        }
        _ => return Err(Error::Invalid),
    };
    let mut delta = ZlibDecoder::new(file).take(size);
    let base_size = varint(&mut delta)?;
    let result_size = varint(&mut delta)?;
    if base.as_file().metadata().map_err(|_| Error::Io)?.len() != base_size
        || result_size > LIMIT
        || result_size > *budget
    {
        return Err(Error::Invalid);
    }
    *budget -= result_size;
    let mut output = NamedTempFile::new().map_err(|_| Error::Io)?;
    let mut written = 0u64;
    // Heap allocation after base resolution: a stack array in this recursive
    // frame would reserve ~4 MiB at the supported delta-chain depth.
    let mut buf = vec![0; 65536];
    while written < result_size {
        let op = byte(&mut delta)?;
        if op & 128 != 0 {
            let mut at = 0u64;
            let mut length = 0u64;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    at |= (byte(&mut delta)? as u64) << (i * 8);
                }
            }
            for i in 0..3 {
                if op & (1 << (i + 4)) != 0 {
                    length |= (byte(&mut delta)? as u64) << (i * 8);
                }
            }
            if length == 0 {
                length = 65536;
            }
            if at + length > base_size || written + length > result_size {
                return Err(Error::Invalid);
            }
            base.seek(SeekFrom::Start(at)).map_err(|_| Error::Io)?;
            let mut remaining = length;
            while remaining > 0 {
                let n = remaining.min(buf.len() as u64) as usize;
                base.read_exact(&mut buf[..n]).map_err(|_| Error::Invalid)?;
                output.write_all(&buf[..n]).map_err(|_| Error::Io)?;
                remaining -= n as u64;
            }
            written += length;
        } else {
            if op == 0 || written + op as u64 > result_size {
                return Err(Error::Invalid);
            }
            delta
                .read_exact(&mut buf[..op as usize])
                .map_err(|_| Error::Invalid)?;
            output
                .write_all(&buf[..op as usize])
                .map_err(|_| Error::Io)?;
            written += op as u64;
        }
    }
    if delta.limit() != 0 || delta.get_mut().read(&mut [0]).map_err(|_| Error::Invalid)? != 0 {
        return Err(Error::Invalid);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    fn hash(bytes: &[u8]) -> ObjectId {
        let mut h = gix::hash::hasher(gix::hash::Kind::Sha1);
        h.update(format!("blob {}\0", bytes.len()).as_bytes());
        h.update(bytes);
        h.try_finalize().unwrap()
    }
    fn compressed(bytes: &[u8]) -> Vec<u8> {
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(bytes).unwrap();
        z.finish().unwrap()
    }
    fn entry(pack: &mut Vec<u8>, kind: u8, bytes: &[u8], reference: &[u8]) -> u64 {
        let offset = pack.len() as u64;
        let mut size = bytes.len() >> 4;
        pack.push((kind << 4) | (bytes.len() as u8 & 15) | if size > 0 { 128 } else { 0 });
        while size > 0 {
            let b = (size & 127) as u8;
            size >>= 7;
            pack.push(b | if size > 0 { 128 } else { 0 });
        }
        pack.extend_from_slice(reference);
        pack.extend(compressed(bytes));
        offset
    }
    #[test]
    fn loose_and_packed_delta_objects_stream_and_verify() {
        for kind in [3, 6, 7] {
            let dir = tempfile::tempdir().unwrap();
            let repo = gix::init_bare(dir.path()).unwrap();
            let objects = dir.path().join("objects");
            let base = b"base contents";
            let target = b"base contents!";
            let oid = hash(target);
            let mut pack = b"PACK\0\0\0\x02\0\0\0\x02".to_vec();
            let base_offset = entry(&mut pack, 3, base, &[]);
            let delta = [13, 14, 0x90, 13, 1, b'!'];
            let distance = (pack.len() as u64 - base_offset) as u8;
            let offset = match kind {
                3 => entry(&mut pack, 3, target, &[]),
                6 => entry(&mut pack, 6, &delta, &[distance]),
                _ => entry(&mut pack, 7, &delta, hash(base).as_bytes()),
            };
            let mut ids = vec![(hash(base), base_offset), (oid, offset)];
            ids.sort_by_key(|v| v.0);
            let mut index = b"\xfftOc\0\0\0\x02".to_vec();
            for n in 0..256 {
                index.extend_from_slice(
                    &(ids
                        .iter()
                        .filter(|v| v.0.as_bytes()[0] as usize <= n)
                        .count() as u32)
                        .to_be_bytes(),
                );
            }
            for (id, _) in &ids {
                index.extend_from_slice(id.as_bytes());
            }
            index.extend([0; 8]);
            for (_, offset) in ids {
                index.extend_from_slice(&(offset as u32).to_be_bytes());
            }
            index.extend([0; 40]);
            std::fs::create_dir_all(objects.join("pack")).unwrap();
            std::fs::write(objects.join("pack/test.idx"), index).unwrap();
            std::fs::write(objects.join("pack/test.pack"), pack).unwrap();
            let blob = AttachmentBlob::from_git(&repo, oid, target.len());
            let mut result = Vec::new();
            blob.open().unwrap().read_to_end(&mut result).unwrap();
            assert_eq!(result, target);
            assert!(
                AttachmentBlob::from_git(&repo, oid, target.len() + 1)
                    .open()
                    .is_err()
            );
            let dest = tempfile::tempdir().unwrap();
            let dest = gix::init_bare(dest.path()).unwrap();
            assert_eq!(blob.write_into(&dest).unwrap(), oid);
            let mut result = Vec::new();
            AttachmentBlob::from_git(&dest, oid, target.len())
                .open()
                .unwrap()
                .read_to_end(&mut result)
                .unwrap();
            assert_eq!(result, target);
        }
    }
    #[test]
    fn staged_clones_survive_and_invalid_containers_fail() {
        let mut chunk = vec![0; 76];
        chunk[..4].copy_from_slice(b"KTC1");
        let blob = AttachmentBlob::from_chunks(&[chunk]).unwrap();
        let clone = blob.clone();
        drop(blob);
        let mut bytes = Vec::new();
        clone.open().unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 88);
        assert!(AttachmentBlob::from_chunks(&[]).is_err());
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"bad").unwrap();
        assert!(AttachmentBlob::from_staged(file).is_err());
    }
    #[test]
    fn alternate_cycles_and_oversized_configuration_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let objects = dir.path().join("objects");
        std::fs::create_dir_all(objects.join("info")).unwrap();
        std::fs::write(objects.join("info/alternates"), ".\n".repeat(64)).unwrap();
        let mut lookup = Lookup::new();
        assert!(load(&objects, hash(b"absent"), 0, &mut { BUDGET }, &mut lookup).is_err());
        assert!(lookup.remaining > 3900); // Self aliases are rejected immediately, not depth^fanout traversed.
        let file = File::create(objects.join("info/alternates")).unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();
        assert!(
            load(
                &objects,
                hash(b"absent"),
                0,
                &mut { BUDGET },
                &mut Lookup::new()
            )
            .is_err()
        );
    }
    #[test]
    fn overflowing_pack_size_and_deep_delta_chains() {
        let dir = tempfile::tempdir().unwrap();
        let objects = dir.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let path = dir.path().join("test.pack");
        let mut overflow = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        overflow.push(0xb0);
        overflow.extend_from_slice(&[0x80; 8]);
        overflow.push(0x10);
        overflow.extend(compressed(b""));
        std::fs::write(&path, overflow).unwrap();
        assert!(packed(&objects, &path, 12, 0, &mut { BUDGET }, &mut Lookup::new()).is_err());
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x41".to_vec();
        let mut offset = entry(&mut pack, 3, b"x", &[]);
        for _ in 0..64 {
            let distance = pack.len() as u64 - offset;
            assert!(distance < 128);
            offset = entry(&mut pack, 6, &[1, 1, 0x90, 1], &[distance as u8]);
        }
        std::fs::write(&path, pack).unwrap();
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let mut file = packed(
                    &objects,
                    &path,
                    offset,
                    0,
                    &mut { BUDGET },
                    &mut Lookup::new(),
                )
                .unwrap();
                assert_eq!(hash_file(file.as_file_mut(), 1).unwrap(), hash(b"x"));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

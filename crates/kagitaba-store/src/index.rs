//! Versioned, deterministic participant catalogue. Never an authorization source.
//!
//! KTI3 || participant[32] || AES-128-SIV(plaintext, AD=[the 36-byte header]).
//! RFC 5297 AES-128-SIV consumes the random 32-byte index key directly. There is
//! no nonce. Plaintext is fingerprint[32], row count u32, then rows sorted by ID:
//! id[16], primary digest[32], own grant SHA256[32], kind u8 (item=0, collection=1),
//! password/totp/passkey u8 booleans, title, usernames, scopes. Strings are UTF-8
//! prefixed by u32 byte length; arrays by u32 element count. Integers are big endian.
//! Usernames/scopes are sorted and deduplicated. No timestamps or Git IDs occur.
use crate::{Error, Result, Snapshot};
use aes_siv::{KeyInit, siv::Aes128Siv};
use base64::Engine;
use kagitaba_core::{
    EntryId, KeyId,
    crypto::{ContentKey, KeyAgreement, PublicKey, WrappedKey},
};
use kagitaba_cxf::{Payload, PayloadKind};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROWS: usize = 50_000;
const MAX_STRING: usize = 16 * 1024;
const MAX_VALUES: usize = 1024;

/// Listing hints only. Presence flags do not promise support for use.
#[derive(Clone)]
pub struct Row {
    pub digest: [u8; 32],
    pub grant_digest: [u8; 32],
    pub title: String,
    pub kind: PayloadKind,
    pub usernames: Vec<String>,
    pub scopes: Vec<String>,
    pub password: bool,
    pub totp: bool,
    pub passkey: bool,
    pub collection: Option<CollectionNode>,
}
impl Row {
    fn wire_size(&self) -> Result<usize> {
        if self.title.len() > MAX_STRING {
            return Err(Error::Invalid);
        }
        let mut size = 16 + 32 + 32 + 4 + 4 + self.title.len();
        for values in [&self.usernames, &self.scopes] {
            if values.len() > MAX_VALUES || values.iter().any(|s| s.len() > MAX_STRING) {
                return Err(Error::Invalid);
            }
            size += 4 + values.iter().map(|s| 4 + s.len()).sum::<usize>();
        }
        size += 1;
        if let Some(tree) = &self.collection {
            size += tree.wire_size(0, &mut TreeBudget::default())?;
        }
        Ok(size)
    }
}
impl Drop for Row {
    fn drop(&mut self) {
        self.title.zeroize();
        self.usernames.zeroize();
        self.scopes.zeroize();
    }
}

/// Decrypted collection hints; links never imply access to their targets.
#[derive(Clone)]
pub struct CollectionNode {
    /// Decoded CXF ID. Embedded collection IDs can be arbitrary opaque bytes.
    pub id: Vec<u8>,
    pub title: String,
    /// Direct local links only, sorted and deduplicated. May be inaccessible.
    pub entries: Vec<EntryId>,
    /// External/account-qualified or non-local-sized links excluded from resolution.
    pub unresolved_links: usize,
    /// Embedded children in source order.
    pub children: Vec<CollectionNode>,
}
impl Drop for CollectionNode {
    fn drop(&mut self) {
        self.title.zeroize();
        self.id.zeroize();
    }
}
#[derive(Default)]
struct TreeBudget {
    nodes: usize,
    links: usize,
    ids: BTreeSet<Vec<u8>>,
}
impl TreeBudget {
    fn node(&mut self, id: &[u8], links: usize, depth: usize) -> Result<()> {
        self.nodes += 1;
        self.links = self.links.checked_add(links).ok_or(Error::Invalid)?;
        if depth >= 32
            || self.nodes > 1024
            || self.links > MAX_ROWS
            || id.is_empty()
            || id.len() > 1024
            || !self.ids.insert(id.to_vec())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl CollectionNode {
    fn wire_size(&self, depth: usize, budget: &mut TreeBudget) -> Result<usize> {
        budget.node(
            &self.id,
            self.entries
                .len()
                .checked_add(self.unresolved_links)
                .ok_or(Error::Invalid)?,
            depth,
        )?;
        if self.title.len() > MAX_STRING || self.entries.windows(2).any(|v| v[0] >= v[1]) {
            return Err(Error::Invalid);
        }
        let mut size = 4 + self.id.len() + 4 + self.title.len() + 4 + 16 * self.entries.len() + 8;
        for child in &self.children {
            size += child.wire_size(depth + 1, budget)?;
        }
        Ok(size)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        number(out, self.id.len());
        out.extend_from_slice(&self.id);
        string(out, &self.title)?;
        number(out, self.entries.len());
        for id in &self.entries {
            out.extend_from_slice(id.as_bytes());
        }
        number(out, self.unresolved_links);
        number(out, self.children.len());
        for child in &self.children {
            child.encode(out)?;
        }
        Ok(())
    }
}
fn validate_tree_owner(id: EntryId, row: &Row) -> Result<()> {
    match (&row.kind, &row.collection) {
        (PayloadKind::Item, None) => Ok(()),
        (PayloadKind::Collection, Some(tree)) if tree.id == id.as_bytes() => Ok(()),
        _ => Err(Error::Invalid),
    }
}
fn decoded_id(value: &serde_json::Value) -> Result<Vec<u8>> {
    let text = value.as_str().ok_or(Error::Invalid)?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
        .map_err(|_| Error::Invalid)
}
fn extract_collection(entity: &serde_json::Value) -> Result<CollectionNode> {
    let id = decoded_id(&entity["id"])?;
    let mut entries = BTreeSet::new();
    let mut unresolved_links = 0;
    if let Some(links) = entity["items"].as_array() {
        for link in links {
            // An account-qualified reference belongs to its source namespace.
            if link.get("account").is_some() {
                unresolved_links += 1;
                continue;
            }
            let bytes = decoded_id(&link["item"])?;
            if let Ok(bytes) = <[u8; 16]>::try_from(bytes.as_slice()) {
                entries.insert(EntryId::from_bytes(bytes));
            } else {
                unresolved_links += 1;
            }
        }
    }
    let mut node = CollectionNode {
        id,
        title: entity["title"].as_str().unwrap_or("Untitled").to_owned(),
        entries: entries.into_iter().collect(),
        unresolved_links,
        children: Vec::new(),
    };
    if let Some(children) = entity["subCollections"].as_array() {
        for child in children {
            node.children
                .push(extract_collection(child)?);
        }
    }
    Ok(node)
}
pub struct Index {
    fingerprint: [u8; 32],
    rows: BTreeMap<EntryId, Row>,
}
impl Index {
    pub fn rows(&self) -> &BTreeMap<EntryId, Row> {
        &self.rows
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn is_current(&self, snapshot: &Snapshot, participant: KeyId) -> bool {
        self.fingerprint == fingerprint(snapshot, participant)
    }
    /// Reuses unchanged rows. Removed/inaccessible entries require no decryption.
    /// Only newly accessible entries or changed primaries/own grants call the key.
    pub async fn refresh(
        snapshot: &Snapshot,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
        previous: Option<&Index>,
    ) -> Result<Self> {
        let index = Self::refresh_for_listing(snapshot, recipient, backend, previous).await?;
        // Persisted caches retain their strict encoding and resource bounds.
        index.encode()?;
        Ok(index)
    }
    /// Build complete transient listing hints from validated payloads even when
    /// they exceed cache bounds. `seal` still enforces every persisted index limit.
    /// Decryption failures remain errors; this is not a partial-index fallback.
    pub async fn refresh_for_listing(
        snapshot: &Snapshot,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
        previous: Option<&Index>,
    ) -> Result<Self> {
        if !snapshot.wallet.participants().contains_key(&recipient.id()) {
            return Err(Error::Invalid);
        }
        let mut rows = BTreeMap::new();
        for (id, entry) in snapshot.wallet.entries() {
            if snapshot.is_metadata(id) {
                continue;
            }
            let Some(grant) = entry.grants().get(&recipient.id()) else {
                continue;
            };
            let digest = entry.primary().digest();
            let grant_digest: [u8; 32] = Sha256::digest(grant.to_bytes()).into();
            let row = if let Some(old) = previous
                .and_then(|index| index.rows.get(id))
                .filter(|row| row.digest == digest && row.grant_digest == grant_digest)
            {
                old.clone()
            } else {
                let payload = Payload::open(entry, recipient, backend)
                    .await
                    .map_err(|_| Error::Invalid)?;
                extract(&payload, digest, grant_digest)?
            };
            rows.insert(*id, row);
        }
        let index = Self {
            fingerprint: fingerprint(snapshot, recipient.id()),
            rows,
        };
        Ok(index)
    }
    pub fn seal(&self, key: &ContentKey, participant: KeyId) -> Result<Vec<u8>> {
        let mut header = b"KTI3".to_vec();
        header.extend_from_slice(participant.as_bytes());
        let mut siv = Aes128Siv::new_from_slice(key.as_bytes()).map_err(|_| Error::Invalid)?;
        let mut encrypted = self.encode()?;
        siv.encrypt_in_place([header.as_slice()], &mut *encrypted)
            .map_err(|_| Error::Invalid)?;
        header.extend_from_slice(&encrypted);
        if header.len() > MAX_INDEX_BYTES {
            return Err(Error::Invalid);
        }
        Ok(header)
    }
    /// Invalid/disposable cache data must be handled as a cache miss by callers.
    pub fn open(bytes: &[u8], key: &ContentKey, participant: KeyId) -> Result<Self> {
        if bytes.len() < 52
            || bytes.len() > MAX_INDEX_BYTES
            || &bytes[..4] != b"KTI3"
            || &bytes[4..36] != participant.as_bytes()
        {
            return Err(Error::Invalid);
        }
        let mut siv = Aes128Siv::new_from_slice(key.as_bytes()).map_err(|_| Error::Invalid)?;
        let mut clear = Zeroizing::new(bytes[36..].to_vec());
        siv.decrypt_in_place([&bytes[..36]], &mut *clear)
            .map_err(|_| Error::Invalid)?;
        let mut input = Reader(&clear);
        let fingerprint = input.array()?;
        let count = input.count(MAX_ROWS)?;
        let mut rows = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let id = EntryId::from_bytes(input.array()?);
            if previous.is_some_and(|p| p >= id) {
                return Err(Error::Invalid);
            }
            previous = Some(id);
            let digest = input.array()?;
            let grant_digest = input.array()?;
            let kind = match input.byte()? {
                0 => PayloadKind::Item,
                1 => PayloadKind::Collection,
                _ => return Err(Error::Invalid),
            };
            let password = input.boolean()?;
            let totp = input.boolean()?;
            let passkey = input.boolean()?;
            rows.insert(
                id,
                Row {
                    digest,
                    grant_digest,
                    kind,
                    password,
                    totp,
                    passkey,
                    title: input.string()?,
                    usernames: input.strings()?,
                    scopes: input.strings()?,
                    collection: if input.boolean()? {
                        Some(input.collection(0, &mut TreeBudget::default())?)
                    } else {
                        None
                    },
                },
            );
        }
        for (id, row) in &rows {
            validate_tree_owner(*id, row)?;
        }
        if !input.0.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(Self { fingerprint, rows })
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.rows.len() > MAX_ROWS {
            return Err(Error::Invalid);
        }
        let mut out = Zeroizing::new(self.fingerprint.to_vec());
        number(&mut out, self.rows.len());
        for (id, row) in &self.rows {
            if out.len() + row.wire_size()? + 52 > MAX_INDEX_BYTES {
                return Err(Error::Invalid);
            }
            out.extend_from_slice(id.as_bytes());
            out.extend_from_slice(&row.digest);
            out.extend_from_slice(&row.grant_digest);
            out.extend_from_slice(&[
                match row.kind {
                    PayloadKind::Item => 0,
                    PayloadKind::Collection => 1,
                },
                u8::from(row.password),
                u8::from(row.totp),
                u8::from(row.passkey),
            ]);
            string(&mut out, &row.title)?;
            strings(&mut out, &row.usernames)?;
            strings(&mut out, &row.scopes)?;
            validate_tree_owner(*id, row)?;
            out.push(u8::from(row.collection.is_some()));
            if let Some(tree) = &row.collection {
                tree.wire_size(0, &mut TreeBudget::default())?;
                tree.encode(&mut out)?;
            }
            if out.len() + 52 > MAX_INDEX_BYTES {
                return Err(Error::Invalid);
            }
        }
        Ok(out)
    }
}
/// Sorted relevant credential entries, including the complete own grant bytes.
/// Domain and participant binding prevent reuse for another catalogue.
pub fn fingerprint(snapshot: &Snapshot, participant: KeyId) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Kagitaba/index-snapshot/v1\0");
    hash.update(participant.as_bytes());
    for (id, entry) in snapshot.wallet.entries() {
        if snapshot.is_metadata(id) {
            continue;
        }
        if let Some(grant) = entry.grants().get(&participant) {
            hash.update(id.as_bytes());
            hash.update(entry.primary().digest());
            hash.update(Sha256::digest(grant.to_bytes()));
        }
    }
    hash.finalize().into()
}
fn extract(payload: &Payload, digest: [u8; 32], grant_digest: [u8; 32]) -> Result<Row> {
    let entity = payload.entity();
    let mut row = Row {
        digest,
        grant_digest,
        kind: payload.kind(),
        title: entity["title"].as_str().unwrap_or("Untitled").to_owned(),
        usernames: vec![],
        scopes: vec![],
        password: false,
        totp: false,
        passkey: false,
        collection: if payload.kind() == PayloadKind::Collection {
            Some(extract_collection(entity)?)
        } else {
            None
        },
    };
    if let Some(credentials) = entity["credentials"].as_array() {
        for credential in credentials {
            match credential["type"].as_str() {
                Some("basic-auth") => {
                    row.password |= credential["password"]["value"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty());
                    if let Some(name) = credential["username"]["value"]
                        .as_str()
                        .or_else(|| credential["username"].as_str())
                    {
                        row.usernames.push(name.to_owned());
                    }
                }
                Some("totp") => row.totp = true,
                Some("passkey") => {
                    row.passkey = true;
                    if let Some(name) = credential["username"].as_str() {
                        row.usernames.push(name.to_owned());
                    }
                    if let Some(rp) = credential["rpId"].as_str() {
                        row.scopes.push(rp.to_owned());
                    }
                }
                _ => (),
            }
        }
    }
    if let Some(urls) = entity["scope"]["urls"].as_array() {
        for url in urls {
            if let Some(url) = url.as_str() {
                row.scopes.push(url.to_owned());
            }
        }
    }
    if let Some(apps) = entity["scope"]["androidApps"].as_array() {
        for app in apps {
            row.scopes.push(format!("android:{}", canonical_json(app)?));
        }
    }
    row.usernames.sort();
    row.usernames.dedup();
    row.scopes.sort();
    row.scopes.dedup();
    Ok(row)
}
// Explicit ordering remains stable when another crate enables serde_json's
// preserve_order feature. Serialize scalar values directly to retain arbitrary
// precision numbers; do not round-trip them through f64 or a typed CXF model.
fn canonical_json(value: &serde_json::Value) -> Result<String> {
    fn append(out: &mut String, value: &serde_json::Value) -> Result<()> {
        match value {
            serde_json::Value::Object(object) => {
                let mut fields = object.iter().collect::<Vec<_>>();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                out.push('{');
                for (position, (key, value)) in fields.into_iter().enumerate() {
                    if position != 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).map_err(|_| Error::Invalid)?);
                    out.push(':');
                    append(out, value)?;
                }
                out.push('}');
            }
            serde_json::Value::Array(array) => {
                out.push('[');
                for (position, value) in array.iter().enumerate() {
                    if position != 0 {
                        out.push(',');
                    }
                    append(out, value)?;
                }
                out.push(']');
            }
            _ => out.push_str(&serde_json::to_string(value).map_err(|_| Error::Invalid)?),
        }
        Ok(())
    }
    let mut out = Zeroizing::new(String::new());
    append(&mut out, value)?;
    Ok(std::mem::take(&mut *out))
}
fn key_context(participant: KeyId) -> Vec<u8> {
    let mut context = b"Kagitaba/index-key/v1\0".to_vec();
    context.extend_from_slice(participant.as_bytes());
    context
}
impl Snapshot {
    /// Provision once and retain on cache invalidation. Publish with normal signing.
    pub fn provision_index_key(
        &mut self,
        recipient: &PublicKey,
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Option<ContentKey>> {
        if self.wallet.participants().get(&recipient.id()) != Some(recipient) {
            return Err(Error::Invalid);
        }
        if self.index_keys.contains_key(&recipient.id()) {
            return Ok(None);
        }
        let key = ContentKey::generate(rng)?;
        let wrapped = WrappedKey::wrap(&key, recipient, &key_context(recipient.id()), rng)?;
        self.index_keys
            .insert(recipient.id(), wrapped.as_bytes().to_vec());
        Ok(Some(key))
    }
    pub async fn open_index_key(
        &self,
        recipient: &PublicKey,
        backend: &impl KeyAgreement,
    ) -> Result<ContentKey> {
        let wrapped = self.index_keys.get(&recipient.id()).ok_or(Error::Invalid)?;
        Ok(WrappedKey::from_bytes(wrapped)?
            .unwrap(recipient, &key_context(recipient.id()), backend)
            .await?)
    }
}
fn number(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_be_bytes());
}
fn string(out: &mut Vec<u8>, s: &str) -> Result<()> {
    if s.len() > MAX_STRING {
        return Err(Error::Invalid);
    }
    number(out, s.len());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}
fn strings(out: &mut Vec<u8>, values: &[String]) -> Result<()> {
    if values.len() > MAX_VALUES || values.windows(2).any(|p| p[0] >= p[1]) {
        return Err(Error::Invalid);
    }
    number(out, values.len());
    for s in values {
        string(out, s)?;
    }
    Ok(())
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.0.get(..N).ok_or(Error::Invalid)?;
        let out = bytes.try_into().map_err(|_| Error::Invalid)?;
        self.0 = &self.0[N..];
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > max {
            return Err(Error::Invalid);
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<String> {
        let n = self.count(MAX_STRING)?;
        let s = std::str::from_utf8(self.0.get(..n).ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?
            .to_owned();
        self.0 = &self.0[n..];
        Ok(s)
    }
    fn collection(&mut self, depth: usize, budget: &mut TreeBudget) -> Result<CollectionNode> {
        let len = self.count(1024)?;
        let id = self.0.get(..len).ok_or(Error::Invalid)?.to_vec();
        self.0 = &self.0[len..];
        let mut node = CollectionNode {
            id,
            title: self.string()?,
            entries: Vec::new(),
            unresolved_links: 0,
            children: Vec::new(),
        };
        let count = self.count(MAX_ROWS)?;
        budget.node(&node.id, count, depth)?;
        for _ in 0..count {
            let id = EntryId::from_bytes(self.array()?);
            if node.entries.last().is_some_and(|old| *old >= id) {
                return Err(Error::Invalid);
            }
            node.entries.push(id);
        }
        node.unresolved_links = self.count(MAX_ROWS)?;
        budget.links += node.unresolved_links;
        if budget.links > MAX_ROWS {
            return Err(Error::Invalid);
        }
        let count = self.count(1024)?;
        for _ in 0..count {
            node.children.push(self.collection(depth + 1, budget)?);
        }
        Ok(node)
    }
    fn strings(&mut self) -> Result<Vec<String>> {
        let n = self.count(MAX_VALUES)?;
        let mut values = Zeroizing::new(Vec::<String>::with_capacity(n));
        for _ in 0..n {
            let s = self.string()?;
            if values.last().is_some_and(|p| p >= &s) {
                return Err(Error::Invalid);
            }
            values.push(s);
        }
        Ok(std::mem::take(&mut *values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use kagitaba_core::crypto::{AgreementRequest, AgreementSecret, SoftwareIdentity};
    use rand_core::SeedableRng;
    use std::cell::Cell;
    struct Counting {
        key: SoftwareIdentity,
        calls: Cell<usize>,
    }
    impl KeyAgreement for Counting {
        fn key_id(&self) -> KeyId {
            self.key.public_key().id()
        }
        async fn agree(
            &self,
            request: &AgreementRequest,
        ) -> kagitaba_core::Result<AgreementSecret> {
            self.calls.set(self.calls.get() + 1);
            self.key.agree(request).await
        }
    }
    fn payload(id: u8, title: &str) -> Payload {
        use base64::Engine;
        let id = EntryId::from_bytes([id; 16]);
        Payload::new(id,PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
            "id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes()),"title":title,"credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":"alice"},"password":{"fieldType":"string","value":"secret"}}],"scope":{"urls":["https://example.org"],"androidApps":[]}
        })).unwrap()).unwrap()
    }
    #[test]
    fn password_presence_requires_a_nonempty_value() {
        for (password, expected) in [
            (serde_json::Value::Null, false),
            (
                serde_json::json!({"fieldType":"concealed-string","value":""}),
                false,
            ),
            (
                serde_json::json!({"fieldType":"concealed-string","value":"secret"}),
                true,
            ),
            (
                serde_json::json!({"fieldType":"concealed-string","value":" "}),
                true,
            ),
        ] {
            let original = payload(4, "Test");
            let changed = original
                .edited(|value| {
                    value["entity"]["credentials"][0]["password"] = password;
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                extract(&changed, [0; 32], [0; 32]).unwrap().password,
                expected
            );
        }
        let key = ContentKey::from_bytes([9; 32]);
        let participant = KeyId::from_bytes([3; 32]);
        let legacy = [b"KTI1".as_slice(), participant.as_bytes(), &[0; 16]].concat();
        assert!(Index::open(&legacy, &key, participant).is_err());
    }
    #[test]
    fn deterministic_authenticated_index_and_incremental_refresh() {
        let backend = Counting {
            key: SoftwareIdentity::from_bytes(&[7; 32]).unwrap(),
            calls: Cell::new(0),
        };
        let public = backend.key.public_key();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let mut snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
        let key = snapshot
            .provision_index_key(&public, &mut rng)
            .unwrap()
            .unwrap();
        let wrapper = snapshot.index_keys[&public.id()].clone();
        assert!(
            snapshot
                .provision_index_key(&public, &mut rng)
                .unwrap()
                .is_none()
        );
        let unwrapped = block_on(snapshot.open_index_key(&public, &backend)).unwrap();
        assert_eq!(key.as_bytes(), unwrapped.as_bytes());
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                payload(1, "First")
                    .seal(std::slice::from_ref(&public), &mut rng)
                    .unwrap(),
            )
            .unwrap();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                payload(2, "Second")
                    .seal(std::slice::from_ref(&public), &mut rng)
                    .unwrap(),
            )
            .unwrap();
        let index = block_on(Index::refresh(&snapshot, &public, &backend, None)).unwrap();
        assert_eq!(backend.calls.get(), 3);
        assert_eq!(
            index.rows[&EntryId::from_bytes([1; 16])].usernames,
            ["alice"]
        );
        assert!(index.rows[&EntryId::from_bytes([1; 16])].password);
        let bytes = index.seal(&key, public.id()).unwrap();
        assert_eq!(bytes, index.seal(&key, public.id()).unwrap());
        let opened = Index::open(&bytes, &key, public.id()).unwrap();
        assert!(opened.is_current(&snapshot, public.id()));
        assert_eq!(bytes, opened.seal(&key, public.id()).unwrap());
        assert!(Index::open(&bytes, &ContentKey::from_bytes([1; 32]), public.id()).is_err());
        assert!(Index::open(&bytes, &key, KeyId::from_bytes([1; 32])).is_err());
        for offset in [0, 4, 35, 36, bytes.len() - 1] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(Index::open(&corrupt, &key, public.id()).is_err());
        }
        snapshot.indexes.insert(public.id(), bytes);
        // Cache-only changes and unrelated participants do not change validity.
        assert!(index.is_current(&snapshot, public.id()));
        let other = SoftwareIdentity::from_bytes(&[8; 32]).unwrap().public_key();
        snapshot.wallet = snapshot.wallet.with_participant(other.clone()).unwrap();
        snapshot.signers.insert(other.id(), other.clone());
        assert!(index.is_current(&snapshot, public.id()));
        let refreshed =
            block_on(Index::refresh(&snapshot, &public, &backend, Some(&index))).unwrap();
        assert_eq!(backend.calls.get(), 3);
        assert_eq!(index.fingerprint, refreshed.fingerprint);
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                payload(2, "Updated")
                    .seal(std::slice::from_ref(&public), &mut rng)
                    .unwrap(),
            )
            .unwrap();
        assert!(!index.is_current(&snapshot, public.id()));
        let updated = block_on(Index::refresh(&snapshot, &public, &backend, Some(&index))).unwrap();
        assert_eq!(backend.calls.get(), 4);
        assert_eq!(updated.rows[&EntryId::from_bytes([2; 16])].title, "Updated");
        let first = snapshot.wallet.entries()[&EntryId::from_bytes([1; 16])].clone();
        snapshot.wallet = snapshot
            .wallet
            .with_entry(
                kagitaba_core::wallet::Entry::from_parts(first.primary().clone(), []).unwrap(),
            )
            .unwrap();
        let removed =
            block_on(Index::refresh(&snapshot, &public, &backend, Some(&updated))).unwrap();
        assert_eq!(backend.calls.get(), 4);
        assert!(!removed.rows.contains_key(&EntryId::from_bytes([1; 16])));
        snapshot.indexes.clear();
        assert_eq!(snapshot.index_keys[&public.id()], wrapper);
    }
    #[test]
    fn own_grant_changes_invalidate_but_other_recipients_grants_do_not() {
        use kagitaba_core::wallet::GrantRecord;
        let backend = Counting {
            key: SoftwareIdentity::from_bytes(&[7; 32]).unwrap(),
            calls: Cell::new(0),
        };
        let public = backend.key.public_key();
        let other = SoftwareIdentity::from_bytes(&[8; 32]).unwrap().public_key();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([20; 32]);
        let mut snapshot = Snapshot::empty(public.clone(), public.clone()).unwrap();
        snapshot.wallet = snapshot.wallet.with_participant(other.clone()).unwrap();
        snapshot.signers.insert(other.id(), other.clone());
        let entry = payload(1, "Example")
            .seal(std::slice::from_ref(&public), &mut rng)
            .unwrap();
        snapshot.wallet = snapshot.wallet.with_entry(entry.clone()).unwrap();
        let index = block_on(Index::refresh(&snapshot, &public, &backend, None)).unwrap();
        let primary = entry.primary();
        let key = block_on(
            WrappedKey::from_bytes(entry.grants()[&public.id()].body())
                .unwrap()
                .unwrap(&public, &primary.grant_context(public.id()), &backend.key),
        )
        .unwrap();
        let wrapped =
            WrappedKey::wrap(&key, &other, &primary.grant_context(other.id()), &mut rng).unwrap();
        let added = entry
            .with_grant(GrantRecord::new(primary, other.id(), wrapped.as_bytes().to_vec()).unwrap())
            .unwrap();
        snapshot.wallet = snapshot.wallet.with_entry(added.clone()).unwrap();
        assert!(index.is_current(&snapshot, public.id()));
        block_on(Index::refresh(&snapshot, &public, &backend, Some(&index))).unwrap();
        assert_eq!(backend.calls.get(), 1);
        let wrapped =
            WrappedKey::wrap(&key, &public, &primary.grant_context(public.id()), &mut rng).unwrap();
        let replacement =
            GrantRecord::new(primary, public.id(), wrapped.as_bytes().to_vec()).unwrap();
        let changed = kagitaba_core::wallet::Entry::from_parts(
            primary.clone(),
            added
                .grants()
                .values()
                .filter(|g| g.recipient() != public.id())
                .cloned()
                .chain([replacement]),
        )
        .unwrap();
        snapshot.wallet = snapshot.wallet.with_entry(changed).unwrap();
        assert!(!index.is_current(&snapshot, public.id()));
        let fresh = block_on(Index::refresh(&snapshot, &public, &backend, Some(&index))).unwrap();
        assert_eq!(backend.calls.get(), 2);
        assert!(fresh.is_current(&snapshot, public.id()));
    }
    #[test]
    fn android_scope_canonicalization_is_recursive_and_preserves_exact_numbers() {
        let a: serde_json::Value = serde_json::from_str(r#"{"name":"Example","bundleId":"org.example","extra":{"z":9007199254740993,"a":[{"z":1,"a":2}]}}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"extra":{"a":[{"a":2,"z":1}],"z":9007199254740993},"bundleId":"org.example","name":"Example"}"#).unwrap();
        let expected = r#"{"bundleId":"org.example","extra":{"a":[{"a":2,"z":1}],"z":9007199254740993},"name":"Example"}"#;
        assert_eq!(canonical_json(&a).unwrap(), expected);
        assert_eq!(canonical_json(&b).unwrap(), expected);
        let original = payload(1, "Example");
        let first = original
            .edited(|v| {
                v["entity"]["scope"]["androidApps"] = serde_json::json!([a]);
                Ok(())
            })
            .unwrap();
        let second = original
            .edited(|v| {
                v["entity"]["scope"]["androidApps"] = serde_json::json!([b]);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            extract(&first, [0; 32], [0; 32]).unwrap().scopes,
            extract(&second, [0; 32], [0; 32]).unwrap().scopes
        );
    }
    #[test]
    fn collection_tree_roundtrip_preserves_direct_local_membership() {
        let root = EntryId::from_bytes([21; 16]);
        let child = EntryId::from_bytes([22; 16]);
        let local = EntryId::from_bytes([23; 16]);
        let inaccessible = EntryId::from_bytes([24; 16]);
        let external = EntryId::from_bytes([25; 16]);
        let encoded =
            |id: EntryId| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes());
        let entity = serde_json::json!({"id":encoded(root),"title":"Synthetic root","items":[
            {"item":encoded(local)},{"item":encoded(local)},{"item":encoded(inaccessible)},
            {"item":encoded(external),"account":"ZXh0ZXJuYWw"}],
            "subCollections":[{"id":encoded(child),"title":"Synthetic child","items":[{"item":encoded(external)}]}]});
        let payload = Payload::new(
            root,
            PayloadKind::Collection,
            &serde_json::to_vec(&entity).unwrap(),
        )
        .unwrap();
        let row = extract(&payload, [1; 32], [2; 32]).unwrap();
        let tree = row.collection.as_ref().unwrap();
        assert_eq!(tree.entries, vec![local, inaccessible]);
        assert_eq!(tree.unresolved_links, 1);
        assert_eq!(tree.children[0].entries, vec![external]);
        assert_eq!(tree.children[0].id, child.as_bytes());
        assert_eq!(tree.title, "Synthetic root");
        let index = Index {
            fingerprint: [3; 32],
            rows: BTreeMap::from([(root, row)]),
        };
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([99; 32]);
        let key = ContentKey::generate(&mut rng).unwrap();
        let participant = SoftwareIdentity::generate(&mut rng)
            .unwrap()
            .public_key()
            .id();
        let bytes = index.seal(&key, participant).unwrap();
        assert_eq!(&bytes[..4], b"KTI3");
        assert_eq!(bytes, index.seal(&key, participant).unwrap());
        let reopened = Index::open(&bytes, &key, participant).unwrap();
        assert_eq!(*reopened.encode().unwrap(), *index.encode().unwrap());
        let tree = reopened.rows()[&root].collection.as_ref().unwrap();
        // UI filters against readable rows; missing links never create access.
        let available = BTreeSet::from([local, external]);
        assert_eq!(
            tree.entries
                .iter()
                .filter(|id| available.contains(id))
                .copied()
                .collect::<Vec<_>>(),
            vec![local]
        );
        let mut legacy = bytes;
        legacy[..4].copy_from_slice(b"KTI2");
        assert!(Index::open(&legacy, &key, participant).is_err());
    }
    #[test]
    fn collection_tree_rejects_duplicate_ids_unsorted_links_and_wrong_owner() {
        let id = EntryId::from_bytes([21; 16]);
        let mut tree = CollectionNode {
            id: id.as_bytes().to_vec(),
            title: "root".into(),
            entries: vec![],
            unresolved_links: 0,
            children: vec![],
        };
        tree.children.push(tree.clone());
        assert!(tree.wire_size(0, &mut TreeBudget::default()).is_err());
        tree.children.clear();
        tree.entries = vec![id, id];
        assert!(tree.wire_size(0, &mut TreeBudget::default()).is_err());
        tree.entries.clear();
        let payload = payload(21, "item");
        let mut row = extract(&payload, [0; 32], [0; 32]).unwrap();
        row.collection = Some(tree);
        assert!(validate_tree_owner(id, &row).is_err());
        row.kind = PayloadKind::Collection;
        assert!(validate_tree_owner(EntryId::from_bytes([22; 16]), &row).is_err());
    }
    #[test]
    fn collection_bounds_apply_before_encoding_and_decoder_recursion() {
        fn node(n: u8) -> CollectionNode {
            CollectionNode {
                id: vec![n],
                title: "node".into(),
                entries: vec![],
                unresolved_links: 0,
                children: vec![],
            }
        }
        let mut tree = node(0);
        for n in 1..33 {
            let mut parent = node(n);
            parent.children.push(tree);
            tree = parent;
        }
        assert!(tree.wire_size(0, &mut TreeBudget::default()).is_err());
        let mut wire = Vec::new();
        tree.encode(&mut wire).unwrap();
        assert!(
            Reader(&wire)
                .collection(0, &mut TreeBudget::default())
                .is_err()
        );
        let mut tree = node(0);
        tree.unresolved_links = MAX_ROWS + 1;
        assert!(tree.wire_size(0, &mut TreeBudget::default()).is_err());
        tree.unresolved_links = 1;
        let mut child = node(1);
        child.unresolved_links = usize::MAX;
        tree.children.push(child);
        assert!(tree.wire_size(0, &mut TreeBudget::default()).is_err());
    }
}

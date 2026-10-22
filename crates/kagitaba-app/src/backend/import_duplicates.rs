//! Conservative import equivalence. Digests are sensitive, transient lookup keys,
//! never persistent indexes or diagnostics. Collections are remapped separately.
use super::*;
use kagitaba_cxf::{PayloadKind, attachments};
use serde_json::Value;
use zeroize::Zeroize;

type Blobs = BTreeMap<String, kagitaba_store::AttachmentBlob>;

/// Compare current content across exporters, excluding retained import provenance
/// and timestamps only when it can be archived by merge_provenance. Unknown active
/// data remains meaningful. Generated attachment identity/randomness is excluded.
/// Every attachment is authenticated, including its declared plaintext hash.
/// Missing/extra/corrupt blobs fail closed; collections are not deduplicated.
pub(super) fn fingerprint(payload: &Payload, blobs: &Blobs) -> Result<Option<[u8; 32]>> {
    if payload.kind() != PayloadKind::Item {
        return Ok(None);
    }
    let files = attachments::list(payload)?;
    if files.len() != blobs.len() {
        return Err("Attachment manifest does not match stored files".into());
    }
    for file in &files {
        let blob = blobs.get(&file.blob_id).ok_or("Missing attachment data")?;
        let mut source = blob.open()?;
        attachments::decrypt_stream(payload.entry_id(), file, &mut source, &mut std::io::sink())?;
    }
    let value = semantic(payload)?;
    let canonical = Zeroizing::new(serde_json::to_vec(&value.0)?);
    let mut hash = Sha256::new();
    hash.update(b"Kagitaba/import-equivalence/v2\0");
    hash.update(canonical.as_slice());
    Ok(Some(hash.finalize().into()))
}

fn normalized(payload: &Payload) -> Result<SensitiveValue> {
    let serialized = payload.to_json()?;
    let mut value = SensitiveValue(serde_json::from_slice(&serialized)?);
    let entity = value.0["entity"].as_object_mut().ok_or("Invalid item")?;
    if let Some(mut id) = entity.remove("id") {
        wipe(&mut id);
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        for credential in credentials {
            if credential.get("kagitabaFile").is_none() {
                continue;
            }
            let object = credential.as_object_mut().ok_or("Invalid attachment")?;
            if let Some(mut id) = object.remove("id") {
                wipe(&mut id);
            }
            let metadata = object
                .get_mut("kagitabaFile")
                .and_then(Value::as_object_mut)
                .ok_or("Invalid attachment")?;
            for key in ["blobId", "key"] {
                if let Some(mut removed) = metadata.remove(key) {
                    wipe(&mut removed);
                }
            }
        }
    }
    normalize_keepass_protected_fields(&mut value.0["entity"]);
    sort_objects(&mut value.0);
    Ok(value)
}

const ARCHIVE: &str = "kagitabaImportProvenance";
fn known_source(value: &Value) -> bool {
    matches!(
        value.get("name").and_then(Value::as_str),
        Some("kagitaba-keepass-source" | "kagitaba-bitwarden-source" | "kagitaba-firefox-source")
    )
}
fn sort_values(values: &mut [Value]) {
    values.iter_mut().for_each(sort_objects);
    values.sort_by(|a, b| {
        let a = Zeroizing::new(serde_json::to_vec(a).expect("JSON value serializes"));
        let b = Zeroizing::new(serde_json::to_vec(b).expect("JSON value serializes"));
        a.as_slice().cmp(b.as_slice())
    });
}
fn semantic(payload: &Payload) -> Result<SensitiveValue> {
    let mut value = normalized(payload)?;
    validate_archive(value.0.get(ARCHIVE))?;
    for name in ["source", ARCHIVE] {
        if let Some(mut removed) = value.0.as_object_mut().and_then(|o| o.remove(name)) {
            wipe(&mut removed);
        }
    }
    let entity = value.0["entity"].as_object_mut().ok_or("Invalid item")?;
    for name in ["creationAt", "modifiedAt"] {
        if let Some(mut removed) = entity.remove(name) {
            wipe(&mut removed);
        }
    }
    if let Some(extensions) = entity.get_mut("extensions").and_then(Value::as_array_mut) {
        extensions.retain_mut(|extension| {
            if known_source(extension) {
                wipe(extension);
                false
            } else {
                true
            }
        });
        if extensions.is_empty() {
            entity.remove("extensions");
        }
    }
    if let Some(scope) = entity.get_mut("scope").and_then(Value::as_object_mut) {
        for name in ["urls", "androidApps"] {
            if let Some(values) = scope.get_mut(name).and_then(Value::as_array_mut) {
                sort_values(values);
                if values.is_empty() {
                    scope.remove(name);
                }
            }
        }
        if scope.is_empty() {
            entity.remove("scope");
        }
    }
    if entity.get("favorite") == Some(&Value::Bool(false)) {
        entity.remove("favorite");
    }
    if entity
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        entity.remove("tags");
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        fn known(c: &Value) -> bool {
            matches!(
                c["type"].as_str(),
                Some("basic-auth" | "note" | "totp" | "passkey" | "custom-fields" | "file")
            )
        }
        for credential in credentials.iter_mut() {
            if credential["type"] == "custom-fields"
                && let Some(fields) = credential.get_mut("fields").and_then(Value::as_array_mut)
            {
                sort_values(fields);
            }
        }
        for credential in credentials.iter_mut() {
            if credential["type"] == "basic-auth"
                && credential.get("username")
                    == Some(&serde_json::json!({"fieldType":"string","value":""}))
                && let Some(mut username) = credential
                    .as_object_mut()
                    .and_then(|o| o.remove("username"))
            {
                wipe(&mut username);
            }
        }
        credentials.retain_mut(|credential| {
            let inert = *credential == serde_json::json!({"type":"basic-auth"})
                || *credential == serde_json::json!({"type":"note","content":{"fieldType":"string","value":""}});
            if inert { wipe(credential); }
            !inert
        });
        // Unknown credential positions and bytes remain meaningful.
        let slots: Vec<_> = credentials
            .iter()
            .enumerate()
            .filter_map(|(i, c)| known(c).then_some(i))
            .collect();
        let mut sorted = SensitiveValue(Value::Array(
            slots
                .iter()
                .map(|i| std::mem::take(&mut credentials[*i]))
                .collect(),
        ));
        sort_values(sorted.0.as_array_mut().expect("array"));
        for (slot, credential) in slots
            .into_iter()
            .zip(std::mem::take(sorted.0.as_array_mut().expect("array")))
        {
            credentials[slot] = credential;
        }
    }
    sort_objects(&mut value.0);
    Ok(value)
}
fn validate_archive(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let archive = value
        .as_object()
        .ok_or("Invalid import provenance archive")?;
    if archive.len() != 2 || archive.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("Unsupported import provenance archive".into());
    }
    let records = archive
        .get("records")
        .and_then(Value::as_array)
        .ok_or("Invalid import provenance archive")?;
    for record in records {
        let object = record
            .as_object()
            .ok_or("Invalid import provenance record")?;
        if object.is_empty()
            || object.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "source" | "extensions" | "creationAt" | "modifiedAt"
                )
            })
        {
            return Err("Invalid import provenance record".into());
        }
        if let Some(extensions) = object.get("extensions") {
            let extensions = extensions
                .as_array()
                .ok_or("Invalid import provenance extensions")?;
            if extensions.iter().any(|e| !known_source(e)) {
                return Err("Unknown import provenance extension".into());
            }
        }
    }
    Ok(())
}
fn provenance(payload: &Payload) -> Result<BTreeMap<[u8; 32], SensitiveValue>> {
    let raw = payload.to_json()?;
    let value = SensitiveValue(serde_json::from_slice(&raw)?);
    validate_archive(value.0.get(ARCHIVE))?;
    let mut records = BTreeMap::new();
    fn insert(
        records: &mut BTreeMap<[u8; 32], SensitiveValue>,
        mut record: SensitiveValue,
    ) -> Result<()> {
        if record.0.as_object().is_some_and(|o| o.is_empty()) {
            return Ok(());
        }
        normalize_keepass_protected_fields(&mut record.0);
        sort_objects(&mut record.0);
        let bytes = Zeroizing::new(serde_json::to_vec(&record.0)?);
        records
            .entry(Sha256::digest(bytes.as_slice()).into())
            .or_insert(record);
        Ok(())
    }
    if let Some(archive) = value.0.get(ARCHIVE) {
        for record in archive["records"].as_array().expect("validated archive") {
            insert(&mut records, SensitiveValue(record.clone()))?;
        }
    }
    let mut own = SensitiveValue(serde_json::json!({}));
    if let Some(source) = value.0.get("source") {
        own.0["source"] = source.clone();
    }
    for name in ["creationAt", "modifiedAt"] {
        if let Some(timestamp) = value.0["entity"].get(name) {
            own.0[name] = timestamp.clone();
        }
    }
    if let Some(extensions) = value.0["entity"]
        .get("extensions")
        .and_then(Value::as_array)
    {
        let known: Vec<_> = extensions
            .iter()
            .filter(|e| known_source(e))
            .cloned()
            .collect();
        if !known.is_empty() {
            own.0["extensions"] = Value::Array(known);
        }
    }
    insert(&mut records, own)?;
    Ok(records)
}

/// Preserve excluded import metadata without changing active content. None means
/// the incoming provenance is already retained; callers can keep primary bytes.
/// The payload size limit remains authoritative: overflow fails, never truncates.
pub(super) fn merge_provenance(
    survivor: &Payload,
    incoming: &[&Payload],
) -> Result<Option<Payload>> {
    let expected = semantic(survivor)?;
    let mut records = provenance(survivor)?;
    let before = records.len();
    for payload in incoming {
        if semantic(payload)?.0 != expected.0 {
            return Err("Cannot merge provenance of different current content".into());
        }
        for (digest, record) in provenance(payload)? {
            records.entry(digest).or_insert(record);
        }
    }
    if records.len() == before {
        return Ok(None);
    }
    let archive = SensitiveValue(
        serde_json::json!({"version":1,"records":records.values().map(|v|&v.0).collect::<Vec<_>>()}),
    );
    Ok(Some(survivor.edited(|value| {
        value[ARCHIVE] = archive.0.clone();
        Ok(())
    })?))
}

/// Advisory only: hashes never authorize deduplication or leave this process.
pub(super) struct Comparison {
    identity: [u8; 32],
    categories: BTreeMap<&'static str, [u8; 32]>,
}
impl Drop for Comparison {
    fn drop(&mut self) {
        self.identity.zeroize();
        for digest in self.categories.values_mut() {
            digest.zeroize();
        }
    }
}
impl Comparison {
    pub(super) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(super) fn differences(&self, other: &Self) -> Vec<&'static str> {
        self.categories
            .iter()
            .filter_map(|(name, digest)| {
                (other.categories.get(name) != Some(digest)).then_some(*name)
            })
            .collect()
    }
}

pub(super) fn comparison(payload: &Payload) -> Result<Option<Comparison>> {
    use base64::Engine;
    if payload.kind() != PayloadKind::Item {
        return Ok(None);
    }
    let Some(source) = payload.source() else {
        return Ok(None);
    };
    let mut identity = Sha256::new();
    identity.update(b"Kagitaba/import-source-diagnostic/v1\0");
    for field in [&source["account"]["id"], &source["originalId"]] {
        let Some(encoded) = field.as_str() else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(
            match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
            {
                Ok(bytes) => bytes,
                Err(_) => return Ok(None),
            },
        );
        identity.update((bytes.len() as u64).to_be_bytes());
        identity.update(bytes.as_slice());
    }
    let mut value = semantic(payload)?;
    let mut categories = BTreeMap::new();
    fn take(value: &mut Value, key: &str) -> Value {
        value
            .as_object_mut()
            .and_then(|o| o.remove(key))
            .unwrap_or(Value::Null)
    }
    fn hash(
        categories: &mut BTreeMap<&'static str, [u8; 32]>,
        name: &'static str,
        value: Value,
    ) -> Result<()> {
        let mut value = SensitiveValue(value);
        sort_objects(&mut value.0);
        let encoded = Zeroizing::new(serde_json::to_vec(&value.0)?);
        let mut digest = Sha256::new();
        digest.update(b"Kagitaba/import-category-diagnostic/v1\0");
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(encoded.as_slice());
        categories.insert(name, digest.finalize().into());
        Ok(())
    }
    hash(
        &mut categories,
        "URLs/scopes",
        take(&mut value.0["entity"], "scope"),
    )?;
    let mut metadata = SensitiveValue(serde_json::json!({}));
    for key in ["title", "subtitle", "tags"] {
        if let Some(member) = value.0["entity"]
            .as_object_mut()
            .and_then(|o| o.remove(key))
        {
            metadata.0[key] = member;
        }
    }
    hash(
        &mut categories,
        "Title/tags",
        std::mem::take(&mut metadata.0),
    )?;
    let mut credentials = SensitiveValue(take(&mut value.0["entity"], "credentials"));
    let mut normal = SensitiveValue(serde_json::json!([]));
    let mut files = SensitiveValue(serde_json::json!([]));
    if let Some(entries) = credentials.0.as_array_mut() {
        for entry in std::mem::take(entries) {
            let target = if entry.get("kagitabaFile").is_some() {
                &mut files
            } else {
                &mut normal
            };
            target.0.as_array_mut().expect("array").push(entry);
        }
    }
    hash(
        &mut categories,
        "Current credentials",
        std::mem::take(&mut normal.0),
    )?;
    hash(&mut categories, "Attachments", std::mem::take(&mut files.0))?;
    hash(
        &mut categories,
        "Other active fields",
        std::mem::take(&mut value.0),
    )?;
    Ok(Some(Comparison {
        identity: identity.finalize().into(),
        categories,
    }))
}

// This importer-generated list denotes a set of protected field names. Older
// converters emitted HashMap order, so normalize only this known set on both
// sides. Keep unknown extensions, field values and all other array order intact.
fn normalize_keepass_protected_fields(entity: &mut Value) {
    let Some(extensions) = entity.get_mut("extensions").and_then(Value::as_array_mut) else {
        return;
    };
    for extension in extensions {
        if extension.get("name").and_then(Value::as_str) != Some("kagitaba-keepass-source") {
            continue;
        }
        let Some(fields) = extension
            .get_mut("protectedFields")
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        if fields.iter().all(Value::is_string) {
            fields.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        }
    }
}

struct SensitiveValue(Value);
impl Drop for SensitiveValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        _ => {}
    }
}
fn sort_objects(value: &mut Value) {
    match value {
        Value::Object(values) => {
            values.sort_keys();
            values.values_mut().for_each(sort_objects);
        }
        Value::Array(values) => values.iter_mut().for_each(sort_objects),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn item(byte: u8) -> Payload {
        let id = EntryId::from_bytes([byte; 16]);
        Payload::new(id, PayloadKind::Item, &serde_json::to_vec(&json!({
            "id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),
            "title":"Synthetic", "credentials":[{"type":"note","content":{"fieldType":"string","value":"Synthetic note"}}],
            "unknown":{"preserved":"value"}
        })).unwrap()).unwrap()
    }
    fn with_file(payload: &Payload, bytes: &[u8]) -> (Payload, Blobs) {
        let (payload, blobs) =
            attachments::add(payload, "example.bin", bytes, &mut rand::rngs::SysRng).unwrap();
        (
            payload,
            blobs
                .into_iter()
                .map(|(id, chunks)| {
                    (
                        id,
                        kagitaba_store::AttachmentBlob::from_chunks(&chunks).unwrap(),
                    )
                })
                .collect(),
        )
    }
    #[test]
    fn generated_identity_and_provenance_ignored_but_unknown_content_retained() {
        let a = item(1);
        let b = item(2);
        let empty = Blobs::new();
        assert_eq!(
            fingerprint(&a, &empty).unwrap(),
            fingerprint(&b, &empty).unwrap()
        );
        let changed = b
            .edited(|v| {
                v["entity"]["unknown"]["preserved"] = "changed".into();
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&a, &empty).unwrap(),
            fingerprint(&changed, &empty).unwrap()
        );
        let bytes = a.to_json().unwrap();
        let mut raw: Value = serde_json::from_slice(&bytes).unwrap();
        raw["source"] = json!({"vendor":"one"});
        let sourced = Payload::from_json(a.entry_id(), &serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(
            fingerprint(&a, &empty).unwrap(),
            fingerprint(&sourced, &empty).unwrap()
        );
    }
    #[test]
    fn legacy_keepass_protected_field_order_does_not_hide_duplicates() {
        let a = item(1).edited(|v| {
            v["entity"]["extensions"] = json!([{"name":"kagitaba-keepass-source",
                "data":{"preserved":"same"},"protectedFields":["Password","Private custom","otp"]}]);
            Ok(())
        }).unwrap();
        let b = a
            .with_entry_id(EntryId::from_bytes([2; 16]))
            .unwrap()
            .edited(|v| {
                v["entity"]["extensions"][0]["protectedFields"] =
                    json!(["otp", "Password", "Private custom"]);
                Ok(())
            })
            .unwrap();
        let empty = Blobs::new();
        assert_eq!(
            fingerprint(&a, &empty).unwrap(),
            fingerprint(&b, &empty).unwrap()
        );
        let changed = b
            .edited(|v| {
                v["entity"]["extensions"][0]["protectedFields"] = json!(["Password"]);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            fingerprint(&a, &empty).unwrap(),
            fingerprint(&changed, &empty).unwrap()
        );
        let unknown = a
            .edited(|v| {
                v["entity"]["extensions"][0]["name"] = "unknown".into();
                Ok(())
            })
            .unwrap();
        let reordered = unknown
            .edited(|v| {
                v["entity"]["extensions"][0]["protectedFields"] =
                    json!(["otp", "Password", "Private custom"]);
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&unknown, &empty).unwrap(),
            fingerprint(&reordered, &empty).unwrap()
        );
    }

    #[test]
    fn independent_encryption_matches_only_authenticated_equal_files() {
        let (a, ab) = with_file(&item(1), b"Synthetic attachment");
        let (b, bb) = with_file(&item(2), b"Synthetic attachment");
        assert_eq!(fingerprint(&a, &ab).unwrap(), fingerprint(&b, &bb).unwrap());
        let file_id = attachments::list(&b).unwrap()[0].id;
        let renamed = attachments::rename(&b, file_id, "renamed.bin").unwrap();
        assert_ne!(
            fingerprint(&a, &ab).unwrap(),
            fingerprint(&renamed, &bb).unwrap()
        );
        let extended = b
            .edited(|entity| {
                entity["entity"]["credentials"][1]["kagitabaFile"]["futurePolicy"] =
                    "preserve".into();
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&a, &ab).unwrap(),
            fingerprint(&extended, &bb).unwrap()
        );
        let (changed, cb) = with_file(&item(2), b"Different attachment");
        assert_ne!(
            fingerprint(&a, &ab).unwrap(),
            fingerprint(&changed, &cb).unwrap()
        );
        assert!(fingerprint(&a, &Blobs::new()).is_err());
        let wrong = ab.keys().cloned().zip(bb.values().cloned()).collect();
        assert!(fingerprint(&a, &wrong).is_err());
        assert!(fingerprint(&item(1), &ab).is_err());
    }
    #[test]
    fn provenance_union_preserves_sources_timestamps_and_is_idempotent() {
        fn sourced(n: u8, vendor: &str, time: u64) -> Payload {
            item(n).edited(|value| {
                value["source"]=json!({"account":{"id":"YWNjb3VudA","metadata":vendor},"originalId":"aXRlbQ","header":{"vendor":vendor}});
                value["entity"]["creationAt"]=time.into();
                value["entity"]["modifiedAt"]=(time+1).into();
                value["entity"]["extensions"]=json!([{"name":format!("kagitaba-{vendor}-source"),"data":{"passwordHistory":["synthetic old value"]}}]);
                Ok(())
            }).unwrap()
        }
        let a = sourced(1, "keepass", 5);
        let b = sourced(2, "bitwarden", 9);
        assert_eq!(
            fingerprint(&a, &Blobs::new()).unwrap(),
            fingerprint(&b, &Blobs::new()).unwrap()
        );
        let merged = merge_provenance(&a, &[&b]).unwrap().unwrap();
        assert!(merge_provenance(&merged, &[&a, &b]).unwrap().is_none());
        assert!(merge_provenance(&a, &[&a]).unwrap().is_none());
        assert_eq!(
            fingerprint(&a, &Blobs::new()).unwrap(),
            fingerprint(&merged, &Blobs::new()).unwrap()
        );
        let raw = SensitiveValue(serde_json::from_slice(&merged.to_json().unwrap()).unwrap());
        let records = raw.0[ARCHIVE]["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.get("source").is_some()
            && r.get("creationAt").is_some()
            && r.get("modifiedAt").is_some()
            && r.get("extensions").is_some()));
        assert!(
            records
                .iter()
                .all(|r| r.get("entity").is_none() && r.get("id").is_none())
        );
        assert_eq!(raw.0["entity"]["creationAt"], 5);
        let changed = b
            .edited(|v| {
                v["entity"]["unknown"]["preserved"] = "different".into();
                Ok(())
            })
            .unwrap();
        assert!(merge_provenance(&a, &[&changed]).is_err());
        for archive in [
            json!({"version":2,"records":[]}),
            json!({"version":1,"records":[],"unknown":true}),
            json!({"version":1,"records":[{"active":"not provenance"}]}),
        ] {
            let bad = a
                .edited(|v| {
                    v[ARCHIVE] = archive;
                    Ok(())
                })
                .unwrap();
            assert!(fingerprint(&bad, &Blobs::new()).is_err());
            assert!(merge_provenance(&a, &[&bad]).is_err());
        }
    }

    #[test]
    fn known_presentation_order_normalizes_but_unknowns_and_scopes_remain_meaningful() {
        let a=item(1).edited(|v| {
            v["entity"]["credentials"]=json!([
                {"type":"note","content":{"fieldType":"string","value":"synthetic"}},
                {"type":"custom-fields","fields":[{"fieldType":"string","label":"A","value":"one"},{"fieldType":"concealed-string","label":"B","value":"two"}]}
            ]);
            v["entity"]["scope"]=json!({"urls":["https://b.invalid","https://a.invalid"],"androidApps":[]});
            Ok(())
        }).unwrap();
        let b = a
            .with_entry_id(EntryId::from_bytes([2; 16]))
            .unwrap()
            .edited(|v| {
                v["entity"]["credentials"][1]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
                v["entity"]["credentials"].as_array_mut().unwrap().reverse();
                v["entity"]["scope"] =
                    json!({"urls":["https://a.invalid","https://b.invalid"],"androidApps":[]});
                Ok(())
            })
            .unwrap();
        assert_eq!(
            fingerprint(&a, &Blobs::new()).unwrap(),
            fingerprint(&b, &Blobs::new()).unwrap()
        );
        let changed = b
            .edited(|v| {
                v["entity"]["scope"]["futurePolicy"] = true.into();
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&a, &Blobs::new()).unwrap(),
            fingerprint(&changed, &Blobs::new()).unwrap()
        );
        let unknown = a
            .edited(|v| {
                v["entity"]["credentials"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"type":"future-secret","data":"synthetic"}));
                Ok(())
            })
            .unwrap();
        let moved = unknown
            .edited(|v| {
                v["entity"]["credentials"]
                    .as_array_mut()
                    .unwrap()
                    .rotate_right(1);
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&unknown, &Blobs::new()).unwrap(),
            fingerprint(&moved, &Blobs::new()).unwrap()
        );
        let empty = item(3)
            .edited(|v| {
                v["entity"]["scope"] = json!({"urls":[],"androidApps":[]});
                Ok(())
            })
            .unwrap();
        assert_eq!(
            fingerprint(&item(4), &Blobs::new()).unwrap(),
            fingerprint(&empty, &Blobs::new()).unwrap()
        );
    }

    #[test]
    fn advisory_categories_distinguish_account_metadata_from_credentials() {
        let a = item(1)
            .edited(|v| {
                v["source"] = json!({"account":{"id":"YQ","name":"one"},"originalId":"aQ"});
                Ok(())
            })
            .unwrap();
        let account = a
            .edited(|v| {
                v["source"]["account"]["name"] = "two".into();
                Ok(())
            })
            .unwrap();
        let credential = a
            .edited(|v| {
                v["entity"]["credentials"][0]["content"]["value"] = "different".into();
                Ok(())
            })
            .unwrap();
        let base = comparison(&a).unwrap().unwrap();
        let account = comparison(&account).unwrap().unwrap();
        let credential = comparison(&credential).unwrap().unwrap();
        assert_eq!(base.identity(), account.identity());
        assert!(base.differences(&account).is_empty());
        assert_eq!(base.differences(&credential), vec!["Current credentials"]);
    }
    #[test]
    fn inert_defaults_normalize_without_erasing_password_or_field_metadata() {
        let empty = item(1)
            .edited(|v| {
                v["entity"]["credentials"] = json!([]);
                Ok(())
            })
            .unwrap();
        let inert=empty.edited(|v| {
            v["entity"]["credentials"]=json!([{"type":"basic-auth","username":{"fieldType":"string","value":""}},{"type":"note","content":{"fieldType":"string","value":""}}]);
            v["entity"]["tags"]=json!([]);Ok(())
        }).unwrap();
        assert_eq!(
            fingerprint(&empty, &Blobs::new()).unwrap(),
            fingerprint(&inert, &Blobs::new()).unwrap()
        );
        let favorite = empty
            .edited(|v| {
                v["entity"]["favorite"] = true.into();
                Ok(())
            })
            .unwrap();
        assert_ne!(
            fingerprint(&empty, &Blobs::new()).unwrap(),
            fingerprint(&favorite, &Blobs::new()).unwrap()
        );
        for credential in [
            json!({"type":"basic-auth","password":{"fieldType":"concealed-string","value":""}}),
            json!({"type":"basic-auth","username":{"fieldType":"string","value":"","label":"Account"}}),
            json!({"type":"note","content":{"fieldType":"string","value":"","future":true}}),
            json!({"type":"basic-auth","future":true}),
        ] {
            let meaningful = empty
                .edited(|v| {
                    v["entity"]["credentials"] = json!([credential]);
                    Ok(())
                })
                .unwrap();
            assert_ne!(
                fingerprint(&empty, &Blobs::new()).unwrap(),
                fingerprint(&meaningful, &Blobs::new()).unwrap()
            );
        }
    }
}

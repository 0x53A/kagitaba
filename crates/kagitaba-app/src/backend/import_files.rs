//! Import attachment staging is encrypted; source bytes never go to disk.
use super::*;
use kagitaba_core::wallet::Wallet;
use kagitaba_cxf::{SourceAttachment, attachments};

pub(super) struct PendingImport {
    pub entries: Vec<Payload>,
    blobs: BTreeMap<EntryId, BTreeMap<String, kagitaba_store::AttachmentBlob>>,
    pub report: kagitaba_cxf::ImportReport,
    pub file_count: usize,
    duplicates: BTreeMap<EntryId, EntryId>,
    duplicate_differences: BTreeMap<&'static str, usize>,
    unavailable_entries: usize,
    scan_binding: Option<(String, KeyId)>,
}

impl PendingImport {
    /// Accept application-prepared entries with encrypted attachment staging.
    /// No persistence or grant changes occur until the normal reviewed apply.
    pub(super) fn from_prepared(entries: Vec<Payload>, blobs: BTreeMap<EntryId, BTreeMap<String, kagitaba_store::AttachmentBlob>>) -> Result<Self> {
        let mut ids = BTreeSet::new();
        let mut report = kagitaba_cxf::ImportReport::default();
        let mut file_count = 0;
        for payload in &entries {
            if !ids.insert(payload.entry_id()) { return Err("Duplicate prepared entry".into()); }
            match payload.kind() {
                kagitaba_cxf::PayloadKind::Item => report.items += 1,
                kagitaba_cxf::PayloadKind::Collection => report.root_collections += 1,
            }
            let files = attachments::list(payload)?;
            let stored = blobs.get(&payload.entry_id());
            if files.len() != stored.map_or(0, BTreeMap::len) { return Err("Attachment manifest does not match prepared files".into()); }
            for file in &files {
                let blob = stored.and_then(|files| files.get(&file.blob_id)).ok_or("Missing prepared attachment")?;
                if blob.len() as u64 != attachments::expected_blob_size(file)? { return Err("Invalid prepared attachment size".into()); }
            }
            file_count += files.len();
        }
        if blobs.keys().any(|id| !ids.contains(id)) { return Err("Prepared attachment owner is missing".into()); }
        Ok(Self { entries, blobs, report, file_count, duplicates:BTreeMap::new(), duplicate_differences:BTreeMap::new(), unavailable_entries:0, scan_binding:None })
    }

    pub fn prepare(plan: ImportPlan, sources: Vec<SourceAttachment>) -> Result<Self> {
        let report = plan.report();
        let mut entries = plan.into_entries();
        let mut by_source = BTreeMap::new();
        for (index, payload) in entries.iter().enumerate().filter(|_| !sources.is_empty()) {
            if payload.kind() == kagitaba_cxf::PayloadKind::Item
                && let Some(id) = payload.source().and_then(|source| source["originalId"].as_str())
                && by_source.insert(id.to_owned(), index).is_some()
            {
                return Err("Ambiguous attachment owner in import".into());
            }
        }
        let mut blobs = BTreeMap::<EntryId, BTreeMap<String, kagitaba_store::AttachmentBlob>>::new();
        let file_count = sources.len();
        for source in sources {
            let index = *by_source.get(&source.source_item_id).ok_or("Attachment owner is missing from import")?;
            let payload = &entries[index];
            let mut staging = tempfile::NamedTempFile::new()?;
            let next = attachments::add_stream(payload, &source.name, source.bytes.len() as u64,
                &mut std::io::Cursor::new(source.bytes.as_slice()), &mut staging, &mut rand::rngs::SysRng)?;
            let file = attachments::list(&next)?.pop().ok_or("Missing imported attachment")?;
            let blob = kagitaba_store::AttachmentBlob::from_staged(staging)?;
            if blobs.entry(payload.entry_id()).or_default().insert(file.blob_id.clone(), blob).is_some() {
                return Err("Duplicate imported attachment".into());
            }
            entries[index] = next;
        }
        Ok(Self { entries, blobs, report, file_count, duplicates: BTreeMap::new(), duplicate_differences:BTreeMap::new(), unavailable_entries: 0, scan_binding: None })
    }

    pub fn preview(&self, mut warnings: ImportWarnings) -> Result<ImportPreview> {
        for diagnostic in &mut warnings.details {
            diagnostic.entry_index = self.entries.iter().position(|payload| {
                payload.kind() == kagitaba_cxf::PayloadKind::Item
                    && payload.source().and_then(|source| source["originalId"].as_str()) == Some(diagnostic.source_id.as_str())
            });
        }
        Ok(ImportPreview {
            report: self.report.clone(), warnings,
            entries: self.entries.iter().map(|payload| {
                let mut entry = import_preview::PreviewEntry::from_payload(payload)?;
                entry.existing_duplicate = self.duplicates.contains_key(&payload.entry_id());
                Ok(entry)
            }).collect::<Result<_>>()?,
            imported_files: self.file_count,
            existing_duplicates: self.duplicates.len(),
            duplicate_differences: self.duplicate_differences.clone(),
            unavailable_entries: self.unavailable_entries,
        })
    }

    pub async fn scan_existing(&mut self, snapshot: &Snapshot, head: &str, recipient: &PublicKey, backend: &impl kagitaba_core::crypto::KeyAgreement) -> Result<()> {
        self.scan_binding = None;
        self.duplicates.clear();
        self.duplicate_differences.clear();
        self.unavailable_entries = 0;
        let empty = BTreeMap::new();
        let mut existing = BTreeMap::new();
        let mut comparisons = BTreeMap::<[u8;32], Vec<import_duplicates::Comparison>>::new();
        for (id, entry) in snapshot.wallet.entries() {
            if snapshot.is_metadata(id) { continue; }
            if !entry.grants().contains_key(&recipient.id()) {
                self.unavailable_entries += 1;
                continue;
            }
            let fingerprint = match Payload::open(entry, recipient, backend).await {
                Ok(payload) => {
                    let fingerprint = super::import_duplicates::fingerprint(&payload, snapshot.attachments.get(id).unwrap_or(&empty));
                    if matches!(fingerprint, Ok(Some(_))) && let Some(comparison) = import_duplicates::comparison(&payload)? {
                        comparisons.entry(comparison.identity()).or_default().push(comparison);
                    }
                    fingerprint
                },
                Err(error @ kagitaba_cxf::Error::Core(kagitaba_core::Error::KeyUnavailable)) => return Err(error.into()),
                Err(_) => { self.unavailable_entries += 1; continue; }
            };
            match fingerprint {
                Ok(Some(hash)) => { existing.entry(hash).or_insert(*id); }
                Ok(None) => (),
                Err(_) => self.unavailable_entries += 1,
            }
        }
        for payload in &self.entries {
            let Some(hash) = super::import_duplicates::fingerprint(payload, self.blobs.get(&payload.entry_id()).unwrap_or(&empty))? else { continue; };
            if let Some(id) = existing.get(&hash) {
                self.duplicates.insert(payload.entry_id(), *id);
                continue;
            }
            let incoming = import_duplicates::comparison(payload)?;
            let best = incoming.as_ref().and_then(|incoming| comparisons.get(&incoming.identity()).map(|candidates| {
                candidates.iter().map(|candidate|incoming.differences(candidate))
                    .min_by(|a,b|a.len().cmp(&b.len()).then_with(||a.cmp(b))).unwrap_or_default()
            }));
            match best {
                Some(categories) if categories.is_empty() => *self.duplicate_differences.entry("Other active fields").or_default() += 1,
                Some(categories) => for category in categories { *self.duplicate_differences.entry(category).or_default() += 1; },
                None => *self.duplicate_differences.entry("No matching source identity").or_default() += 1,
            }
        }
        self.scan_binding = Some((head.to_owned(), recipient.id()));
        Ok(())
    }

    /// Use only the reviewed snapshot and key; no partial candidate escapes on failure.
    pub async fn apply(&self, snapshot: &Snapshot, head: &str, recipients: &[KeyId], skip: bool, recipient: &PublicKey, backend: &impl kagitaba_core::crypto::KeyAgreement) -> Result<Snapshot> {
        if self.scan_binding.as_ref().is_none_or(|(bound_head, key)| bound_head != head || *key != recipient.id()) {
            return Err("Wallet or key changed; preview this import again".into());
        }
        if !skip || self.duplicates.is_empty() { return self.encrypt_into(snapshot, recipients); }
        if recipients.is_empty() || recipients.iter().collect::<BTreeSet<_>>().len() != recipients.len() {
            return Err("Choose distinct import recipients".into());
        }
        for id in recipients { if !snapshot.wallet.participants().contains_key(id) { return Err("Unknown import recipient".into()); } }
        let mut next = snapshot.clone();
        let mut updates = Vec::new();
        for survivor in self.duplicates.values().copied().collect::<BTreeSet<_>>() {
            let entry = next.wallet.entries().get(&survivor).ok_or("Duplicate survivor no longer exists")?;
            let original = Payload::open(entry, recipient, backend).await?;
            let incoming = self.entries.iter().filter(|payload| self.duplicates.get(&payload.entry_id()) == Some(&survivor)).collect::<Vec<_>>();
            if let Some(merged) = import_duplicates::merge_provenance(&original, &incoming)? {
                let union = entry.grants().keys().copied().chain(recipients.iter().copied()).collect::<BTreeSet<_>>();
                let keys = union.iter().map(|id| next.wallet.participants().get(id).cloned().ok_or("Unknown import recipient")).collect::<std::result::Result<Vec<_>, _>>()?;
                updates.push(merged.seal(&keys, &mut rand::rngs::SysRng)?);
                continue;
            }
            let missing = recipients.iter().filter(|id| !entry.grants().contains_key(id)).copied().collect::<Vec<_>>();
            if missing.is_empty() { continue; }
            let grant = entry.grants().get(&recipient.id()).ok_or("This key cannot extend duplicate access")?;
            let key = kagitaba_core::crypto::WrappedKey::from_bytes(grant.body())?.unwrap(recipient, &entry.primary().grant_context(recipient.id()), backend).await?;
            let mut updated = entry.clone();
            for id in missing {
                let public = next.wallet.participants().get(&id).ok_or("Unknown import recipient")?;
                let wrapped = kagitaba_core::crypto::WrappedKey::wrap(&key, public, &entry.primary().grant_context(id), &mut rand::rngs::SysRng)?;
                updated = updated.with_grant(kagitaba_core::wallet::GrantRecord::new(entry.primary(), id, wrapped.as_bytes().to_vec())?)?;
            }
            updates.push(updated);
        }
        next.wallet = next.wallet.with_entries(updates)?;
        let mut entries = Vec::new();
        for payload in &self.entries {
            if self.duplicates.contains_key(&payload.entry_id()) { continue; }
            entries.push(payload.edited(|value| { rewrite_import_links(&mut value["entity"], &self.duplicates); Ok(()) })?);
        }
        let remaining = Self {
            entries,
            blobs: self.blobs.iter().filter(|(id,_)| !self.duplicates.contains_key(id)).map(|(id,blobs)| (*id,blobs.clone())).collect(),
            report: self.report.clone(), file_count:self.file_count, duplicates:BTreeMap::new(), duplicate_differences:BTreeMap::new(), unavailable_entries:0, scan_binding:None,
        };
        remaining.encrypt_into(&next, recipients)
    }

    /// Return a complete candidate snapshot only after all files and entries succeed.
    pub fn encrypt_into(&self, snapshot: &Snapshot, recipients: &[KeyId]) -> Result<Snapshot> {
        if recipients.is_empty() || recipients.iter().collect::<BTreeSet<_>>().len() != recipients.len() {
            return Err("Choose distinct import recipients".into());
        }
        let keys = recipients.iter().map(|id| snapshot.wallet.participants().get(id).cloned().ok_or("Unknown import recipient"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if self.entries.iter().any(|p| snapshot.wallet.entries().contains_key(&p.entry_id())) {
            return Err("Imported entry already exists".into());
        }
        let sealed = self.entries.iter().map(|p| p.seal(&keys, &mut rand::rngs::SysRng)).collect::<kagitaba_cxf::Result<Vec<_>>>()?;
        let mut next = snapshot.clone();
        next.wallet = Wallet::from_parts(snapshot.wallet.participants().values().cloned(), snapshot.wallet.entries().values().cloned().chain(sealed))?;
        next.attachments.extend(self.blobs.clone());
        for payload in &self.entries { files::validate(&next, payload.entry_id(), payload)?; }
        next.validate()?;
        Ok(next)
    }
}

fn rewrite_import_links(entity: &mut serde_json::Value, duplicates: &BTreeMap<EntryId, EntryId>) {
    fn link(value: &mut serde_json::Value, duplicates: &BTreeMap<EntryId, EntryId>) {
        use base64::Engine;
        if value.get("account").is_some() { return; }
        let Some(encoded) = value["item"].as_str() else { return; };
        let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded) else { return; };
        let Ok(bytes) = <[u8;16]>::try_from(bytes.as_slice()) else { return; };
        if let Some(survivor) = duplicates.get(&EntryId::from_bytes(bytes)) {
            value["item"] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(survivor.as_bytes()).into();
        }
    }
    if let Some(items) = entity.get_mut("items").and_then(serde_json::Value::as_array_mut) { for item in items { link(item, duplicates); } }
    if let Some(credentials) = entity.get_mut("credentials").and_then(serde_json::Value::as_array_mut) {
        for credential in credentials { if credential["type"] == "item-reference" { link(&mut credential["reference"], duplicates); } }
    }
    if let Some(children) = entity.get_mut("subCollections").and_then(serde_json::Value::as_array_mut) { for child in children { rewrite_import_links(child, duplicates); } }
}

/// Preserve the exact source bytes in a dedicated item before ID remapping.
/// A separate source account avoids collisions with exporter item namespaces.
pub(super) fn with_original_file(document: Document, path: &Path, bytes: Zeroizing<Vec<u8>>) -> Result<(Document, SourceAttachment)> {
    let name = path.file_name().and_then(|name| name.to_str()).ok_or("Source filename is not valid UTF-8")?;
    let mut raw = crate::editor::SecretValue(document.as_json().clone());
    let accounts = raw.0["accounts"].as_array_mut().ok_or("Invalid import accounts")?;
    let mut counter = 0u64;
    let account_id = loop {
        let candidate = data_encoding::BASE64URL_NOPAD.encode(format!("kagitaba-original-file-account-{counter}").as_bytes());
        counter += 1;
        if !accounts.iter().any(|account| account["id"].as_str().is_some_and(|id| id.trim_end_matches('=') == candidate)) { break candidate; }
    };
    // Stable item ID within the isolated source account; the import planner
    // allocates a fresh wallet ID and attachment ownership follows that mapping.
    let mut identity = Sha256::new();
    identity.update(b"Kagitaba/original-import-file\0");
    identity.update(name.as_bytes());
    identity.update([0]);
    identity.update(bytes.as_slice());
    let source_item_id = data_encoding::BASE64URL_NOPAD.encode(&identity.finalize());
    accounts.push(serde_json::json!({
        "id":account_id,"username":"","email":"","collections":[],
        "items":[{"id":source_item_id,"title":format!("Original file: {name}"),"credentials":[]}]
    }));
    let encoded = Zeroizing::new(serde_json::to_vec(&raw.0)?);
    Ok((Document::from_json(&encoded)?, SourceAttachment {
        source_item_id, name: Zeroizing::new(name.to_owned()), bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use zeroize::Zeroizing;

    fn fixture() -> (Snapshot, SoftwareIdentity, ImportPlan, String) {
        let identity = SoftwareIdentity::from_bytes(&[7; 32]).unwrap();
        let public = identity.public_key();
        let snapshot = Snapshot::empty(public.clone(), public).unwrap();
        let converted = kagitaba_cxf::bitwarden::from_json(br#"{"encrypted":false,"items":[{"id":"source-item","type":1,"name":"Synthetic import","login":{"username":"test","password":"synthetic"}}]}"#).unwrap();
        let source_id = converted.document().as_json()["accounts"][0]["items"][0]["id"].as_str().unwrap().to_owned();
        let plan = converted.document().plan_import(&snapshot.wallet, &mut rand::rngs::SysRng).unwrap();
        (snapshot, identity, plan, source_id)
    }

    #[test]
    fn exact_duplicates_union_access_and_remap_collection_without_changing_survivor() {
        use base64::Engine;
        let (snapshot, identity, plan, _) = fixture();
        let first = PendingImport::prepare(plan, vec![]).unwrap();
        let mut snapshot = first.encrypt_into(&snapshot, &[identity.public_key().id()]).unwrap();
        let survivor = first.entries[0].entry_id();
        let original = snapshot.wallet.entries()[&survivor].clone();
        let other = SoftwareIdentity::from_bytes(&[9;32]).unwrap();
        let public = other.public_key();
        snapshot.wallet = snapshot.wallet.with_participant(public.clone()).unwrap();
        snapshot.signers.insert(public.id(), public.clone());
        let (_, _, mut plan, _) = fixture();
        plan.wrap_collection("Synthetic import", &mut rand::rngs::SysRng).unwrap();
        let mut pending = PendingImport::prepare(plan, vec![]).unwrap();
        block_on(pending.scan_existing(&snapshot,"accepted-head", &identity.public_key(), &identity)).unwrap();
        let preview = pending.preview(ImportWarnings::default()).unwrap();
        assert_eq!(preview.existing_duplicates,1);
        assert_eq!(preview.entries.iter().filter(|entry| entry.existing_duplicate).count(),1);
        assert!(preview.entries.iter().filter(|entry| entry.collection).all(|entry| !entry.existing_duplicate));
        assert!(block_on(pending.apply(&snapshot,"different-head", &[public.id()],true,&identity.public_key(),&identity)).is_err());
        assert!(block_on(pending.apply(&snapshot,"accepted-head", &[public.id()],true,&public,&other)).is_err());
        struct Denied(KeyId);
        impl kagitaba_core::crypto::KeyAgreement for Denied {
            fn key_id(&self) -> KeyId { self.0 }
            async fn agree(&self, _: &kagitaba_core::crypto::AgreementRequest) -> kagitaba_core::Result<kagitaba_core::crypto::AgreementSecret> {
                Err(kagitaba_core::Error::KeyUnavailable)
            }
        }
        assert!(block_on(pending.apply(&snapshot,"accepted-head", &[public.id()],true,&identity.public_key(),&Denied(identity.public_key().id()))).is_err());
        assert_eq!(snapshot.wallet.entries()[&survivor].grants().len(),1);
        let next = block_on(pending.apply(&snapshot,"accepted-head", &[public.id()],true,&identity.public_key(),&identity)).unwrap();
        let reused = &next.wallet.entries()[&survivor];
        assert_eq!(reused.primary(),original.primary());
        assert_eq!(reused.grants()[&identity.public_key().id()],original.grants()[&identity.public_key().id()]);
        assert!(block_on(Payload::open(reused,&public,&other)).is_ok());
        assert_eq!(next.wallet.entries().len(),2);
        let collection = next.wallet.entries().iter().find(|(id,_)|**id!=survivor).unwrap().1;
        let opened = block_on(Payload::open(collection,&public,&other)).unwrap();
        assert_eq!(opened.entity()["items"][0]["item"],base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(survivor.as_bytes()));
        // Turning off skipping imports a fresh entry and the collection.
        let unskipped=block_on(pending.apply(&snapshot,"accepted-head", &[public.id()],false,&identity.public_key(),&identity)).unwrap();
        assert_eq!(unskipped.wallet.entries().len(),3);
        assert_eq!(snapshot.wallet.entries()[&survivor].grants().len(),1);
    }

    #[test]
    fn reimport_matches_legacy_keepass_protected_field_order() {
        let (snapshot, identity, plan, _) = fixture();
        let first = PendingImport::prepare(plan, vec![]).unwrap();
        let old = first.entries[0].edited(|v| {
            v["entity"]["extensions"] = serde_json::json!([{
                "name":"kagitaba-keepass-source", "data":{"preserved":"synthetic"},
                "protectedFields":["otp","Password","Private custom"]
            }]);
            Ok(())
        }).unwrap();
        let original_id = old.entry_id();
        let new_id = EntryId::from_bytes([42;16]);
        let fresh = old.with_entry_id(new_id).unwrap().edited(|v| {
            v["entity"]["extensions"][0]["protectedFields"] = serde_json::json!(["Password","Private custom","otp"]);
            Ok(())
        }).unwrap();
        let first = PendingImport::from_prepared(vec![old], BTreeMap::new()).unwrap();
        let snapshot = first.encrypt_into(&snapshot, &[identity.public_key().id()]).unwrap();
        let mut pending = PendingImport::from_prepared(vec![fresh], BTreeMap::new()).unwrap();
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert_eq!(pending.preview(ImportWarnings::default()).unwrap().existing_duplicates,1);
        let result = block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(result.wallet.entries().len(),1);
        assert!(result.wallet.entries().contains_key(&original_id));
        assert!(!result.wallet.entries().contains_key(&new_id));
    }

    #[test]
    fn keepass_and_bitwarden_match_and_preserve_both_import_sources() {
        let (snapshot, identity, _, _) = fixture();
        let mut config = keepass::config::DatabaseConfig::default();
        config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
        let mut db = keepass::Database::with_config(config);
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", "Cross-vendor account");
            entry.set_unprotected("UserName", "synthetic-user");
            entry.set_protected("Password", "synthetic-password");
            entry.set_unprotected("URL", "https://example.test");
        }
        let mut bytes = Vec::new();
        db.save(&mut bytes, keepass::DatabaseKey::new().with_password("synthetic")).unwrap();
        let keepass = kagitaba_cxf::keepass::from_bytes(&bytes, Some("synthetic"), None).unwrap();
        let first = PendingImport::prepare(keepass.document().plan_import(&snapshot.wallet, &mut rand::rngs::SysRng).unwrap(), vec![]).unwrap();
        let survivor = first.entries.iter().find(|p| p.kind() == kagitaba_cxf::PayloadKind::Item).unwrap().entry_id();
        let snapshot = first.encrypt_into(&snapshot, &[identity.public_key().id()]).unwrap();
        let original = block_on(Payload::open(&snapshot.wallet.entries()[&survivor], &identity.public_key(), &identity)).unwrap();
        let bitwarden = kagitaba_cxf::bitwarden::from_json(br#"{"encrypted":false,"items":[{"id":"cross-vendor","type":1,"name":"Cross-vendor account","favorite":false,"notes":null,"fields":null,"folderId":null,"reprompt":0,"passwordHistory":null,"login":{"username":"synthetic-user","password":"synthetic-password","totp":null,"fido2Credentials":[],"uris":[{"uri":"https://example.test","match":null}]}}]}"#).unwrap();
        let mut pending = PendingImport::prepare(bitwarden.document().plan_import(&snapshot.wallet, &mut rand::rngs::SysRng).unwrap(), vec![]).unwrap();
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert_eq!(pending.preview(ImportWarnings::default()).unwrap().existing_duplicates,1);
        let next = block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(next.wallet.entries().len(),snapshot.wallet.entries().len());
        let merged = block_on(Payload::open(&next.wallet.entries()[&survivor], &identity.public_key(), &identity)).unwrap();
        assert!(merged.source()==original.source());
        assert!(serde_json::from_slice::<serde_json::Value>(&merged.to_json().unwrap()).unwrap().get("kagitabaImportProvenance").is_some());
        // Reimporting the same source again must not grow provenance or revise the survivor.
        let mut again = PendingImport::prepare(bitwarden.document().plan_import(&next.wallet, &mut rand::rngs::SysRng).unwrap(), vec![]).unwrap();
        block_on(again.scan_existing(&next,"next",&identity.public_key(),&identity)).unwrap();
        let repeated = block_on(again.apply(&next,"next",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(repeated.wallet.entries()[&survivor].primary(),next.wallet.entries()[&survivor].primary());
    }

    #[test]
    fn skipping_duplicates_preserves_leaf_collection_shape() {
        let (snapshot, identity, plan, _) = fixture();
        let first = PendingImport::prepare(plan,vec![]).unwrap();
        let snapshot = first.encrypt_into(&snapshot,&[identity.public_key().id()]).unwrap();
        let (_,_,plan,_) = fixture();
        let mut pending=PendingImport::prepare(plan,vec![]).unwrap();
        let incoming_id = pending.entries[0].entry_id();
        let root_id=EntryId::from_bytes([55;16]);
        let child_id=EntryId::from_bytes([56;16]);
        let encode=|id:EntryId| data_encoding::BASE64URL_NOPAD.encode(id.as_bytes());
        let collection=Payload::new(root_id,kagitaba_cxf::PayloadKind::Collection,&serde_json::to_vec(&serde_json::json!({
            "id":encode(root_id),"title":"Imported root","items":[],
            "subCollections":[{"id":encode(child_id),"title":"Leaf","items":[{"item":encode(incoming_id)}]}]
        })).unwrap()).unwrap();
        pending.entries.push(collection);
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert_eq!(pending.preview(ImportWarnings::default()).unwrap().existing_duplicates,1);
        let next=block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        let opened=block_on(Payload::open(&next.wallet.entries()[&root_id],&identity.public_key(),&identity)).unwrap();
        let leaf=&opened.entity()["subCollections"][0];
        assert!(leaf.get("subCollections").is_none());
        assert!(leaf.get("credentials").is_none());
        assert_eq!(leaf["items"][0]["item"],encode(first.entries[0].entry_id()));
    }

    #[test]
    fn repeated_keepass_import_with_totp_and_attachment_is_a_duplicate() {
        let (snapshot, identity, _, _) = fixture();
        let mut config = keepass::config::DatabaseConfig::default();
        config.kdf_config = keepass::config::KdfConfig::Aes { rounds:10 };
        let mut db = keepass::Database::with_config(config);
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("Title","Synthetic OTP and file");
            entry.set_unprotected("UserName","synthetic-user");
            entry.set_protected("Password","synthetic-password");
            entry.set_protected("TimeOtp-Secret-Base32","JBSWY3DPEHPK3PXP");
            entry.add_attachment("backup.bin",keepass::db::Value::unprotected(vec![42u8;1024*1024+17]));
        }
        let mut bytes=Vec::new();
        db.save(&mut bytes,keepass::DatabaseKey::new().with_password("synthetic")).unwrap();
        let prepare = |wallet:&kagitaba_core::wallet::Wallet| {
            let (document,_,files)=kagitaba_cxf::keepass::from_bytes(&bytes,Some("synthetic"),None).unwrap().into_parts();
            let mut plan=document.plan_import(wallet,&mut rand::rngs::SysRng).unwrap();
            plan.wrap_collection("Import",&mut rand::rngs::SysRng).unwrap();
            PendingImport::prepare(plan,files).unwrap()
        };
        let first=prepare(&snapshot.wallet);
        let original=first.entries.iter().find(|p|p.kind()==kagitaba_cxf::PayloadKind::Item).unwrap();
        assert!(original.entity()["credentials"].as_array().unwrap().iter().any(|c|c["type"]=="totp"));
        assert_eq!(attachments::list(original).unwrap().len(),1);
        let snapshot=first.encrypt_into(&snapshot,&[identity.public_key().id()]).unwrap();
        let mut pending=prepare(&snapshot.wallet);
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert_eq!(pending.preview(ImportWarnings::default()).unwrap().existing_duplicates,1);
        let next=block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(next.attachments.len(),snapshot.attachments.len());
        assert_eq!(next.wallet.entries()[&original.entry_id()].primary(),snapshot.wallet.entries()[&original.entry_id()].primary());
    }

    #[test]
    fn denied_key_stops_duplicate_scan_after_one_private_operation() {
        use kagitaba_core::crypto::{KeyAgreement, AgreementRequest, AgreementSecret};
        struct Denied { id:KeyId, calls:std::cell::Cell<usize> }
        impl KeyAgreement for Denied {
            fn key_id(&self)->KeyId { self.id }
            async fn agree(&self,_:&AgreementRequest)->kagitaba_core::Result<AgreementSecret> {
                self.calls.set(self.calls.get()+1); Err(kagitaba_core::Error::KeyUnavailable)
            }
        }
        let (snapshot,identity,plan,_)=fixture();
        let first=PendingImport::prepare(plan,vec![]).unwrap();
        let snapshot=first.encrypt_into(&snapshot,&[identity.public_key().id()]).unwrap();
        let (_,_,plan,_)=fixture();
        let second=PendingImport::prepare(plan,vec![]).unwrap();
        let snapshot=second.encrypt_into(&snapshot,&[identity.public_key().id()]).unwrap();
        let (_,_,plan,_)=fixture();
        let mut pending=PendingImport::prepare(plan,vec![]).unwrap();
        let backend=Denied{id:identity.public_key().id(),calls:std::cell::Cell::new(0)};
        assert!(block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&backend)).is_err());
        assert_eq!(backend.calls.get(),1);
        assert!(pending.scan_binding.is_none());
    }

    #[test]
    fn changed_content_is_not_skipped_even_with_identical_source_identity() {
        let (snapshot, identity, plan, _) = fixture();
        let first=PendingImport::prepare(plan,vec![]).unwrap();
        let snapshot=first.encrypt_into(&snapshot,&[identity.public_key().id()]).unwrap();
        let (_,_,plan,_)=fixture();
        let mut pending=PendingImport::prepare(plan,vec![]).unwrap();
        pending.entries[0]=pending.entries[0].edited(|value| {
            value["entity"]["credentials"][0]["password"]["value"]="different synthetic password".into(); Ok(())
        }).unwrap();
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert!(pending.duplicates.is_empty());
        let next=block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(next.wallet.entries().len(),2);
    }

    #[test]
    fn inaccessible_entries_are_counted_and_different_entries_are_imported() {
        let (mut snapshot, identity, plan, _) = fixture();
        let other = SoftwareIdentity::from_bytes(&[9;32]).unwrap();
        let public=other.public_key();
        snapshot.wallet=snapshot.wallet.with_participant(public.clone()).unwrap();
        snapshot.signers.insert(public.id(),public.clone());
        let first=PendingImport::prepare(plan,vec![]).unwrap();
        snapshot=first.encrypt_into(&snapshot,&[public.id()]).unwrap();
        let (_,_,plan,_)=fixture();
        let mut pending=PendingImport::prepare(plan,vec![]).unwrap();
        block_on(pending.scan_existing(&snapshot,"head",&identity.public_key(),&identity)).unwrap();
        assert_eq!(pending.unavailable_entries,1);
        assert!(pending.duplicates.is_empty());
        let next=block_on(pending.apply(&snapshot,"head",&[identity.public_key().id()],true,&identity.public_key(),&identity)).unwrap();
        assert_eq!(next.wallet.entries().len(),2);
    }

    #[test]
    fn imported_files_are_encrypted_owned_and_readable_through_the_entry_grant() {
        let (snapshot, identity, plan, source_id) = fixture();
        let bytes = vec![93; attachments::CHUNK_BYTES + 29];
        let pending = PendingImport::prepare(plan, vec![SourceAttachment {
            source_item_id: source_id.clone(), name: Zeroizing::new("backup.bin".into()), bytes: Zeroizing::new(bytes.clone()),
        }, SourceAttachment {
            source_item_id: source_id, name: Zeroizing::new("empty.txt".into()), bytes: Zeroizing::new(vec![]),
        }]).unwrap();
        assert_eq!(pending.file_count, 2);
        assert_eq!(pending.preview(ImportWarnings::default()).unwrap().imported_files, 2);
        assert!(snapshot.wallet.entries().is_empty() && snapshot.attachments.is_empty());
        let next = pending.encrypt_into(&snapshot, &[identity.public_key().id()]).unwrap();
        let entry = next.wallet.entries().values().next().unwrap();
        let payload = block_on(Payload::open(entry, &identity.public_key(), &identity)).unwrap();
        let files = attachments::list(&payload).unwrap();
        assert_eq!(files.len(), 2);
        for file in files {
            let blob = &next.attachments[&payload.entry_id()][&file.blob_id];
            let mut plaintext = Vec::new();
            attachments::decrypt_stream(payload.entry_id(), &file, &mut blob.open().unwrap(), &mut plaintext).unwrap();
            assert_eq!(plaintext, if file.name == "backup.bin" { bytes.as_slice() } else { &[] });
        }
        assert!(pending.encrypt_into(&next, &[identity.public_key().id()]).is_err());
        assert!(pending.encrypt_into(&snapshot, &[]).is_err());
    }

    #[test]
    fn invalid_attachment_owner_or_name_fails_without_publishing_entries() {
        for invalid_owner in [true, false] {
            let (snapshot, _, plan, source_id) = fixture();
            assert!(PendingImport::prepare(plan, vec![SourceAttachment {
                source_item_id: if invalid_owner { "missing".into() } else { source_id },
                name: Zeroizing::new(if invalid_owner { "file.txt" } else { "../file.txt" }.into()),
                bytes: Zeroizing::new(vec![1,2,3]),
            }]).is_err());
            assert!(snapshot.wallet.entries().is_empty() && snapshot.attachments.is_empty());
        }
    }
}


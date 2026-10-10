//! Encrypted KeePass database import (optional `keepass` feature).
//!
//! Uses the Rust keepass library for decryption; no external executable or C
//! cryptographic implementation. Password/key-file input is supplied by the app.
//! KDF work and decompression are performed by the upstream parser: the encrypted
//! input size bound does not bound those costs. Run import off the UI thread.
//! The returned CXF document is plaintext until its import plan is encrypted.

use ::keepass::{
    Database, DatabaseKey,
    db::{EntryRef, GroupId, GroupRef},
};
use serde_json::{Value, json};

use crate::{
    Conversion, ConversionReport, Document, Error, MAX_DOCUMENT_BYTES, Result, WarningKind,
    conversion::{self, field, id},
    json::SecretJson,
};

/// Open a database from a bounded stream. Password and key file are combined when
/// both are present. Hardware challenge-response keys are not handled here.
pub fn from_reader(
    reader: impl std::io::Read,
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Conversion> {
    from_bytes(&conversion::read(reader)?, password, key_file)
}

/// Decrypt a `.kdbx` (or legacy `.kdb` supported by the parser) and convert to CXF.
/// No files are modified and no password is retained by the returned document.
pub fn from_bytes(
    bytes: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Conversion> {
    if bytes.len() > MAX_DOCUMENT_BYTES || key_file.is_some_and(|v| v.len() > MAX_DOCUMENT_BYTES) {
        return Err(Error::SizeLimit);
    }
    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(file) = key_file {
        key = key
            .with_keyfile(&mut std::io::Cursor::new(file))
            .map_err(|_| Error::KeePassUnlock)?;
    }
    let db = Database::parse(bytes, key).map_err(|_| Error::KeePassUnlock)?;
    from_database(&db)
}

/// Convert an already unlocked KeePass database. The caller owns its lifetime.
pub fn from_database(db: &Database) -> Result<Conversion> {
    let mut report = ConversionReport::default();
    let mut items = Vec::new();
    let root = group(
        db.root(),
        db.recycle_bin().map(|g| g.id()),
        &mut items,
        &mut report,
        0,
    )?;
    let roots: Vec<_> = root.into_iter().collect();
    report.items = items.len();
    report.root_collections = roots.len();
    let account = json!({"id":id("keepass-account",&db.root().id().to_string()),"username":"","email":"",
        "items":items,"collections":roots,
        "extensions":[{"name":"kagitaba-keepass-source","meta":serde_json::to_value(&db.meta).map_err(|_|Error::InvalidDocument)?}]});
    Ok(Conversion {
        document: Document::from_value(SecretJson(conversion::export(account, "KeePass")))?,
        report,
    })
}

fn group(
    group: GroupRef<'_>,
    recycle: Option<GroupId>,
    items: &mut Vec<Value>,
    report: &mut ConversionReport,
    depth: usize,
) -> Result<Option<Value>> {
    if depth > 24 {
        return Err(Error::SizeLimit);
    }
    if Some(group.id()) == recycle {
        report.warn(None, WarningKind::Deleted);
        return Ok(None);
    }
    let mut links = Vec::new();
    for entry in group.entries() {
        let item = entry_item(entry, items.len(), report)?;
        links.push(json!({"item":item["id"]}));
        items.push(item);
    }
    let mut children = Vec::new();
    for child in group.groups() {
        if let Some(child) = self::group(child, recycle, items, report, depth + 1)? {
            children.push(child);
        }
    }
    let mut out = json!({"id":id("keepass-group",&group.id().to_string()),"title":group.name,"items":links,
        "extensions":[{"name":"kagitaba-keepass-source","data":serde_json::to_value(&*group).map_err(|_|Error::InvalidDocument)?}]});
    if !children.is_empty() {
        out["subCollections"] = children.into();
    }
    if let Some(notes) = &group.notes {
        out["subtitle"] = notes.clone().into();
    }
    Ok(Some(out))
}

fn entry_item(entry: EntryRef<'_>, index: usize, report: &mut ConversionReport) -> Result<Value> {
    let mut credentials = Vec::new();
    let mut basic = json!({"type":"basic-auth"});
    for (key, value, hidden) in [
        ("username", entry.get_username(), false),
        ("password", entry.get_password(), true),
    ] {
        if let Some(value) = value {
            basic[key] = field(value, hidden);
        }
    }
    credentials.push(basic);
    if let Some(notes) = entry.fields.get("Notes") {
        credentials.push(json!({"type":"note","content":field(notes.get(),notes.is_protected())}));
    }
    if let Some(otp) = entry.get_raw_otp_value().filter(|s| !s.is_empty()) {
        match conversion::totp(otp) {
            Some(otp) => credentials.push(otp),
            None => report.warn(Some(index), WarningKind::OpaqueOtp),
        }
    }
    let mut fields = Vec::new();
    // Sort for stable output independently of the upstream HashMap iteration.
    let mut names: Vec<_> = entry.fields.keys().collect();
    names.sort();
    for name in names {
        let value = &entry.fields[name];
        if value.get().contains("{REF:") || value.get().contains("{S:") {
            report.warn(Some(index), WarningKind::FieldReferences);
        }
        if matches!(
            name.as_str(),
            "Title" | "UserName" | "Password" | "URL" | "Notes" | "otp"
        ) {
            continue;
        }
        let mut mapped = field(value.get(), value.is_protected());
        mapped["label"] = name.clone().into();
        fields.push(mapped);
    }
    if !fields.is_empty() {
        credentials.push(json!({"type":"custom-fields","fields":fields}));
    }
    if entry.attachments().next().is_some() {
        report.warn(Some(index), WarningKind::Attachments);
    }
    if entry
        .history
        .as_ref()
        .is_some_and(|h| !h.get_entries().is_empty())
    {
        report.warn(Some(index), WarningKind::History);
    }
    let protected: Vec<_> = entry
        .fields
        .iter()
        .filter(|(_, v)| v.is_protected())
        .map(|(k, _)| k.clone())
        .collect();
    let mut out = json!({"id":id("keepass-entry",&entry.id().uuid().to_string()),"title":entry.get_title().unwrap_or(""),
        "credentials":credentials,"extensions":[{"name":"kagitaba-keepass-source",
            "data":serde_json::to_value(&*entry).map_err(|_|Error::InvalidDocument)?,"protectedFields":protected}]});
    if !entry.tags.is_empty() {
        out["tags"] = json!(entry.tags);
    }
    let mut urls = Vec::new();
    if let Some(uri) = entry.get_url().filter(|s| !s.is_empty()) {
        if url::Url::parse(uri).is_ok_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
        }) {
            urls.push(uri);
        } else {
            report.warn(Some(index), WarningKind::UriPolicy);
        }
    }
    out["scope"] = json!({"urls":urls,"androidApps":[]});
    for (time, key) in [
        (entry.times.creation, "creationAt"),
        (entry.times.last_modification, "modifiedAt"),
    ] {
        if let Some(time) = time {
            match u64::try_from(time.and_utc().timestamp()) {
                Ok(seconds) => out[key] = seconds.into(),
                Err(_) => report.warn(Some(index), WarningKind::Timestamp),
            }
        }
    }
    Ok(out)
}

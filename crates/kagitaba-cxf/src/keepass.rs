//! Encrypted KeePass database import (optional `keepass` feature).
//!
//! Uses the Rust keepass library for decryption; no external executable or C
//! cryptographic implementation. Password/key-file input is supplied by the app.
//! KDF work and decompression are performed by the upstream parser: the encrypted
//! input size bound does not bound those costs. Run import off the UI thread.
//! The returned CXF document is plaintext until its import plan is encrypted.
//! Active attachment files are extracted separately into zeroizing owners, keyed
//! by the converted item ID (retained as `source.originalId` by import planning).
//! Use `Conversion::into_parts` and application-owned attachment encryption to
//! import these files; JSON alone retains references but never their bytes.
//! Limits: 64 MiB per file, 128 files per item, 256 MiB total retained file bytes.
//! Exceeding a bound fails the entire conversion. Trash and historical-only
//! attachments are not activated. The upstream parser's allocations/KDF remain
//! outside these bounds and do not promise complete zeroization.

mod passkey;

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
    let mut attachments = Vec::new();
    let mut attachment_bytes = 0usize;
    let root = group(
        db.root(),
        db.recycle_bin().map(|g| g.id()),
        &mut items,
        &mut report,
        &mut attachments,
        &mut attachment_bytes,
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
        attachments,
    })
}

fn group(
    group: GroupRef<'_>,
    recycle: Option<GroupId>,
    items: &mut Vec<Value>,
    report: &mut ConversionReport,
    attachments: &mut Vec<crate::SourceAttachment>,
    attachment_bytes: &mut usize,
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
        let mut files: Vec<_> = entry
            .attachments_named()
            .take(crate::attachments::MAX_ATTACHMENTS + 1)
            .collect();
        if files.len() > crate::attachments::MAX_ATTACHMENTS {
            return Err(Error::SizeLimit);
        }
        files.sort_by(|a, b| a.0.cmp(b.0));
        let source_item_id = id("keepass-entry", &entry.id().uuid().to_string())
            .as_str()
            .ok_or(Error::InvalidDocument)?
            .to_owned();
        for (name, file) in files {
            let bytes = file.data.get();
            // The parser owns its input allocations; bound our retained copies too.
            *attachment_bytes = attachment_bytes
                .checked_add(bytes.len())
                .ok_or(Error::SizeLimit)?;
            if bytes.len() > crate::attachments::MAX_FILE_BYTES
                || *attachment_bytes > 256 * 1024 * 1024
            {
                return Err(Error::SizeLimit);
            }
            attachments.push(crate::SourceAttachment {
                source_item_id: source_item_id.clone(),
                name: zeroize::Zeroizing::new(name.to_owned()),
                bytes: zeroize::Zeroizing::new(bytes.clone()),
            });
        }
        let item = entry_item(entry, items.len(), report)?;
        links.push(json!({"item":item["id"]}));
        items.push(item);
    }
    let mut children = Vec::new();
    for child in group.groups() {
        if let Some(child) = self::group(
            child,
            recycle,
            items,
            report,
            attachments,
            attachment_bytes,
            depth + 1,
        )? {
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
    let time_otp_present = entry.fields.keys().any(|name| name.starts_with("TimeOtp-"));
    let mapped_time_otp = time_otp_present.then(|| time_otp(&entry)).flatten();
    let time_otp_mapped = mapped_time_otp.is_some();
    if let Some(otp) = mapped_time_otp {
        if !credentials.iter().any(|existing| existing["type"] == "totp"
            && ["secret", "period", "digits", "algorithm"].iter().all(|key| existing[*key] == otp[*key])) {
            credentials.push(otp);
        }
    } else if time_otp_present {
        report.warn(Some(index), WarningKind::OpaqueOtp);
    }
    let mapped_passkey = passkey::convert(&entry);
    let passkey_mapped = mapped_passkey.is_ok();
    match mapped_passkey {
        Ok(credential) => credentials.push(credential),
        Err(detail) if passkey::present(&entry) => report.warn_detail(Some(index), WarningKind::OpaquePasskey, detail),
        Err(_) => (),
    }
    let (urls, mapped_urls) = additional_urls(&entry, index, report);
    let mut fields = Vec::new();
    // Sort for stable output independently of the upstream HashMap iteration.
    let mut names: Vec<_> = entry.fields.keys().collect();
    names.sort();
    for name in names {
        let value = &entry.fields[name];
        if passkey_mapped && passkey::FIELDS.contains(&name.as_str()) { continue; }
        if value.get().contains("{REF:") || value.get().contains("{S:") {
            report.warn(Some(index), WarningKind::FieldReferences);
        }
        if mapped_urls.contains(name.as_str()) { continue; }
        if time_otp_mapped && TIME_OTP_FIELDS.contains(&name.as_str()) { continue; }
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
    let mut protected: Vec<_> = entry
        .fields
        .iter()
        .filter(|(_, v)| v.is_protected())
        .map(|(k, _)| k.clone())
        .collect();
    protected.sort();
    let mut out = json!({"id":id("keepass-entry",&entry.id().uuid().to_string()),"title":entry.get_title().unwrap_or(""),
        "credentials":credentials,"extensions":[{"name":"kagitaba-keepass-source",
            "data":serde_json::to_value(&*entry).map_err(|_|Error::InvalidDocument)?,"protectedFields":protected}]});
    if !entry.tags.is_empty() {
        out["tags"] = json!(entry.tags);
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

// KeePass built-in {TIMEOTP} fields, documented at
// https://keepass.info/help/base/placeholders.html#otp
const TIME_OTP_FIELDS: &[&str] = &[
    "TimeOtp-Secret", "TimeOtp-Secret-Hex", "TimeOtp-Secret-Base32", "TimeOtp-Secret-Base64",
    "TimeOtp-Length", "TimeOtp-Period", "TimeOtp-Algorithm",
];

fn time_otp(entry: &EntryRef<'_>) -> Option<Value> {
    use zeroize::Zeroizing;
    if entry.fields.keys().any(|name| name.starts_with("TimeOtp-") && !TIME_OTP_FIELDS.contains(&name.as_str())) {
        return None;
    }
    let secrets: Vec<_> = TIME_OTP_FIELDS[..4].iter()
        .filter_map(|name| entry.fields.get(*name).map(|value| (*name, value.get())))
        .collect();
    let [(name, secret)] = secrets.as_slice() else { return None; };
    // References are deliberately not evaluated, including for UTF-8 secrets.
    if secret.contains("{REF:") || secret.contains("{S:") { return None; }
    let mut otp = SecretJson(if *name == "TimeOtp-Secret-Base32" {
        // This field is a seed, never an otpauth URI.
        if secret.starts_with("otpauth:") { return None; }
        conversion::totp(secret)?
    } else {
        let bytes = Zeroizing::new(match *name {
            "TimeOtp-Secret" => secret.as_bytes().to_vec(),
            "TimeOtp-Secret-Hex" => data_encoding::HEXLOWER_PERMISSIVE.decode(secret.as_bytes()).ok()?,
            "TimeOtp-Secret-Base64" => data_encoding::BASE64.decode(secret.as_bytes()).ok()?,
            _ => return None,
        });
        if bytes.is_empty() { return None; }
        let seed = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&bytes));
        conversion::totp(&seed)?
    });
    for (field, key, default) in [("TimeOtp-Length", "digits", 6), ("TimeOtp-Period", "period", 30)] {
        let number = entry.fields.get(field).map(|value| value.get().parse::<u64>()).transpose().ok()?.unwrap_or(default);
        if number == 0 || (key == "digits" && !(6..=8).contains(&number)) { return None; }
        otp.0[key] = number.into();
    }
    otp.0["algorithm"] = match entry.fields.get("TimeOtp-Algorithm").map(|value| value.get().as_str()) {
        None | Some("HMAC-SHA-1") => "sha1",
        Some("HMAC-SHA-256") => "sha256",
        Some("HMAC-SHA-512") => "sha512",
        _ => return None,
    }.into();
    Some(std::mem::take(&mut otp.0))
}

fn additional_urls(entry: &EntryRef<'_>, index: usize, report: &mut ConversionReport)
    -> (Vec<String>, std::collections::BTreeSet<String>) {
    let mut urls = Vec::new();
    let mut mapped = std::collections::BTreeSet::new();
    let mut names: Vec<_> = entry.fields.keys().filter(|name| {
        name.as_str() == "URL" || name.strip_prefix("KP2A_URL_")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
    }).collect();
    names.sort_by_key(|name| (name.as_str() != "URL", name.as_str()));
    for name in names {
        let uri = entry.fields[name].get();
        if uri.is_empty() { continue; }
        let field = Some(if name.as_str() == "URL" { "URL" } else { "KP2A_URL_*" });
        let detail = if uri.contains('{') || uri.contains('}') {
            Some(crate::WarningDetail {field, reason:"The URL contains an unresolved placeholder or field reference.", action:"Inspect the retained source field and enter a literal destination URL if autofill is wanted. No reference is resolved automatically."})
        } else if uri.starts_with("//") || uri.starts_with("regex:") || uri.contains('*') {
            Some(crate::WarningDetail {field, reason:"The URL contains a pattern rather than a literal destination.", action:"Keep the pattern in source data; add explicit destination URLs for Kagitaba autofill. Pattern matching is not implemented."})
        } else if uri.chars().any(char::is_control) || uri.trim() != uri {
            Some(crate::WarningDetail {field, reason:"The URL contains control characters or surrounding whitespace.", action:"Review the preserved value and supply a clean literal URL if autofill is wanted."})
        } else if url::Url::parse(uri).is_ok_and(|url| !url.username().is_empty() || url.password().is_some()) {
            Some(crate::WarningDetail {field, reason:"The URL embeds a username or password.", action:"The original is preserved. Use separate login fields and a URL without embedded credentials for autofill."})
        } else { None };
        if let Some(detail) = detail { report.warn_detail(Some(index), WarningKind::UriPolicy, detail); }
        else {
            // A scope URL is preserved catalogue data, not authorization to fill.
            // Providers independently validate supported origins and schemes.
            if !urls.contains(uri) { urls.push(uri.to_owned()); }
            mapped.insert(name.clone());
        }
    }
    (urls, mapped)
}

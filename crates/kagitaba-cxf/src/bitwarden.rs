//! Bitwarden **unencrypted JSON** exports. CSV and encrypted exports are rejected.
//! Original item data are retained in CXF extensions, including fields whose
//! semantics cannot be translated. The returned document is plaintext until the
//! caller encrypts its import plan. Review the conversion report before use.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    Conversion, ConversionReport, Document, Error, MAX_DOCUMENT_BYTES, Result, WarningKind,
    conversion::{self, field, id, list, optional_text, text},
    json::{self, SecretJson},
};

/// Read a bounded Bitwarden JSON file or stream, without choosing a path.
pub fn from_reader(reader: impl std::io::Read) -> Result<Conversion> {
    from_json(&conversion::read(reader)?)
}

/// Convert an unencrypted personal or organisation JSON export to CXF.
/// Unknown item kinds are retained as opaque source credentials, with warnings.
pub fn from_json(bytes: &[u8]) -> Result<Conversion> {
    let raw = json::parse(
        bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes),
        MAX_DOCUMENT_BYTES,
    )?;
    match raw.0.get("encrypted") {
        Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Err(Error::EncryptedExport),
        _ => return Err(Error::InvalidDocument),
    }
    let source_items = json::array(&raw.0, "items")?;
    let mut report = ConversionReport::default();
    let mut collections = BTreeMap::new();
    for (key, namespace) in [
        ("folders", "bitwarden-folder"),
        ("collections", "bitwarden-collection"),
    ] {
        for source in list(&raw.0, key)? {
            let original = text(source, "id")?;
            if original.is_empty() {
                return Err(Error::InvalidDocument);
            }
            let collection = json!({"id":id(namespace,original),"title":text(source,"name")?,"items":[],
                "extensions":[{"name":"kagitaba-bitwarden-source","data":source}]});
            if collections
                .insert((key, original.to_owned()), collection)
                .is_some()
            {
                return Err(Error::DuplicateId);
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();
    for (index, source) in source_items.iter().enumerate() {
        let original = text(source, "id")?;
        if original.is_empty() {
            return Err(Error::InvalidDocument);
        }
        if !seen.insert(original) {
            return Err(Error::DuplicateId);
        }
        if optional_text(source, "deletedDate")?.is_some() {
            report.warn(Some(index), WarningKind::Deleted);
            continue;
        }
        let mut item = SecretJson(
            json!({"id":id("bitwarden-item",original),"title":text(source,"name")?,
            "credentials":[],"extensions":[{"name":"kagitaba-bitwarden-source","data":source}]}),
        );
        if let Some(favorite) = source.get("favorite") {
            if !favorite.is_boolean() {
                return Err(Error::InvalidDocument);
            }
            item.0["favorite"] = favorite.clone();
        }
        for (key, target) in [
            ("creationDate", "creationAt"),
            ("revisionDate", "modifiedAt"),
        ] {
            conversion::timestamp(&mut item.0, source, key, target, index, &mut report)?;
        }
        let mut credentials = Vec::new();
        match source["type"].as_u64().ok_or(Error::InvalidDocument)? {
            1 => login(
                source
                    .get("login")
                    .filter(|v| v.is_object())
                    .ok_or(Error::InvalidDocument)?,
                &mut item.0,
                &mut credentials,
                index,
                &mut report,
            )?,
            2 => {}
            _ => {
                credentials.push(json!({"type":"kagitaba-bitwarden-item","data":source}));
                report.warn(Some(index), WarningKind::OpaqueItem);
            }
        }
        if let Some(notes) = optional_text(source, "notes")? {
            credentials.push(json!({"type":"note","content":field(notes,false)}));
        }
        let mut fields = Vec::new();
        for custom in list(source, "fields")? {
            let value = optional_text(custom, "value")?;
            let kind = custom["type"].as_u64().ok_or(Error::InvalidDocument)?;
            match (kind, value) {
                (0 | 1, Some(value)) => {
                    let mut mapped = field(value, kind == 1);
                    if let Some(name) = optional_text(custom, "name")? {
                        mapped["label"] = name.into();
                    }
                    fields.push(mapped);
                }
                (2, Some("true" | "false")) => {
                    let mut mapped = json!({"fieldType":"boolean","value":value.unwrap()});
                    if let Some(name) = optional_text(custom, "name")? {
                        mapped["label"] = name.into();
                    }
                    fields.push(mapped);
                }
                _ => report.warn(Some(index), WarningKind::OpaqueField),
            }
        }
        if !fields.is_empty() {
            credentials.push(json!({"type":"custom-fields","fields":fields}));
        }
        item.0["credentials"] = credentials.into();
        if source
            .get("reprompt")
            .is_some_and(|v| v != 0 && !v.is_null())
        {
            report.warn(Some(index), WarningKind::Reprompt);
        }
        if !list(source, "passwordHistory")?.is_empty() {
            report.warn(Some(index), WarningKind::History);
        }
        if !list(source, "attachments")?.is_empty() {
            report.warn(Some(index), WarningKind::Attachments);
        }
        let mut memberships = Vec::new();
        if let Some(folder) = optional_text(source, "folderId")? {
            memberships.push(("folders", folder));
        }
        for collection in list(source, "collectionIds")? {
            memberships.push((
                "collections",
                collection.as_str().ok_or(Error::InvalidDocument)?,
            ));
        }
        let mut linked = BTreeSet::new();
        for membership in memberships {
            if !linked.insert(membership) {
                continue;
            }
            if let Some(collection) = collections.get_mut(&(membership.0, membership.1.to_owned()))
            {
                collection["items"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"item":item.0["id"]}));
            } else {
                report.warn(Some(index), WarningKind::MissingCollection);
            }
        }
        items.push(item.0.take());
    }
    report.items = items.len();
    report.root_collections = collections.len();
    let metadata: serde_json::Map<String, Value> = raw
        .0
        .as_object()
        .ok_or(Error::InvalidDocument)?
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "items" | "folders" | "collections"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let account = json!({"id":id("bitwarden-account","export"),"username":"","email":"",
        "items":items,"collections":collections.into_values().collect::<Vec<_>>(),
        "extensions":[{"name":"kagitaba-bitwarden-source","data":metadata}]});
    Ok(Conversion {
        document: Document::from_value(SecretJson(conversion::export(account, "Bitwarden")))?,
        report,
    })
}

fn login(
    login: &Value,
    item: &mut Value,
    credentials: &mut Vec<Value>,
    index: usize,
    report: &mut ConversionReport,
) -> Result<()> {
    let mut basic = json!({"type":"basic-auth"});
    for (key, hidden) in [("username", false), ("password", true)] {
        if let Some(value) = optional_text(login, key)? {
            basic[key] = field(value, hidden);
        }
    }
    credentials.push(basic);
    let mut urls = Vec::new();
    let mut apps = Vec::new();
    for uri in list(login, "uris")? {
        let Some(value) = optional_text(uri, "uri")?.filter(|s| !s.is_empty()) else {
            continue;
        };
        // Do not silently broaden exact/host/prefix/regex/never matching into a
        // generic CXF scope. Keep original policy in the source extension.
        if uri.get("match").is_some_and(|v| !v.is_null()) {
            report.warn(Some(index), WarningKind::UriPolicy);
            continue;
        }
        if let Some(bundle) = value
            .strip_prefix("androidapp://")
            .filter(|s| !s.is_empty())
        {
            apps.push(json!({"bundleId":bundle}));
        } else if let Ok(url) = url::Url::parse(value) {
            if matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
            {
                urls.push(Value::String(value.into()));
            } else {
                report.warn(Some(index), WarningKind::UriPolicy);
            }
        } else {
            report.warn(Some(index), WarningKind::UriPolicy);
        }
    }
    item["scope"] = json!({"urls":urls,"androidApps":apps});
    if let Some(value) = optional_text(login, "totp")?.filter(|s| !s.is_empty()) {
        match conversion::totp(value) {
            Some(otp) => credentials.push(otp),
            None => report.warn(Some(index), WarningKind::OpaqueOtp),
        }
    }
    for source in list(login, "fido2Credentials")? {
        match passkey(source) {
            Some(key) => credentials.push(key),
            None => report.warn(Some(index), WarningKind::OpaquePasskey),
        }
    }
    Ok(())
}

fn b64(s: &str) -> Option<Vec<u8>> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .or_else(|_| data_encoding::BASE64URL.decode(s.as_bytes()))
        .ok()
}
fn passkey(value: &Value) -> Option<Value> {
    if value["counter"] != "0" && value["counter"] != 0 {
        return None;
    }
    if value["discoverable"] != "true" && value["discoverable"] != true {
        return None;
    }
    if value["keyType"] != "public-key" {
        return None;
    }
    let source_id = value["credentialId"].as_str()?;
    let credential_id = if let Some(encoded) = source_id.strip_prefix("b64.") {
        b64(encoded)?
    } else {
        uuid::Uuid::parse_str(source_id).ok()?.as_bytes().to_vec()
    };
    if credential_id.is_empty() {
        return None;
    }
    let handle = b64(value["userHandle"].as_str()?)?;
    if handle.is_empty() || handle.len() > 64 {
        return None;
    }
    let key = Zeroizing::new(b64(value["keyValue"].as_str()?)?);
    pkcs8::PrivateKeyInfoRef::try_from(key.as_slice()).ok()?;
    let rp = value["rpId"].as_str()?;
    if rp.is_empty() {
        return None;
    }
    Some(
        json!({"type":"passkey","credentialId":data_encoding::BASE64URL_NOPAD.encode(&credential_id),
        "rpId":rp,"username":value["userName"].as_str().unwrap_or(""),
        "userDisplayName":value["userDisplayName"].as_str().unwrap_or(""),
        "userHandle":data_encoding::BASE64URL_NOPAD.encode(&handle),"key":data_encoding::BASE64URL_NOPAD.encode(&key)}),
    )
}

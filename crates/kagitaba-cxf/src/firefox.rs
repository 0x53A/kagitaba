//! Firefox plaintext password CSV import. All columns remain encrypted provenance.
//! Scope is active only for HTTP(S) origins with no HTTP realm and an empty or
//! same-origin form action. Other matching policies remain source data with a
//! warning. The caller must encrypt the returned import plan before persistence.
//! Retained JSON is wiped on drop; CSV parser temporary allocations are not all
//! zeroized. No filesystem, network or logging operations occur here.
use crate::{
    Conversion, ConversionReport, Document, Error, MAX_DOCUMENT_BYTES, Result, WarningKind,
    conversion::{self, field, id},
    json::SecretJson,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Read at most 32 MiB from a plaintext Firefox CSV stream.
pub fn from_reader(reader: impl std::io::Read) -> Result<Conversion> {
    from_bytes(&conversion::read(reader)?)
}

/// Convert Firefox CSV bytes, preserving unknown columns and repeated rows.
pub fn from_bytes(bytes: &[u8]) -> Result<Conversion> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::SizeLimit);
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidDocument)?;
    strict_quotes(bytes)?;
    let mut reader = csv::ReaderBuilder::new().flexible(false).from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|_| Error::InvalidDocument)?
        .clone();
    let mut seen = BTreeSet::new();
    if headers.is_empty()
        || headers.iter().any(|h| h.is_empty() || !seen.insert(h))
        || ["url", "username", "password"]
            .iter()
            .any(|h| !seen.contains(h))
    {
        return Err(Error::InvalidDocument);
    }
    let mut report = ConversionReport::default();
    let mut items = SecretJson(json!([]));
    for (index, record) in reader.records().enumerate() {
        let record = record.map_err(|_| Error::InvalidDocument)?;
        if record.len() != headers.len() {
            return Err(Error::InvalidDocument);
        }
        let source = SecretJson(Value::Object(
            headers
                .iter()
                .zip(record.iter())
                .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
                .collect(),
        ));
        let get = |key: &str| source.0[key].as_str().unwrap_or("");
        let origin = get("url");
        // Ordinal distinguishes duplicate GUIDs and identical repeated rows.
        let mut item = SecretJson(json!({
            "id":id("firefox-csv-row", &index.to_string()), "title":origin,
            "credentials":[{"type":"basic-auth","username":field(get("username"),false),"password":field(get("password"),true)}],
            "extensions":[{"name":"kagitaba-firefox-source","data":source.0}]
        }));
        let scope = active_origin(origin, get("httpRealm"), get("formActionOrigin"));
        if let Some(url) = scope {
            item.0["scope"] = json!({"urls":[url],"androidApps":[]});
        } else {
            report.warn(Some(index), WarningKind::UriPolicy);
        }
        for (key, target) in [
            ("timeCreated", "creationAt"),
            ("timePasswordChanged", "modifiedAt"),
        ] {
            let text = get(key);
            if text.is_empty() {
                continue;
            }
            if text.bytes().all(|b| b.is_ascii_digit())
                && let Ok(millis) = text.parse::<u64>()
            {
                item.0[target] = (millis / 1000).into();
                continue;
            }
            report.warn(Some(index), WarningKind::Timestamp);
        }
        items
            .0
            .as_array_mut()
            .ok_or(Error::InvalidDocument)?
            .push(item.0.take());
    }
    report.items = items.0.as_array().ok_or(Error::InvalidDocument)?.len();
    let account = json!({"id":id("firefox-csv-account","export"),"username":"","email":"", "items":items.0.take(),"collections":[]});
    Ok(Conversion {
        document: Document::from_value(SecretJson(conversion::export(account, "Firefox")))?,
        report,
        attachments: Vec::new(),
    })
}

fn origin_url(value: &str) -> Option<url::Url> {
    if value.trim() != value {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url)
}
fn active_origin<'a>(origin: &'a str, realm: &str, action: &str) -> Option<&'a str> {
    if !realm.is_empty() {
        return None;
    }
    let url = origin_url(origin)?;
    if !action.is_empty() && origin_url(action)?.origin() != url.origin() {
        return None;
    }
    Some(origin)
}

// csv deliberately accepts some malformed quote forms. Reject these before
// parsing, without trimming or altering any field contents (including CR/LF).
fn strict_quotes(bytes: &[u8]) -> Result<()> {
    enum State {
        Start,
        Bare,
        Quoted,
        Closed,
    }
    let mut state = State::Start;
    for byte in bytes {
        state = match (state, *byte) {
            (State::Start, b'"') => State::Quoted,
            (State::Start | State::Bare | State::Closed, b',' | b'\r' | b'\n') => State::Start,
            (State::Bare, b'"') => return Err(Error::InvalidDocument),
            (State::Start | State::Bare, _) => State::Bare,
            (State::Quoted, b'"') => State::Closed,
            (State::Quoted, _) => State::Quoted,
            (State::Closed, b'"') => State::Quoted,
            (State::Closed, _) => return Err(Error::InvalidDocument),
        };
    }
    if matches!(state, State::Quoted) {
        Err(Error::InvalidDocument)
    } else {
        Ok(())
    }
}

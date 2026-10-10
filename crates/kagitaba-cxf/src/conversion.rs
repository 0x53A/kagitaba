use std::{collections::BTreeMap, io::Read};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Document, Error, MAX_DOCUMENT_BYTES, Result};

/// A converted export ready for the existing CXF planning/encryption pipeline.
pub struct Conversion {
    pub(crate) document: Document,
    pub(crate) report: ConversionReport,
}
impl Conversion {
    /// Borrow the CXF document; its items include preserved source metadata.
    pub fn document(&self) -> &Document {
        &self.document
    }
    /// Review conversion limitations before saving the import.
    pub fn report(&self) -> &ConversionReport {
        &self.report
    }
    /// Take ownership of the CXF document.
    pub fn into_document(self) -> Document {
        self.document
    }
}

/// Counts and non-secret warnings from translating another manager's format.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConversionReport {
    /// Items produced, including opaque unsupported items.
    pub items: usize,
    /// Root collections produced.
    pub root_collections: usize,
    /// Information that requires review; no credential values are included.
    pub warnings: Vec<ImportWarning>,
}
/// One conversion limitation.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportWarning {
    /// Zero-based source item index; None denotes database/group-level metadata.
    pub item_index: Option<usize>,
    /// The category of the limitation.
    pub kind: WarningKind,
}
/// Conversion limitations, including excluded data and preserved inactive features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    /// Item type has no implemented native mapping; source data are preserved.
    OpaqueItem,
    /// Unsupported, malformed, or nonstandard OTP retained in source metadata.
    OpaqueOtp,
    /// Passkey cannot safely be represented as a CXF passkey.
    OpaquePasskey,
    /// Unsupported or linked custom field retained in source metadata.
    OpaqueField,
    /// URI matching semantics cannot be preserved as standard CXF scope.
    UriPolicy,
    /// A referenced folder or collection is absent from the export.
    MissingCollection,
    /// Source requires an additional unlock prompt; the app must implement it.
    Reprompt,
    /// Attachments are not imported by this converter.
    Attachments,
    /// Entry history is preserved as source metadata, not active credentials.
    History,
    /// Source timestamps could not be represented as CXF timestamps.
    Timestamp,
    /// Trash/recycle-bin records were excluded from active import.
    Deleted,
    /// KeePass field references/placeholders remain literal and need resolution.
    FieldReferences,
}
impl ConversionReport {
    pub(crate) fn warn(&mut self, item_index: Option<usize>, kind: WarningKind) {
        self.warnings.push(ImportWarning { item_index, kind });
    }
}

pub(crate) fn read(reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Read)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::SizeLimit);
    }
    Ok(bytes)
}
pub(crate) fn id(namespace: &str, original: &str) -> Value {
    let mut hash = Sha256::new();
    hash.update(namespace.as_bytes());
    hash.update([0]);
    hash.update(original.as_bytes());
    data_encoding::BASE64URL_NOPAD
        .encode(&hash.finalize())
        .into()
}
pub(crate) fn field(value: &str, concealed: bool) -> Value {
    json!({"fieldType": if concealed {"concealed-string"} else {"string"}, "value":value})
}
pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidDocument)
}
pub(crate) fn optional_text<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(Error::InvalidDocument),
    }
}
pub(crate) fn list<'a>(v: &'a Value, key: &str) -> Result<&'a [Value]> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        _ => Err(Error::InvalidDocument),
    }
}
pub(crate) fn timestamp(
    item: &mut Value,
    source: &Value,
    key: &str,
    target: &str,
    index: usize,
    report: &mut ConversionReport,
) -> Result<()> {
    if let Some(s) = optional_text(source, key)? {
        if let Ok(time) = chrono::DateTime::parse_from_rfc3339(s)
            && let Ok(seconds) = u64::try_from(time.timestamp())
        {
            item[target] = seconds.into();
            return Ok(());
        }
        report.warn(Some(index), WarningKind::Timestamp);
    }
    Ok(())
}
pub(crate) fn export(account: Value, provider: &str) -> Value {
    json!({"version":{"major":1,"minor":0},"exporterRpId":"kagitaba.invalid",
        "exporterDisplayName":format!("Kagitaba {provider} import"),"timestamp":0,"accounts":[account]})
}

/// Translate standard otpauth TOTP URIs or bare base32 seeds. Unknown schemes,
/// algorithms and behavior-changing parameters remain opaque at the call site.
pub(crate) fn totp(input: &str) -> Option<Value> {
    let mut result = json!({"type":"totp","period":30,"digits":6,"algorithm":"sha1"});
    let seed;
    if input.starts_with("otpauth:") {
        let url = url::Url::parse(input).ok()?;
        if url.host_str()? != "totp"
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
        {
            return None;
        }
        let mut params = BTreeMap::new();
        for (key, value) in url.query_pairs() {
            if params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return None;
            }
        }
        if params.keys().any(|k| {
            !matches!(
                k.as_str(),
                "secret" | "issuer" | "algorithm" | "digits" | "period" | "image"
            )
        }) {
            return None;
        }
        seed = Zeroizing::new(params.get("secret")?.clone());
        for (name, default) in [("period", 30u16), ("digits", 6u16)] {
            let n = params
                .get(name)
                .map(|s| s.parse::<u16>())
                .transpose()
                .ok()?
                .unwrap_or(default);
            if n == 0 || (name == "digits" && !matches!(n, 6..=8)) {
                return None;
            }
            result[name] = n.into();
        }
        let algorithm = params
            .get("algorithm")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or("sha1".into());
        if !matches!(algorithm.as_str(), "sha1" | "sha256" | "sha512") {
            return None;
        }
        result["algorithm"] = algorithm.into();
        let label = percent_encoding::percent_decode_str(url.path().strip_prefix('/')?)
            .decode_utf8()
            .ok()?;
        let (label_issuer, username) = label
            .split_once(':')
            .map(|(a, b)| (Some(a), b))
            .unwrap_or((None, &label));
        if !username.is_empty() {
            result["username"] = username.into();
        }
        if let Some(issuer) = params.get("issuer").map(String::as_str).or(label_issuer) {
            result["issuer"] = issuer.into();
        }
    } else {
        seed = Zeroizing::new(input.to_owned());
    }
    let normalized = Zeroizing::new(
        seed.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>()
            .to_ascii_uppercase(),
    );
    let bytes = data_encoding::BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(normalized.as_bytes()))
        .ok()
        .map(Zeroizing::new)?;
    if bytes.is_empty() {
        return None;
    }
    result["secret"] = data_encoding::BASE32_NOPAD.encode(&bytes).into();
    Some(result)
}

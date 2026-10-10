use std::{collections::BTreeSet, io::Read};

use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    json::{self, SecretJson},
    model,
};

/// Maximum plaintext exchange size (32 MiB). Individual encrypted entries have
/// the core's smaller payload limit. JSON nesting is also bounded by the parser.
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

/// Validated CXF document retaining unknown fields and credentials.
/// No Debug/Clone implementation: this object owns plaintext credentials.
pub struct Document(pub(crate) SecretJson);

impl Document {
    pub(crate) fn from_value(value: SecretJson) -> Result<Self> {
        // Conversion adds wrappers around source data. Apply the same depth and
        // size limits as a subsequent read of the resulting document.
        Self::from_json(&json::encode(&value.0)?)
    }
    /// Read a plaintext CXF file/stream with a hard byte bound. The caller opens
    /// the file; this application library neither chooses nor remembers paths.
    pub fn from_reader(reader: impl std::io::Read) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        reader
            .take(MAX_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Read)?;
        Self::from_json(&bytes)
    }

    /// Parse a complete plaintext CXF JSON export, independent of file extension.
    /// A CXP ExportResponse returns `CxpSessionRequired`, never a partial import.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw = json::parse(bytes, MAX_DOCUMENT_BYTES)?;
        if raw.0.get("hpke").is_some() && raw.0.get("payload").is_some() {
            return Err(Error::CxpSessionRequired);
        }
        validate(&raw.0)?;
        Ok(Self(raw))
    }

    /// Full preserved JSON, including unknown fields. Contains secrets.
    pub fn as_json(&self) -> &Value {
        &self.0.0
    }

    /// Serialize without dropping unsupported data. Clears output on drop.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        json::encode(&self.0.0)
    }

    /// Create an owned upstream typed view. This explicitly copies secrets;
    /// upstream types implement Debug and do not zeroize on drop. Never log it.
    /// Use the preserved JSON, not this view, for lossless reserialization.
    pub fn typed(&self) -> Result<model::Header<Value>> {
        model::Header::deserialize(&self.0.0).map_err(|_| Error::InvalidDocument)
    }
}

fn validate(value: &Value) -> Result<()> {
    let major = value["version"]["major"]
        .as_u64()
        .ok_or(Error::InvalidDocument)?;
    if major != 1 {
        return Err(Error::UnsupportedVersion);
    }
    // Library models cover all current credential kinds, plus unknown kinds.
    model::Header::<Value>::deserialize(value).map_err(|_| Error::InvalidDocument)?;
    let mut accounts = BTreeSet::new();
    for account in json::array(value, "accounts")? {
        json::register(account, &mut accounts)?;
        let mut ids = BTreeSet::from([json::id(&account["id"])?]);
        for item in json::array(account, "items")? {
            json::register(item, &mut ids)?;
            validate_item(item)?;
        }
        for collection in json::array(account, "collections")? {
            validate_collection(collection, &mut ids, 0)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_link(value: &Value) -> Result<()> {
    model::LinkedItem::deserialize(value).map_err(|_| Error::InvalidDocument)?;
    json::id(&value["item"])?;
    if let Some(account) = value.get("account") {
        json::id(account)?;
    }
    Ok(())
}

pub(crate) fn validate_item(value: &Value) -> Result<()> {
    model::Item::<Value>::deserialize(value).map_err(|_| Error::InvalidDocument)?;
    json::id(&value["id"])?;
    for credential in json::array(value, "credentials")? {
        // Parse these directly: serde's forward-compatible Unknown fallback must
        // not turn malformed core credential types into apparently usable data.
        match credential["type"].as_str().ok_or(Error::InvalidDocument)? {
            "basic-auth" => {
                model::BasicAuthCredential::<Value>::deserialize(credential)
                    .map_err(|_| Error::InvalidDocument)?;
            }
            "passkey" => {
                model::PasskeyCredential::deserialize(credential)
                    .map_err(|_| Error::InvalidDocument)?;
                let key = credential["key"].as_str().ok_or(Error::InvalidDocument)?;
                let der = data_encoding::BASE64URL_NOPAD
                    .decode(key.as_bytes())
                    .or_else(|_| data_encoding::BASE64URL.decode(key.as_bytes()))
                    .map(Zeroizing::new)
                    .map_err(|_| Error::InvalidDocument)?;
                pkcs8::PrivateKeyInfoRef::try_from(der.as_slice())
                    .map_err(|_| Error::InvalidDocument)?;
            }
            "totp" => {
                model::TotpCredential::deserialize(credential)
                    .map_err(|_| Error::InvalidDocument)?;
                let s = credential["secret"]
                    .as_str()
                    .ok_or(Error::InvalidDocument)?;
                let decoded = data_encoding::BASE32_NOPAD
                    .decode(s.as_bytes())
                    .or_else(|_| data_encoding::BASE32.decode(s.as_bytes()))
                    .map(Zeroizing::new)
                    .map_err(|_| Error::InvalidDocument)?;
                if decoded.is_empty()
                    || credential["period"].as_u64() == Some(0)
                    || credential["digits"].as_u64() == Some(0)
                {
                    return Err(Error::InvalidDocument);
                }
            }
            "note" => {
                model::NoteCredential::<Value>::deserialize(credential)
                    .map_err(|_| Error::InvalidDocument)?;
            }
            "item-reference" => validate_link(&credential["reference"])?,
            // Other/unknown credential types are retained, not activated.
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn validate_collection(
    value: &Value,
    ids: &mut BTreeSet<Vec<u8>>,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        return Err(Error::SizeLimit);
    }
    model::Collection::<Value>::deserialize(value).map_err(|_| Error::InvalidDocument)?;
    json::register(value, ids)?;
    for link in json::array(value, "items")? {
        validate_link(link)?;
    }
    for child in json::optional_array(value, "subCollections")? {
        validate_collection(child, ids, depth + 1)?;
    }
    Ok(())
}

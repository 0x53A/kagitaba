use std::{collections::BTreeSet, fmt};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, value::RawValue};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

// Retained plaintext strings are cleared on drop. This does not promise to clear
// serde's temporary allocations or caller-owned typed views.
pub(crate) struct SecretJson(pub Value);

impl Drop for SecretJson {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => {
            for (mut key, mut value) in std::mem::take(m) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        _ => {}
    }
}

pub(crate) fn parse(bytes: &[u8], max: usize) -> Result<SecretJson> {
    if bytes.len() > max {
        return Err(Error::SizeLimit);
    }
    let raw: &RawValue = serde_json::from_slice(bytes).map_err(|_| Error::InvalidDocument)?;
    parse_raw(raw, 0)
}

// Explicit container parsing rejects duplicate names everywhere. Raw scalar
// parsing preserves arbitrary-precision numbers without confusing literal JSON
// member names with serde_json's internal arbitrary-precision number sentinel.
fn parse_raw(raw: &RawValue, depth: usize) -> Result<SecretJson> {
    if depth > 64 {
        return Err(Error::SizeLimit);
    }
    let mut de = serde_json::Deserializer::from_str(raw.get());
    let visitor = Containers { depth };
    match raw.get().as_bytes().first() {
        Some(b'{') => de
            .deserialize_map(visitor)
            .map_err(|_| Error::InvalidDocument),
        Some(b'[') => de
            .deserialize_seq(visitor)
            .map_err(|_| Error::InvalidDocument),
        _ => serde_json::from_str(raw.get())
            .map(SecretJson)
            .map_err(|_| Error::InvalidDocument),
    }
}

struct Containers {
    depth: usize,
}

impl<'de> Visitor<'de> for Containers {
    type Value = SecretJson;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique object members")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
        let mut values = SecretJson(Value::Array(Vec::new()));
        while let Some(raw) = a.next_element::<&RawValue>()? {
            let mut value = parse_raw(raw, self.depth + 1).map_err(de::Error::custom)?;
            values.0.as_array_mut().unwrap().push(value.0.take());
        }
        Ok(values)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
        let mut values = SecretJson(Value::Object(Map::new()));
        while let Some(key) = a.next_key::<String>()? {
            let map = values.0.as_object_mut().unwrap();
            if map.contains_key(&key) {
                return Err(de::Error::custom("duplicate member"));
            }
            let raw: &RawValue = a.next_value()?;
            let mut value = parse_raw(raw, self.depth + 1).map_err(de::Error::custom)?;
            map.insert(key, value.0.take());
        }
        Ok(values)
    }
}

pub(crate) fn encode(value: &Value) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, value).map_err(|_| Error::InvalidDocument)?;
    Ok(bytes)
}

pub(crate) fn array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    value
        .get(name)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(Error::InvalidDocument)
}

pub(crate) fn optional_array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    match value.get(name) {
        None => Ok(&[]),
        Some(_) => array(value, name),
    }
}

pub(crate) fn id(value: &Value) -> Result<Vec<u8>> {
    let s = value.as_str().ok_or(Error::InvalidDocument)?;
    if s.len() > 88 {
        return Err(Error::InvalidDocument);
    }
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .or_else(|_| data_encoding::BASE64URL.decode(s.as_bytes()))
        .map_err(|_| Error::InvalidDocument)?;
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(Error::InvalidDocument);
    }
    Ok(bytes)
}

pub(crate) fn register(value: &Value, ids: &mut BTreeSet<Vec<u8>>) -> Result<()> {
    if !ids.insert(id(&value["id"])?) {
        return Err(Error::DuplicateId);
    }
    Ok(())
}

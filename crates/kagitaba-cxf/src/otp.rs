//! Shared TOTP import and generation. Callers own camera, images, time and UI.
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Parse an otpauth TOTP URI without fetching anything. Unknown parameters and
/// algorithms are rejected explicitly instead of silently changing their meaning.
pub fn parse(input: &str) -> Result<Value, &'static str> {
    if input.len() > 16384 || !input.starts_with("otpauth://totp/") {
        return Err("Choose a TOTP otpauth QR code or URI");
    }
    crate::conversion::totp(input).ok_or("Unsupported or invalid TOTP URI")
}
/// Generate a code for supported algorithms/digits; unsupported stored data is retained.
pub fn code(v: &Value, now: u64) -> Result<(Zeroizing<String>, u64), &'static str> {
    use hmac::{Hmac, KeyInit, Mac};
    let period = v["period"]
        .as_u64()
        .filter(|p| *p > 0)
        .ok_or("Invalid TOTP period")?;
    let digits = v["digits"]
        .as_u64()
        .filter(|n| (6..=8).contains(n))
        .ok_or("Unsupported TOTP digits")?;
    let raw = v["secret"].as_str().ok_or("Missing TOTP secret")?;
    let key = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(raw.trim_end_matches('=').as_bytes())
            .map_err(|_| "Invalid TOTP secret")?,
    );
    if key.is_empty() {
        return Err("Invalid TOTP secret");
    }
    macro_rules! mac {
        ($hash:ty) => {{
            let mut h = Hmac::<$hash>::new_from_slice(&key).map_err(|_| "Invalid TOTP key")?;
            h.update(&(now / period).to_be_bytes());
            Zeroizing::new(h.finalize().into_bytes().to_vec())
        }};
    }
    let digest = match v["algorithm"].as_str() {
        Some("sha1") => mac!(sha1::Sha1),
        Some("sha256") => mac!(sha2::Sha256),
        Some("sha512") => mac!(sha2::Sha512),
        _ => return Err("Unsupported TOTP algorithm"),
    };
    let offset = (digest[digest.len() - 1] & 15) as usize;
    let value = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid TOTP digest")?,
    ) & 0x7fffffff;
    Ok((
        Zeroizing::new(format!(
            "{:0width$}",
            value % 10u32.pow(digits as u32),
            width = digits as usize
        )),
        period - now % period,
    ))
}
/// Decode bounded grayscale pixels. Returns all distinct TOTP URIs for explicit
/// selection; never selects a random QR or follows a link from an image.
pub fn scan(
    width: usize,
    height: usize,
    pixels: &[u8],
) -> Result<Vec<Zeroizing<String>>, &'static str> {
    if width == 0
        || height == 0
        || width > 2048
        || height > 2048
        || width.checked_mul(height) != Some(pixels.len())
    {
        return Err("QR image exceeds 2048 by 2048 pixels");
    }
    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| pixels[y * width + x]);
    let mut found = Vec::new();
    for grid in image.detect_grids() {
        if let Ok((_, text)) = grid.decode() {
            let text = Zeroizing::new(text);
            if parse(&text).is_ok() && !found.contains(&text) {
                found.push(text);
            }
        }
    }
    if found.is_empty() {
        return Err("No supported TOTP QR code found");
    }
    Ok(found)
}

/// Make a disposable upstream validation view. Its u8 numeric fields must not
/// constrain the authoritative JSON, whose positive u64 values are checked here.
pub(crate) fn validation_view(value: &Value) -> crate::Result<crate::json::SecretJson> {
    fn credential(v: &mut Value) -> crate::Result<()> {
        if v["type"] == "totp" {
            for (key, default) in [("period", 30), ("digits", 6)] {
                if v[key].as_u64().is_none_or(|n| n == 0) {
                    return Err(crate::Error::InvalidDocument);
                }
                v[key] = json!(default);
            }
        }
        Ok(())
    }
    fn item(v: &mut Value) -> crate::Result<()> {
        if let Some(values) = v.get_mut("credentials").and_then(Value::as_array_mut) {
            for c in values {
                credential(c)?;
            }
        }
        Ok(())
    }
    fn visit(v: &mut Value) -> crate::Result<()> {
        if v.get("type").is_some() {
            return credential(v);
        }
        if let Some(accounts) = v.get_mut("accounts").and_then(Value::as_array_mut) {
            for account in accounts {
                if let Some(items) = account.get_mut("items").and_then(Value::as_array_mut) {
                    for value in items {
                        item(value)?;
                    }
                }
            }
        } else {
            item(v)?;
        }
        Ok(())
    }
    let mut view = crate::json::SecretJson(value.clone());
    visit(&mut view.0)?;
    Ok(view)
}

use eframe::egui;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};
pub struct Clipboard {
    inner: Option<arboard::Clipboard>,
    owned: Option<([u8; 32], Instant)>,
}
impl Clipboard {
    pub fn new() -> Self {
        Self {
            inner: arboard::Clipboard::new().ok(),
            owned: None,
        }
    }
    pub fn copy(&mut self, text: &str) -> bool {
        if let Some(c) = &mut self.inner
            && c.set_text(text.to_owned()).is_ok()
        {
            self.owned = Some((Sha256::digest(text.as_bytes()).into(), Instant::now()));
            return true;
        }
        false
    }
    pub fn tick(&mut self) {
        if self
            .owned
            .as_ref()
            .is_some_and(|(_, t)| t.elapsed() >= Duration::from_secs(30))
        {
            self.clear();
        }
    }
    pub fn clear(&mut self) {
        if let Some((hash, _)) = self.owned.take()
            && let Some(c) = &mut self.inner
            && let Ok(text) = c.get_text()
        {
            let text = Zeroizing::new(text);
            if Sha256::digest(text.as_bytes()).as_slice() == hash {
                let _ = c.clear();
            }
        }
    }
}
impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear();
    }
}
pub struct SecretValue(pub Value);
impl Drop for SecretValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => {
            for (mut k, mut v) in std::mem::take(m) {
                k.zeroize();
                wipe(&mut v);
            }
        }
        _ => {}
    }
}
pub fn show(ui: &mut egui::Ui, json: &mut String, clipboard: &mut Clipboard) -> Option<String> {
    let Ok(value) = serde_json::from_str::<Value>(json) else {
        ui.label("Invalid JSON; fix it in the complete payload editor.");
        return None;
    };
    let mut v = SecretValue(value);
    let mut changed = false;
    let mut status = None;
    let Some(entity) = v.0.get_mut("entity").filter(|e| e.is_object()) else {
        ui.label("Missing entry object; fix the complete payload.");
        return None;
    };
    if let Some(title) = entity.get_mut("title") {
        changed |= field(ui, "Title", title, false, clipboard, &mut status);
    }
    if let Some(urls) = entity
        .get_mut("scope")
        .and_then(|s| s.get_mut("urls"))
        .and_then(Value::as_array_mut)
    {
        for (i, url) in urls.iter_mut().enumerate() {
            ui.push_id(("url", i), |ui| {
                changed |= field(ui, "URL", url, false, clipboard, &mut status);
            });
        }
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        for (i, c) in credentials.iter_mut().enumerate() {
            ui.push_id(i, |ui| match c["type"].as_str().unwrap_or("") {
                "basic-auth" => {
                    if let Some(value) = c.pointer_mut("/username/value") {
                        changed |= field(ui, "Username", value, false, clipboard, &mut status);
                    }
                    if let Some(value) = c.pointer_mut("/password/value") {
                        changed |= field(ui, "Password", value, true, clipboard, &mut status);
                        if ui.button("Generate password (24 characters)").clicked() {
                            match password() {
                                Ok(new) => {
                                    wipe(value);
                                    *value = new.into();
                                    changed = true;
                                }
                                Err(e) => status = Some(e.into()),
                            }
                        }
                    }
                }
                "note" => {
                    if let Some(value) = c.pointer_mut("/content/value") {
                        changed |= field(ui, "Note", value, true, clipboard, &mut status);
                    }
                }
                "totp" => {
                    ui.collapsing("TOTP settings", |ui| {
                        if let Some(secret) = c.get_mut("secret") {
                            changed |=
                                field(ui, "Base32 secret", secret, true, clipboard, &mut status);
                        }
                        if let Some(algorithm) = c
                            .get("algorithm")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                        {
                            let mut next = algorithm.clone();
                            egui::ComboBox::from_id_salt("totp-algorithm")
                                .selected_text(&next)
                                .show_ui(ui, |ui| {
                                    for a in ["sha1", "sha256", "sha512"] {
                                        ui.selectable_value(&mut next, a.into(), a);
                                    }
                                });
                            if next != algorithm {
                                c["algorithm"] = next.into();
                                changed = true;
                            }
                        }
                        for (name, range) in [("digits", 6..=8), ("period", 1..=300)] {
                            if let Some(mut number) = c[name].as_u64() {
                                ui.horizontal(|ui| {
                                    ui.label(name);
                                    if ui
                                        .add(egui::DragValue::new(&mut number).range(range))
                                        .changed()
                                    {
                                        c[name] = number.into();
                                        changed = true;
                                    }
                                });
                            }
                        }
                    });
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    match totp(c, now) {
                        Ok((code, remaining)) => {
                            ui.horizontal(|ui| {
                                ui.monospace(code.as_str());
                                ui.label(format!("{remaining}s"));
                                if ui.button("Copy code").clicked() {
                                    status = Some(
                                        if clipboard.copy(&code) {
                                            "Code copied; clears in 30 seconds"
                                        } else {
                                            "Clipboard unavailable"
                                        }
                                        .into(),
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            ui.label(e);
                        }
                    }
                }
                "passkey" => {
                    ui.label(format!(
                        "Passkey for {}",
                        c["rpId"].as_str().unwrap_or("unknown relying party")
                    ));
                    ui.label("Stored securely. Browser authentication is not yet implemented.");
                }
                _ => {
                    ui.label("Additional credential retained; inspect the complete payload below.");
                }
            });
        }
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        ui.horizontal(|ui|{
            if ui.button("Add TOTP").clicked(){credentials.push(serde_json::json!({"type":"totp","secret":"","algorithm":"sha1","period":30,"digits":6}));changed=true;}
            if ui.button("Add note").clicked(){credentials.push(serde_json::json!({"type":"note","content":{"fieldType":"string","value":""}}));changed=true;}
        });
    }
    if entity.get("credentials").is_some() && ui.button("Add URL").clicked() {
        let scope = entity
            .as_object_mut()
            .expect("checked object")
            .entry("scope")
            .or_insert_with(|| serde_json::json!({"urls":[],"androidApps":[]}));
        if let Some(scope) = scope.as_object_mut() {
            let urls = scope.entry("urls").or_insert_with(|| serde_json::json!([]));
            if let Some(urls) = urls.as_array_mut() {
                urls.push("".into());
                changed = true;
            }
        }
    }
    if let Some(items) = entity.get("items").and_then(Value::as_array) {
        ui.label(format!("Collection: {} direct links", items.len()));
        for link in items {
            ui.label(format!(
                "Linked item: {}",
                link["item"].as_str().unwrap_or("unknown")
            ));
        }
        ui.label("Use the complete payload editor to change links and nested collections.");
    }
    if changed && let Ok(updated) = serde_json::to_string_pretty(&v.0) {
        json.zeroize();
        *json = updated;
    }
    status
}
fn field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Value,
    secret: bool,
    clip: &mut Clipboard,
    status: &mut Option<String>,
) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let mut edited = Zeroizing::new(text.to_owned());
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        changed = ui
            .add(egui::TextEdit::singleline(&mut *edited).password(secret))
            .changed();
        if ui.button("Copy").clicked() {
            *status = Some(
                if clip.copy(&edited) {
                    "Copied; clears in 30 seconds. Clipboard history may retain copies."
                } else {
                    "Clipboard unavailable"
                }
                .into(),
            );
        }
    });
    if changed {
        wipe(value);
        *value = Value::String(std::mem::take(&mut *edited));
    }
    changed
}
pub fn password() -> Result<String, &'static str> {
    use rand::TryRng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = Zeroizing::new([0; 24]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| "Randomness unavailable")?;
    Ok(bytes
        .iter()
        .map(|b| ALPHABET[(b & 63) as usize] as char)
        .collect())
}
pub fn totp(v: &Value, now: u64) -> Result<(Zeroizing<String>, u64), &'static str> {
    use hmac::{Hmac, KeyInit, Mac};
    let period = v["period"].as_u64().ok_or("Invalid TOTP period")?;
    let digits = v["digits"].as_u64().ok_or("Invalid TOTP digits")?;
    if period == 0 || !(6..=8).contains(&digits) {
        return Err("Unsupported TOTP parameters");
    }
    let raw = v["secret"].as_str().ok_or("Missing TOTP secret")?;
    let key = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(raw.trim_end_matches('=').as_bytes())
            .map_err(|_| "Invalid TOTP secret")?,
    );
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
    let code = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid TOTP digest")?,
    ) & 0x7fffffff;
    Ok((
        Zeroizing::new(format!(
            "{:0width$}",
            code % 10u32.pow(digits as u32),
            width = digits as usize
        )),
        period - now % period,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_vectors() {
        for (algorithm, secret, expected) in [
            ("sha1", b"12345678901234567890".as_slice(), "94287082"),
            (
                "sha256",
                b"12345678901234567890123456789012".as_slice(),
                "46119246",
            ),
            (
                "sha512",
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                "90693936",
            ),
        ] {
            let v = serde_json::json!({"algorithm":algorithm,"secret":data_encoding::BASE32_NOPAD.encode(secret),"period":30,"digits":8});
            let (code, left) = totp(&v, 59).unwrap();
            assert_eq!(code.as_str(), expected);
            assert_eq!(left, 1);
        }
    }
    #[test]
    fn rejects_invalid_otp_parameters() {
        for v in [
            serde_json::json!({"period":0,"digits":6}),
            serde_json::json!({"period":30,"digits":99}),
        ] {
            assert!(totp(&v, 59).is_err());
        }
    }
    #[test]
    fn malformed_editor_drafts_never_panic_or_silently_change() {
        let ctx = egui::Context::default();
        let mut clipboard = Clipboard {
            inner: None,
            owned: None,
        };
        for input in [
            "null",
            "[]",
            r#"{"entity":"bad"}"#,
            r#"{"entity":{"title":"x","credentials":[{"type":"basic-auth","username":"bad","password":4},{"type":"note","content":[]},{"type":"totp","digits":99}]}}"#,
        ] {
            let mut text = input.to_owned();
            let mut output = ctx.run_ui(Default::default(), |ui| {
                show(ui, &mut text, &mut clipboard);
            });
            output.textures_delta.clear();
            assert_eq!(text, input);
        }
    }
}

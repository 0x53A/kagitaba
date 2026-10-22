use crate::theme;
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
fn passkey_algorithm(value: &Value) -> &'static str {
    use base64::Engine;
    use p256::pkcs8::DecodePrivateKey;
    let Some(encoded) = value["key"].as_str() else { return "Unknown"; };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')) else { return "Unknown"; };
    let bytes = Zeroizing::new(bytes);
    if p256::SecretKey::from_pkcs8_der(&bytes).is_ok() { "ES256 / P-256" } else { "Unknown" }
}

fn passkey_details(ui: &mut egui::Ui, value: &Value, clipboard: &mut Clipboard, status: &mut Option<String>) {
    for (label, key, secret) in [
        ("Relying party", "rpId", false), ("Username", "username", false),
        ("Display name", "userDisplayName", false), ("Credential ID", "credentialId", false),
        ("User handle", "userHandle", true),
    ] {
        let Some(text) = value[key].as_str().filter(|v| !v.is_empty()) else { continue; };
        theme::caption(ui, label);
        let id = ui.id().with(("passkey-detail", key));
        let mut revealed = ui.data(|d| d.get_temp::<bool>(id).unwrap_or(false));
        ui.horizontal_wrapped(|ui| {
            if secret && !revealed { ui.label("••••••••"); }
            else { ui.add(egui::Label::new(egui::RichText::new(text).monospace()).selectable(true).wrap()); }
            if secret && ui.small_button(if revealed { "Hide" } else { "Show" }).clicked() { revealed = !revealed; }
            if ui.small_button("Copy").clicked() {
                *status = Some(if clipboard.copy(text) { "Copied; clears in 30 seconds" } else { "Clipboard unavailable" }.into());
            }
        });
        ui.data_mut(|d| d.insert_temp(id, revealed));
    }
    theme::caption(ui, "Algorithm"); ui.label(passkey_algorithm(value));
    for (label, key) in [("Backup eligible", "eligible"), ("Backed up", "state")] {
        theme::caption(ui, label);
        ui.label(match value["kagitabaBackupFlags"].get(key) {
            None => "Not recorded", Some(Value::Bool(true)) => "Yes", Some(Value::Bool(false)) => "No", Some(_) => "Invalid",
        });
    }
}

pub fn show(
    ui: &mut egui::Ui,
    json: &mut String,
    clipboard: &mut Clipboard,
    tools: &mut crate::credential_tools::Tools,
) -> Option<String> {
    let Ok(value) = serde_json::from_str::<Value>(json) else {
        ui.colored_label(
            theme::ERROR,
            "Invalid JSON; fix it in the complete payload editor.",
        );
        return None;
    };
    let mut v = SecretValue(value);
    let mut changed = false;
    let mut status = None;
    let is_item = v.0["kind"] == "item";
    let Some(entity) = v.0.get_mut("entity").filter(|e| e.is_object()) else {
        ui.colored_label(
            theme::ERROR,
            "Missing entry object; fix the complete payload.",
        );
        return None;
    };
    if let Some(title) = entity.get_mut("title") {
        changed |= field(ui, "Title", title, false, clipboard, &mut status);
    }
    if is_item {
        let mut urls = SecretValue(entity.pointer("/scope/urls").cloned().unwrap_or_else(|| Value::Array(vec![])));
        if let Some(rows) = urls.0.as_array_mut()
            && url_table(ui, rows, clipboard, &mut status) {
            let scope = entity.as_object_mut().unwrap().entry("scope").or_insert_with(|| serde_json::json!({"androidApps":[]}));
            scope["urls"] = std::mem::take(&mut urls.0);
            changed = true;
        }
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        for (i, c) in credentials.iter_mut().enumerate() {
            ui.push_id(i, |ui| match c["type"].as_str().unwrap_or("") {
                "basic-auth" => {
                    theme::section(ui, "Login");
                    for (name, kind) in [("username", "string"), ("password", "concealed-string")] {
                        if c.get(name).is_none_or(Value::is_null)
                            && ui.button(format!("Add {name}")).clicked()
                        {
                            c[name] = serde_json::json!({"fieldType":kind,"value":""});
                            changed = true;
                        }
                    }
                    if let Some(value) = c.pointer_mut("/username/value") {
                        changed |= field(ui, "Username", value, false, clipboard, &mut status);
                    }
                    if ui.button("Generate…").clicked() {
                        tools.open_generator(Some(i));
                    }
                    if let Some(value) = c.pointer_mut("/password/value") {
                        changed |= field(ui, "Password", value, true, clipboard, &mut status);
                    }
                }
                "custom-fields" => {
                    theme::section(ui, "Custom fields");
                    if let Some(fields) = c.get_mut("fields").and_then(Value::as_array_mut) {
                        for (index, custom) in fields.iter_mut().enumerate() {
                            ui.push_id(("custom", index), |ui| {
                                changed |= custom_field(ui, custom, clipboard, &mut status);
                            });
                        }
                    }
                }
                "note" => {
                    ui.separator();
                    if let Some(value) = c.pointer_mut("/content/value") {
                        changed |= field(ui, "Note", value, true, clipboard, &mut status);
                    }
                }
                "totp" => {
                    theme::section(ui, "One-time password");
                    ui.collapsing("TOTP settings", |ui| {
                        for name in ["issuer", "username"] {
                            if let Some(v) = c.get_mut(name) {
                                changed |= field(ui, name, v, false, clipboard, &mut status);
                            } else if ui.button(format!("Add TOTP {name}")).clicked() {
                                c[name] = "".into();
                                changed = true;
                            }
                        }
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
                        for name in ["digits", "period"] {
                            if let Some(mut number) = c[name].as_u64() {
                                ui.horizontal(|ui| {
                                    theme::caption(ui, name);
                                    if ui
                                        .add(
                                            egui::DragValue::new(&mut number)
                                                .range(1..=u64::MAX)
                                                .clamp_existing_to_range(false),
                                        )
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
                                ui.label(
                                    egui::RichText::new(code.as_str())
                                        .monospace()
                                        .size(24.0)
                                        .color(theme::AQUA),
                                );
                                theme::caption(ui, format!("{remaining}s"));
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
                            ui.colored_label(theme::ERROR, e);
                        }
                    }
                }
                "passkey" => {
                    theme::section(ui, "Passkey");
                    passkey_details(ui, c, clipboard, &mut status);
                }
                "file" if c.get("kagitabaFile").is_some() => {}
                _ => {
                    theme::caption(ui, "Additional credential retained in complete payload.");
                }
            });
        }
    }
    if let Some(credentials) = entity.get_mut("credentials").and_then(Value::as_array_mut) {
        ui.horizontal_wrapped(|ui|{
            if ui.button("Import TOTP (camera / picture / URI)").clicked(){tools.totp=true;}
            if ui.button("Add login").clicked(){credentials.push(serde_json::json!({"type":"basic-auth","username":{"fieldType":"string","value":""},"password":{"fieldType":"concealed-string","value":""}}));changed=true;}
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
        theme::caption(
            ui,
            "Edit links and nested collections in the complete payload.",
        );
    }
    if changed && let Ok(updated) = serde_json::to_string_pretty(&v.0) {
        json.zeroize();
        *json = updated;
    }
    status
}
fn url_table(ui: &mut egui::Ui, urls: &mut Vec<Value>, clipboard: &mut Clipboard, status: &mut Option<String>) -> bool {
    theme::section(ui, "URLs");
    let mut changed = false;
    let mut remove = None;
    if !urls.is_empty() {
        egui::Frame::new().stroke(egui::Stroke::new(1.0, theme::MUTED)).inner_margin(4.0).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            let input_width = (ui.available_width() - 96.0 - 2.0 * ui.spacing().item_spacing.x - 8.0).max(1.0);
            for (index, value) in urls.iter_mut().enumerate() {
                ui.push_id(("url", index), |ui| {
                    ui.horizontal(|ui| {
                        if let Some(text) = value.as_str() {
                            let mut edited = Zeroizing::new(text.to_owned());
                            let response = ui.add_sized([input_width, 36.0], egui::TextEdit::singleline(&mut *edited)
                                .font(egui::TextStyle::Monospace).vertical_align(egui::Align::Center).hint_text("URL"));
                            if response.changed() {
                                wipe(value);
                                *value = Value::String(edited.to_string());
                                changed = true;
                            }
                            if ui.add_sized([60.0, 36.0], egui::Button::new("Copy")).clicked() {
                                *status = Some(if clipboard.copy(&edited) { "Copied; clears in 30 seconds. Clipboard history may retain copies." } else { "Clipboard unavailable" }.into());
                            }
                        }
                        if ui.add_sized([36.0, 36.0], egui::Button::new(egui::RichText::new("×").color(theme::ERROR)))
                            .on_hover_text("Remove URL").clicked() { remove = Some(index); }
                    });
                });
            }
        });
    }
    if let Some(index) = remove { let mut removed = urls.remove(index); wipe(&mut removed); changed = true; }
    let response = ui.add_sized([ui.available_width(), 36.0], egui::Button::new("+ URL").frame(false));
    let rect = response.rect.shrink(0.5);
    let color = if response.hovered() || response.has_focus() { theme::AQUA } else { theme::MUTED };
    ui.painter().extend(egui::Shape::dashed_line(&[rect.left_top(), rect.right_top(), rect.right_bottom(), rect.left_bottom(), rect.left_top()], egui::Stroke::new(1.0, color), 5.0, 4.0));
    if response.clicked() { urls.push(Value::String(String::new())); changed = true; }
    changed
}

fn custom_field(ui: &mut egui::Ui, custom: &mut Value, clipboard: &mut Clipboard, status: &mut Option<String>) -> bool {
    let label = Zeroizing::new(custom["label"].as_str().unwrap_or("Unnamed field").to_owned());
    let kind = custom["fieldType"].as_str().unwrap_or("").to_owned();
    match kind.as_str() {
        "string" | "concealed-string" if custom["value"].is_string() => {
            let concealed = kind == "concealed-string" || label.trim().eq_ignore_ascii_case("pin");
            field(ui, &label, &mut custom["value"], concealed, clipboard, status)
        }
        "boolean" if matches!(custom["value"].as_str(), Some("true" | "false")) => {
            let mut checked = custom["value"] == "true";
            if ui.checkbox(&mut checked, label.as_str()).changed() {
                wipe(&mut custom["value"]);
                custom["value"] = Value::String(checked.to_string());
                true
            } else { false }
        }
        _ => {
            theme::caption(ui, format!("{} · {}", label.as_str(), kind));
            false
        }
    }
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
    theme::caption(ui, label);
    ui.horizontal(|ui| {
        let reveal_id = ui.id().with(("reveal-field", label));
        let mut revealed = ui
            .ctx()
            .data_mut(|data| data.get_temp::<bool>(reveal_id).unwrap_or(false));
        let width = (ui.available_width() - if secret { 145.0 } else { 72.0 }).max(60.0);
        changed = ui
            .add(
                egui::TextEdit::multiline(&mut *edited)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(1)
                    .password(secret && !revealed)
                    .desired_width(width),
            )
            .changed();
        if secret && ui.button(if revealed { "Hide" } else { "Show" }).clicked() {
            revealed = !revealed;
            ui.ctx()
                .data_mut(|data| data.insert_temp(reveal_id, revealed));
        }
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
pub fn totp(v: &Value, now: u64) -> Result<(Zeroizing<String>, u64), &'static str> {
    kagitaba_cxf::otp::code(v, now)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passkey_details_preserve_data_and_conceal_handle_and_key() {
        use p256::pkcs8::EncodePrivateKey;
        use base64::Engine;
        let key=p256::SecretKey::from_slice(&[7;32]).unwrap().to_pkcs8_der().unwrap();
        let encoded=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes());
        let value=serde_json::json!({"type":"passkey","rpId":"example.com","username":"Synthetic account","credentialId":"synthetic-credential","userHandle":"HIDDEN_SYNTHETIC_HANDLE","key":encoded,"kagitabaBackupFlags":{"eligible":false,"state":false}});
        assert_eq!(passkey_algorithm(&value),"ES256 / P-256");
        assert_eq!(passkey_algorithm(&serde_json::json!({"key":"invalid"})),"Unknown");
        let original=value.clone();
        let ctx=egui::Context::default();let mut clip=Clipboard{inner:None,owned:None};let mut status=None;
        let mut output=ctx.run_ui(Default::default(),|ui|passkey_details(ui,&value,&mut clip,&mut status));
        output.textures_delta.clear();
        fn gather(shape:&egui::epaint::Shape,text:&mut String) { match shape {egui::epaint::Shape::Text(t)=>text.push_str(&t.galley.job.text),egui::epaint::Shape::Vec(v)=>for s in v {gather(s,text)},_=>()}}
        let mut text=String::new();for shape in output.shapes {gather(&shape.shape,&mut text);}
        assert!(text.contains("synthetic-credential"));assert!(text.contains("Synthetic account"));
        assert!(!text.contains("HIDDEN_SYNTHETIC_HANDLE"));assert!(!text.contains(&encoded));assert_eq!(value,original);
    }

    #[test]
    fn custom_pin_is_concealed_without_changing_source_type() {
        for (label,kind,hidden) in [("Pin","string",true),(" PIN ","string",true),("Reference","string",false),("Reference","concealed-string",true)] {
            let ctx=egui::Context::default();
            let mut value=serde_json::json!({"label":label,"fieldType":kind,"value":"SYNTHETIC_PIN_VALUE","vendor":{"kept":true}});
            let original=value.clone();
            let mut clip=Clipboard { inner:None,owned:None };
            let mut status=None;
            let mut output=ctx.run_ui(Default::default(),|ui| { assert!(!custom_field(ui,&mut value,&mut clip,&mut status)); });
            output.textures_delta.clear();
            fn gather(shape:&egui::epaint::Shape,text:&mut String) {
                match shape { egui::epaint::Shape::Text(t)=>text.push_str(&t.galley.job.text),egui::epaint::Shape::Vec(v)=>for s in v {gather(s,text)},_=>() }
            }
            let mut text=String::new();for shape in output.shapes {gather(&shape.shape,&mut text);}
            assert_eq!(text.contains("SYNTHETIC_PIN_VALUE"),!hidden);
            assert_eq!(value,original);
        }
    }

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
                show(ui, &mut text, &mut clipboard, &mut Default::default());
            });
            output.textures_delta.clear();
            assert_eq!(text, input);
        }
    }
}

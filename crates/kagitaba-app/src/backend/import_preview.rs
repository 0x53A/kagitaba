//! Read-only import views. Every retained source string is wiped on drop.
use kagitaba_cxf::{Payload, PayloadKind};
use serde_json::Value;
use zeroize::Zeroizing;

pub struct PreviewEntry {
    pub title: Zeroizing<String>,
    pub collection: bool,
    pub existing_duplicate: bool,
    pub custom_fields: usize,
    pub attachment_count: usize,
    pub history_count: usize,
    pub history: Zeroizing<String>,
    pub reveal_history: bool,
    pub fields: Vec<PreviewField>,
    pub raw: Zeroizing<String>,
    pub expanded: bool,
    pub reveal_raw: bool,
}

pub struct PreviewField {
    pub label: Zeroizing<String>,
    pub value: Zeroizing<String>,
    pub sensitive: bool,
    pub revealed: bool,
}

impl PreviewEntry {
    pub fn from_payload(payload: &Payload) -> super::Result<Self> {
        let entity = payload.entity();
        let mut fields = Vec::new();
        let mut custom_fields = 0;
        let mut attachment_count = 0;
        if let Some(scope) = entity.get("scope").and_then(Value::as_object) {
            for (name, value) in scope {
                if value.is_null() || value.as_array().is_some_and(Vec::is_empty) || value.as_object().is_some_and(serde_json::Map::is_empty) { continue; }
                flatten(&mut fields, &format!("Scopes / {name}"), value, false)?;
            }
        }
        if let Some(credentials) = entity["credentials"].as_array() {
            for (i, credential) in credentials.iter().enumerate() {
                let kind = credential["type"].as_str().unwrap_or("unknown");
                let prefix = Zeroizing::new(format!("{} · {kind}", i + 1));
                if kind == "file" {
                    let owned = credential.get("kagitabaFile").is_some();
                    attachment_count += usize::from(owned);
                    let name = credential["name"].as_str().unwrap_or("Unnamed file");
                    fields.push(PreviewField {
                        label: Zeroizing::new(if owned { "Attachment" } else { "External file descriptor" }.into()),
                        value: Zeroizing::new(match credential["decryptedSize"].as_u64() {
                            Some(size) => format!("{name} · {size} bytes"),
                            None => name.to_owned(),
                        }),
                        sensitive: false, revealed: false,
                    });
                } else if kind == "custom-fields" {
                    if let Some(custom) = credential["fields"].as_array() {
                        custom_fields += custom.len();
                        for (index, field) in custom.iter().enumerate() {
                            let name = field["label"].as_str().unwrap_or("Unnamed field");
                            let field_type = field["fieldType"].as_str().unwrap_or("unknown");
                            let label = Zeroizing::new(format!("{} / {} · {name} ({field_type})", prefix.as_str(), index + 1));
                            flatten(&mut fields, &label, &field["value"], true)?;
                        }
                    }
                } else if let Some(object) = credential.as_object() {
                    for (key, value) in object {
                        if key == "type" { continue; }
                        let label = Zeroizing::new(format!("{} / {key}", prefix.as_str()));
                        flatten(&mut fields, &label, value, key != "username")?;
                    }
                }
            }
        }
        if payload.kind() == PayloadKind::Collection {
            for key in ["items", "subCollections"] {
                if let Some(value) = entity.get(key) { flatten(&mut fields, key, value, false)?; }
            }
        }
        // The complete envelope includes unknown fields, source extensions and history.
        // Keep only zeroizing serialized storage, not an unprotected JSON clone.
        let raw = payload.to_json()?;
        let raw_value = crate::editor::SecretValue(serde_json::from_slice(&raw)?);
        let mut history = Zeroizing::new(String::new());
        let mut history_count = 0;
        if let Some(extensions) = entity["extensions"].as_array() {
            for extension in extensions {
                let data = &extension["data"];
                for key in ["passwordHistory", "history"] {
                    if let Some(value) = data.get(key).filter(|v| !v.is_null()) {
                        let count = value.as_array().map(Vec::len)
                            .or_else(|| value.get("entries").and_then(Value::as_array).map(Vec::len)).unwrap_or(1);
                        if count == 0 { continue; }
                        history_count += count;
                        if !history.is_empty() { history.push_str("\n\n"); }
                        let text = Zeroizing::new(serde_json::to_string_pretty(value)?);
                        history.push_str(&text);
                    }
                }
            }
        }
        Ok(Self {
            title: Zeroizing::new(entity["title"].as_str().unwrap_or("Untitled").to_owned()),
            collection: payload.kind() == PayloadKind::Collection,
            existing_duplicate: false,
            fields, custom_fields, attachment_count, history_count, history, reveal_history: false,
            raw: Zeroizing::new(serde_json::to_string_pretty(&raw_value.0)?),
            expanded: false,
            reveal_raw: false,
        })
    }
}

fn flatten(fields: &mut Vec<PreviewField>, label: &str, value: &Value, sensitive: bool) -> super::Result<()> {
    if value.get("fieldType").and_then(Value::as_str).is_some()
        && let Some(inner) = value.get("value") {
        return flatten(fields, label, inner, sensitive);
    }
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                let path = Zeroizing::new(format!("{label} / {key}"));
                flatten(fields, &path, value, sensitive)?;
            }
        }
        Value::Array(array) if !array.is_empty() => {
            for (index, value) in array.iter().enumerate() {
                let path = Zeroizing::new(format!("{label} / {}", index + 1));
                flatten(fields, &path, value, sensitive)?;
            }
        }
        _ => fields.push(PreviewField {
            label: Zeroizing::new(label.to_owned()),
            value: Zeroizing::new(match value { Value::String(text) => text.clone(), _ => serde_json::to_string(value)? }),
            sensitive,
            revealed: false,
        }),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detailed_warning_follows_remapped_item_into_wrapped_preview() {
        let converted = kagitaba_cxf::firefox::from_bytes(b"url,username,password\nhttps://example.test,user,SECRET").unwrap();
        let report = kagitaba_cxf::ConversionReport {
            warnings: vec![kagitaba_cxf::ImportWarning { item_index: Some(0), kind: kagitaba_cxf::WarningKind::OpaquePasskey,
                detail: Some(kagitaba_cxf::WarningDetail { reason: "Missing flag", action: "Inspect original flag", field: Some("KPEX_PASSKEY_FLAG_BE") }) }],
            ..Default::default()
        };
        let mut warnings = crate::backend::conversion_summary(&report);
        crate::backend::conversion_details(&report, converted.document(), &mut warnings);
        let mut plan = converted.document().plan_import(&kagitaba_core::wallet::Wallet::from_parts([], []).unwrap(), &mut rand::rngs::SysRng).unwrap();
        plan.wrap_collection("Import", &mut rand::rngs::SysRng).unwrap();
        let pending = crate::backend::import_files::PendingImport::prepare(plan, vec![]).unwrap();
        let preview = pending.preview(warnings).unwrap();
        let diagnostic = &preview.warnings.details[0];
        let entry = &preview.entries[diagnostic.entry_index.unwrap()];
        assert_eq!(entry.title.as_str(), "https://example.test");
        assert!(!entry.collection && !entry.expanded && !entry.reveal_raw);
        assert_eq!(diagnostic.detail.field, Some("KPEX_PASSKEY_FLAG_BE"));
        assert!(entry.fields.iter().any(|field| field.value.as_str() == "SECRET" && field.sensitive && !field.revealed));
    }

    #[test]
    fn firefox_csv_reaches_preview_without_revealing_password_or_source() {
        let converted = kagitaba_cxf::firefox::from_bytes(
            b"url,username,password,extra\r\nhttps://example.test,alice,\"secret,with commas\",source-only\r\n"
        ).unwrap();
        let plan = converted.document().plan_import(
            &kagitaba_core::wallet::Wallet::from_parts([], []).unwrap(), &mut rand::rngs::SysRng
        ).unwrap();
        let preview = PreviewEntry::from_payload(&plan.entries()[0]).unwrap();
        assert!(preview.fields.iter().any(|field| field.value.as_str() == "alice" && !field.sensitive));
        assert!(preview.fields.iter().any(|field| field.value.as_str() == "secret,with commas" && field.sensitive && !field.revealed));
        assert!(preview.raw.contains("source-only"));
        assert!(!preview.reveal_raw && !preview.expanded);
    }

    #[test]
    fn owned_file_preview_shows_name_size_without_descriptor_secrets() {
        let id = kagitaba_core::EntryId::from_bytes([5; 16]);
        let payload = Payload::new(id, PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
            "id":"BQUFBQUFBQUFBQUFBQUFBQ", "title":"Files", "credentials":[]
        })).unwrap()).unwrap();
        let (payload, _) = kagitaba_cxf::attachments::add(&payload, "Example.txt", b"example", &mut rand::rngs::SysRng).unwrap();
        let preview = PreviewEntry::from_payload(&payload).unwrap();
        assert_eq!(preview.attachment_count, 1);
        assert_eq!(preview.fields.len(), 1);
        assert_eq!(preview.fields[0].label.as_str(), "Attachment");
        assert_eq!(preview.fields[0].value.as_str(), "Example.txt · 7 bytes");
        assert!(!preview.fields[0].sensitive);
        assert!(!preview.reveal_raw);
    }

    #[test]
    fn fields_and_history_are_available_but_secrets_start_hidden() {
        let id = kagitaba_core::EntryId::from_bytes([5;16]);
        let payload = Payload::new(id, PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
            "id": "BQUFBQUFBQUFBQUFBQUFBQ", "title": "Synthetic login",
            "credentials": [{"type":"custom-fields","fields":[{"label":"Recovery", "fieldType":"concealed-string", "value":"synthetic-secret"}]},
            {"type":"basic-auth","username":{"fieldType":"string","value":"synthetic-user"}}],
            "extensions":[{"name":"synthetic-source","data":{"passwordHistory":[{"password":"synthetic-old"}]}}]
        })).unwrap()).unwrap();
        let preview = PreviewEntry::from_payload(&payload).unwrap();
        assert_eq!(preview.title.as_str(), "Synthetic login");
        assert!(preview.fields.iter().any(|field| field.label.contains("Recovery (concealed-string)") && field.sensitive && !field.revealed && field.value.as_str() == "synthetic-secret"));
        assert!(preview.fields.iter().any(|field| !field.sensitive && field.value.as_str() == "synthetic-user"));
        assert!(preview.raw.contains("passwordHistory") && preview.raw.contains("synthetic-old"));
        assert_eq!(preview.custom_fields, 1);
        assert_eq!(preview.history_count, 1);
        assert!(preview.history.contains("synthetic-old"));
        assert!(!preview.reveal_raw && !preview.reveal_history && !preview.expanded);
    }
}

//! Lossless application edits: JS display objects are never authoritative JSON.
use super::*;

pub(super) fn operation(request: &Value) -> Result<Value> {
    let id: EntryId = string(request, "entryId")?.parse().map_err(|_| Error)?;
    let raw = string(request, "payload")?;
    let payload = Payload::from_json(id, raw.as_bytes()).map_err(|_| Error)?;
    let changes = request.get("changes").ok_or(Error)?;
    let edited = payload
        .edited(|document| {
            update(document, changes).map_err(|_| kagitaba_cxf::Error::InvalidDocument)
        })
        .map_err(|_| Error)?;
    let encoded = edited.to_json().map_err(|_| Error)?;
    Ok(json!({"payload":std::str::from_utf8(&encoded).map_err(|_| Error)?}))
}

fn update(document: &mut Value, changes: &Value) -> Result<()> {
    if let Some(title) = changes.get("title") {
        document["entity"]["title"] = title.as_str().ok_or(Error)?.into();
    }
    if let Some(login) = changes.get("login") {
        let basic = document["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error)?
            .iter_mut()
            .find(|value| value["type"] == "basic-auth")
            .ok_or(Error)?;
        for (name, kind) in [("username", "string"), ("password", "concealed-string")] {
            if let Some(value) = login.get(name) {
                let value = value.as_str().ok_or(Error)?;
                if basic.get(name).is_none_or(Value::is_null) {
                    basic[name] = json!({"fieldType":kind});
                }
                basic[name]
                    .as_object_mut()
                    .ok_or(Error)?
                    .insert("value".into(), value.into());
            }
        }
        if let Some(urls) = login.get("urls") {
            if !urls.as_array().ok_or(Error)?.iter().all(Value::is_string) {
                return Err(Error);
            }
            let entity = document["entity"].as_object_mut().ok_or(Error)?;
            let scope = entity
                .entry("scope")
                .or_insert_with(|| json!({"androidApps":[]}));
            scope
                .as_object_mut()
                .ok_or(Error)?
                .insert("urls".into(), urls.clone());
        }
    }
    if let Some(logins) = changes.get("logins").and_then(Value::as_array) {
        for login in logins {
            let index = login["index"].as_u64().ok_or(Error)? as usize;
            let c = document["entity"]["credentials"]
                .get_mut(index)
                .ok_or(Error)?;
            if c["type"] != "basic-auth" {
                return Err(Error);
            }
            for (name, kind) in [("username", "string"), ("password", "concealed-string")] {
                if let Some(value) = login.get(name) {
                    if c.get(name).is_none_or(Value::is_null) {
                        c[name] = json!({"fieldType":kind});
                    }
                    c[name]["value"] = value.as_str().ok_or(Error)?.into();
                }
            }
        }
    }
    if let Some(urls) = changes.get("urls") {
        if !urls.as_array().ok_or(Error)?.iter().all(Value::is_string) {
            return Err(Error);
        }
        let entity = document["entity"].as_object_mut().ok_or(Error)?;
        let scope = entity
            .entry("scope")
            .or_insert_with(|| json!({"androidApps":[]}));
        scope["urls"] = urls.clone();
    }
    if let Some(totps) = changes.get("totps").and_then(Value::as_array) {
        for patch in totps {
            let c = document["entity"]["credentials"]
                .get_mut(patch["index"].as_u64().ok_or(Error)? as usize)
                .ok_or(Error)?;
            if c["type"] != "totp" {
                return Err(Error);
            }
            for key in [
                "secret",
                "algorithm",
                "period",
                "digits",
                "issuer",
                "username",
            ] {
                if let Some(v) = patch.get(key) {
                    let text = v.as_str().ok_or(Error)?;
                    c[key] = if matches!(key, "period" | "digits") {
                        json!(text.parse::<u64>().map_err(|_| Error)?)
                    } else {
                        text.into()
                    };
                }
            }
        }
    }
    if let Some(notes) = changes.get("notes").and_then(Value::as_array) {
        for note in notes {
            let c = document["entity"]["credentials"]
                .get_mut(note["index"].as_u64().ok_or(Error)? as usize)
                .ok_or(Error)?;
            if c["type"] != "note" {
                return Err(Error);
            }
            if c.get("content").is_none_or(Value::is_null) {
                c["content"] = json!({"fieldType":"string"});
            }
            c["content"]["value"] = note["value"].as_str().ok_or(Error)?.into();
        }
    }
    if let Some(fields) = changes.get("customFields").and_then(Value::as_array) {
        for patch in fields {
            let credential = document["entity"]["credentials"].get_mut(patch["index"].as_u64().ok_or(Error)? as usize).ok_or(Error)?;
            if credential["type"] != "custom-fields" { return Err(Error); }
            let field = credential["fields"].get_mut(patch["fieldIndex"].as_u64().ok_or(Error)? as usize).ok_or(Error)?;
            let value = patch["value"].as_str().ok_or(Error)?;
            match field["fieldType"].as_str() {
                Some("string" | "concealed-string") => (),
                Some("boolean") if matches!(value, "true" | "false") => (),
                _ => return Err(Error),
            }
            field["value"] = value.into();
        }
    }
    if let Some(added) = changes.get("appendCredentials").and_then(Value::as_array) {
        document["entity"]["credentials"]
            .as_array_mut()
            .ok_or(Error)?
            .extend(added.iter().cloned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_field_patches_preserve_type_and_unknown_data() {
        let mut document=json!({"entity":{"credentials":[{"type":"custom-fields","vendor":7,"fields":[{"label":"Pin","fieldType":"string","value":"old","vendor":true},{"fieldType":"boolean","value":"false"},{"fieldType":"future","value":{"opaque":true}}]}]}});
        let before=document.clone();
        update(&mut document,&json!({"customFields":[{"index":0,"fieldIndex":0,"value":"new"},{"index":0,"fieldIndex":1,"value":"true"}]})).unwrap();
        let mut expected=before.clone();expected["entity"]["credentials"][0]["fields"][0]["value"]="new".into();expected["entity"]["credentials"][0]["fields"][1]["value"]="true".into();
        assert_eq!(document,expected);
        for (index,value) in [(1,"invalid"),(2,"overwrite")] {
            assert!(update(&mut document,&json!({"customFields":[{"index":0,"fieldIndex":index,"value":value}]})).is_err());
            assert_eq!(document,expected);
        }
    }
}

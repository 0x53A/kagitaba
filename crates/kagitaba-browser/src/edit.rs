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
    Ok(())
}

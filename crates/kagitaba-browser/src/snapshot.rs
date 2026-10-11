//! The browser's application-owned snapshot reader, matching native layout.
use super::*;
use kagitaba_core::{KeyId, wallet::Wallet};
use std::collections::BTreeMap;

struct Snapshot {
    wallet: Wallet,
    signers: BTreeMap<KeyId, PublicKey>,
    metadata: BTreeMap<KeyId, EntryId>,
}

fn read(files: &Value) -> Result<Snapshot> {
    let files = files.as_object().ok_or(Error)?;
    if files.len() > 100_000
        || decode(
            files
                .get("kagitaba-format")
                .and_then(Value::as_str)
                .ok_or(Error)?,
        )?
        .as_slice()
            != b"1\n"
    {
        return Err(Error);
    }
    let mut keys = BTreeMap::new();
    let mut signers = BTreeMap::new();
    let mut devices = Vec::new();
    let mut browsers = BTreeMap::new();
    let mut names = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    let mut primaries = BTreeMap::new();
    let mut grants: BTreeMap<EntryId, Vec<GrantRecord>> = BTreeMap::new();
    let mut total = 0usize;
    for (path, encoded) in files {
        let data = decode(encoded.as_str().ok_or(Error)?)?;
        total = total.checked_add(data.len()).ok_or(Error)?;
        if total > 64 * 1024 * 1024 {
            return Err(Error);
        }
        let parts: Vec<_> = path.split('/').collect();
        match parts.as_slice() {
            ["participants", id, "meta.entry"] => {
                let text = std::str::from_utf8(&data).map_err(|_| Error)?;
                let entry: EntryId = text.strip_suffix('\n').ok_or(Error)?.parse().map_err(|_| Error)?;
                metadata.insert(id.parse().map_err(|_| Error)?, entry);
            }
            ["kagitaba-format"] => {}
            ["participants", id, "name.json"] => {
                let id: KeyId = id.parse().map_err(|_| Error)?;
                if data.len() > 1024 {
                    return Err(Error);
                }
                let value: Value = serde_json::from_slice(&data).map_err(|_| Error)?;
                let name = string(&value, "name")?;
                if value.as_object().is_none_or(|o| o.len() != 2)
                    || value["version"].as_u64() != Some(1)
                    || name.is_empty()
                    || name.trim() != name
                    || name.len() > 512
                    || name.chars().count() > 128
                    || name.chars().any(|c| {
                        c.is_control()
                            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                    })
                {
                    return Err(Error);
                }
                names.insert(id, name.to_owned());
            }
            ["participants", id, name @ ("pub.pem" | "sign.pem")] => {
                let id: KeyId = id.parse().map_err(|_| Error)?;
                let key = PublicKey::from_pem(std::str::from_utf8(&data).map_err(|_| Error)?)
                    .map_err(|_| Error)?;
                if *name == "pub.pem" {
                    if key.id() != id {
                        return Err(Error);
                    }
                    keys.insert(id, key);
                } else {
                    signers.insert(id, key);
                }
            }
            ["participants", id, "device.json"] => {
                let id: KeyId = id.parse().map_err(|_| Error)?;
                if data.len() > 1024 {
                    return Err(Error);
                }
                let hint: Value = serde_json::from_slice(&data).map_err(|_| Error)?;
                let serial = string(&hint, "serial")?;
                let enc = hint["encryptionSlot"].as_u64().ok_or(Error)?;
                let sign = hint["signingSlot"].as_u64().ok_or(Error)?;
                if hint["version"] != 1
                    || serial.is_empty()
                    || serial.len() > 32
                    || !serial.bytes().all(|b| b.is_ascii_digit())
                    || !(0x82..=0x95).contains(&enc)
                    || !(0x82..=0x95).contains(&sign)
                    || enc == sign
                {
                    return Err(Error);
                }
                devices.push(id);
            }
            ["participants", id, "browser.json"] => {
                let id: KeyId = id.parse().map_err(|_| Error)?;
                if data.len() > 64 * 1024 {
                    return Err(Error);
                }
                let metadata: Value = serde_json::from_slice(&data).map_err(|_| Error)?;
                browsers.insert(id, metadata);
            }
            ["entries", id, "primary"] => {
                let id: EntryId = id.parse().map_err(|_| Error)?;
                let primary = PrimaryRecord::from_bytes(&data).map_err(|_| Error)?;
                if primary.entry_id() != id {
                    return Err(Error);
                }
                primaries.insert(id, primary);
            }
            ["entries", id, "grants", recipient] => {
                let id: EntryId = id.parse().map_err(|_| Error)?;
                let recipient: KeyId = recipient.parse().map_err(|_| Error)?;
                let grant = GrantRecord::from_bytes(&data).map_err(|_| Error)?;
                if grant.entry_id() != id || grant.recipient() != recipient {
                    return Err(Error);
                }
                grants.entry(id).or_default().push(grant);
            }
            _ => return Err(Error),
        }
    }
    if signers.len() != keys.len()
        || signers.keys().any(|id| !keys.contains_key(id))
        || devices.iter().any(|id| !keys.contains_key(id))
        || names.keys().any(|id| !keys.contains_key(id))
    {
        return Err(Error);
    }
    for (id, metadata) in &browsers {
        let allowed = [
            "format",
            "version",
            "participantPem",
            "participantId",
            "signingPem",
            "signingId",
            "installationId",
            "unlock",
            "envelope",
        ];
        if metadata
            .as_object()
            .ok_or(Error)?
            .keys()
            .any(|k| !allowed.contains(&k.as_str()))
            || metadata["format"] != "kagitaba-browser-installation"
            || metadata["version"] != 1
            || string(metadata, "participantId")? != id.to_string()
        {
            return Err(Error);
        }
        let participant =
            PublicKey::from_pem(string(metadata, "participantPem")?).map_err(|_| Error)?;
        let signer = PublicKey::from_pem(string(metadata, "signingPem")?).map_err(|_| Error)?;
        if keys.get(id) != Some(&participant)
            || signers.get(id) != Some(&signer)
            || metadata["participantPem"] != participant.to_pem()
            || metadata["signingPem"] != signer.to_pem()
            || string(metadata, "signingId")? != signer.id().to_string()
        {
            return Err(Error);
        }
        let _: EntryId = string(metadata, "installationId")?
            .parse()
            .map_err(|_| Error)?;
        let unlock = &metadata["unlock"];
        if unlock
            .as_object()
            .ok_or(Error)?
            .keys()
            .any(|k| !["rpId", "prfInput", "credentialId"].contains(&k.as_str()))
            || unlock["rpId"] != "kagitaba.local"
            || binary(unlock, "prfInput")?.len() != 32
        {
            return Err(Error);
        }
        let credential = binary(unlock, "credentialId")?;
        if credential.is_empty() || credential.len() > 1024 {
            return Err(Error);
        }
        let envelope = binary(metadata, "envelope")?;
        // KTC1 header + KBI1 identity + authentication tag.
        if envelope.len() != 60 + 68 + 16 {
            return Err(Error);
        }
        Ciphertext::from_bytes(&envelope).map_err(|_| Error)?;
    }
    let mut entries = Vec::new();
    for (id, primary) in primaries {
        entries.push(
            Entry::from_parts(primary, grants.remove(&id).unwrap_or_default())
                .map_err(|_| Error)?,
        );
    }
    if !grants.is_empty() {
        return Err(Error);
    }
    let wallet = Wallet::from_parts(keys.into_values(), entries).map_err(|_| Error)?;
    let mut seen = std::collections::BTreeSet::new();
    for (participant, entry) in &metadata {
        if !wallet.participants().contains_key(participant) || !wallet.entries().contains_key(entry)
            || !seen.insert(entry) || names.contains_key(participant) { return Err(Error); }
    }
    Ok(Snapshot {
        metadata,
        wallet,
        signers,
    })
}

pub(super) fn operation(request: &Value) -> Result<Value> {
    let snapshot = read(&request["files"])?;
    if let Some(previous) = request.get("previous").filter(|v| !v.is_null()) {
        let previous = read(previous)?;
        for (id, entry) in snapshot.wallet.entries() {
            if let Some(old) = previous.wallet.entries().get(id)
                && old.primary() != entry.primary()
                && old.primary().revision_id() == entry.primary().revision_id()
            {
                return Err(Error);
            }
        }
    }
    let participants = snapshot
        .wallet
        .participants()
        .iter()
        .map(|(id, key)| (id.to_string(), Value::String(key.to_pem())))
        .collect::<serde_json::Map<_, _>>();
    let metadata = snapshot
        .metadata
        .into_iter()
        .map(|(id, entry)| (id.to_string(), Value::String(entry.to_string())))
        .collect::<serde_json::Map<_, _>>();
    Ok(
        json!({"signers": snapshot.signers.values().map(PublicKey::to_pem).collect::<Vec<_>>(),
        "participants": participants, "participantMetadata": metadata, "entries": snapshot.wallet.entries().keys().map(ToString::to_string).collect::<Vec<_>>()}),
    )
}

use std::collections::{BTreeMap, BTreeSet};

use kagitaba_core::{EntryId, KeyId, wallet::Wallet};
use rand_core::TryCryptoRng;
use serde_json::{Value, json};

use crate::{
    Document, Error, Payload, PayloadKind, Result,
    json::{self, SecretJson},
};

type IdMap = BTreeMap<(Vec<u8>, Vec<u8>), EntryId>;

/// Non-secret counts that an import UI can display before accepting the plan.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportReport {
    /// Number of source accounts.
    pub accounts: usize,
    /// Accounts with no items or root collections; no entry is created for them.
    pub empty_accounts: usize,
    /// Independently stored credential items.
    pub items: usize,
    /// Independently stored root collections (descendants remain embedded).
    pub root_collections: usize,
    /// Links whose target is absent from this exchange; preserved as external.
    pub unresolved_links: usize,
    /// Credential types retained opaquely, including unknown TOTP algorithms.
    pub opaque_credentials: usize,
    /// File credentials whose external attachment bytes are not part of JSON.
    pub external_files: usize,
}

/// An import staged in memory. Creating/sealing it never mutates its source
/// document, existing wallet, filesystem, or Git. Imports always create new IDs.
pub struct ImportPlan {
    entries: Vec<Payload>,
    report: ImportReport,
}

impl Document {
    /// Allocate fresh IDs, rewrite known references as a single operation, and
    /// create one payload per item/root collection. Account/header metadata are
    /// retained as encrypted provenance on each payload. Empty accounts produce
    /// no wallet entry and are explicitly counted in the report.
    ///
    /// Unknown extensions remain verbatim; opaque vendor-specific references
    /// cannot be rewritten. Their original namespace is retained in provenance.
    pub fn plan_import(
        &self,
        wallet: &Wallet,
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<ImportPlan> {
        let mut used: BTreeSet<_> = wallet.entries().keys().copied().collect();
        let mut ids = IdMap::new();
        let mut item_ids = IdMap::new();
        let accounts = json::array(self.as_json(), "accounts")?;
        for account in accounts {
            let account_id = json::id(&account["id"])?;
            for item in json::array(account, "items")? {
                allocate(item, &account_id, &mut ids, &mut used, rng)?;
                let key = (account_id.clone(), json::id(&item["id"])?);
                item_ids.insert(key.clone(), ids[&key]);
            }
            for collection in json::array(account, "collections")? {
                allocate_tree(collection, &account_id, &mut ids, &mut used, rng)?;
            }
        }
        let mut report = ImportReport {
            accounts: accounts.len(),
            ..Default::default()
        };
        let mut entries = Vec::new();
        let header = metadata_without(self.as_json(), &["accounts"]);
        for account in accounts {
            let account_id = json::id(&account["id"])?;
            let metadata = metadata_without(account, &["items", "collections"]);
            let items = json::array(account, "items")?;
            let collections = json::array(account, "collections")?;
            report.items += items.len();
            report.root_collections += collections.len();
            report.empty_accounts += usize::from(items.is_empty() && collections.is_empty());
            for (entity, kind) in items
                .iter()
                .map(|v| (v, PayloadKind::Item))
                .chain(collections.iter().map(|v| (v, PayloadKind::Collection)))
            {
                let entry = ids[&(account_id.clone(), json::id(&entity["id"])?)];
                let mut body = SecretJson(entity.clone());
                match kind {
                    PayloadKind::Item => {
                        body.0["id"] = encoded(entry);
                        for credential in body.0["credentials"].as_array_mut().unwrap() {
                            match credential["type"].as_str().unwrap() {
                                "item-reference" => rewrite_link(
                                    &mut credential["reference"],
                                    &account_id,
                                    &item_ids,
                                    &mut report,
                                )?,
                                "basic-auth" | "passkey" | "note" => {}
                                "totp"
                                    if matches!(
                                        credential["algorithm"].as_str(),
                                        Some("sha1" | "sha256" | "sha512")
                                    ) => {}
                                "file" => {
                                    report.external_files += 1;
                                    report.opaque_credentials += 1;
                                }
                                _ => report.opaque_credentials += 1,
                            }
                        }
                    }
                    PayloadKind::Collection => {
                        rewrite_tree(&mut body.0, &account_id, &ids, &item_ids, &mut report)?
                    }
                }
                let source =
                    json!({"header": header.0, "account": metadata.0, "originalId": entity["id"]});
                entries.push(Payload::build(
                    entry,
                    kind,
                    body.0.take(),
                    source,
                    self.as_json()["version"]["minor"].as_u64().unwrap() as u8,
                )?);
            }
        }
        Ok(ImportPlan { entries, report })
    }
}

impl ImportPlan {
    /// Counts of imported and retained-but-unsupported data.
    pub fn report(&self) -> ImportReport {
        self.report
    }
    /// Plaintext payloads for review. Never log their contents.
    pub fn entries(&self) -> &[Payload] {
        &self.entries
    }

    /// Encrypt all planned payloads for explicitly selected registered keys and
    /// return a new snapshot only after the entire operation succeeds.
    /// No existing entry is replaced, even if a plan is applied to another wallet.
    pub fn encrypt_into(
        &self,
        wallet: &Wallet,
        recipients: &[KeyId],
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<Wallet> {
        if recipients.is_empty()
            || recipients.iter().collect::<BTreeSet<_>>().len() != recipients.len()
        {
            return Err(Error::InvalidRecipients);
        }
        let keys = recipients
            .iter()
            .map(|id| {
                wallet
                    .participants()
                    .get(id)
                    .cloned()
                    .ok_or(Error::InvalidRecipients)
            })
            .collect::<Result<Vec<_>>>()?;
        if self
            .entries
            .iter()
            .any(|p| wallet.entries().contains_key(&p.entry_id()))
        {
            return Err(Error::DuplicateId);
        }
        let imported = self
            .entries
            .iter()
            .map(|p| p.seal(&keys, rng))
            .collect::<Result<Vec<_>>>()?;
        Ok(Wallet::from_parts(
            wallet.participants().values().cloned(),
            wallet.entries().values().cloned().chain(imported),
        )?)
    }
}

fn encoded(id: EntryId) -> Value {
    data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()).into()
}

fn metadata_without(value: &Value, excluded: &[&str]) -> SecretJson {
    SecretJson(Value::Object(
        value
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| !excluded.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

fn allocate(
    value: &Value,
    account: &[u8],
    ids: &mut IdMap,
    used: &mut BTreeSet<EntryId>,
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<()> {
    // Bounded retries avoid hanging forever with a broken/repeating RNG.
    for _ in 0..16 {
        let fresh = EntryId::generate(rng)?;
        if used.insert(fresh) {
            ids.insert((account.to_vec(), json::id(&value["id"])?), fresh);
            return Ok(());
        }
    }
    Err(kagitaba_core::Error::Randomness.into())
}

fn allocate_tree(
    value: &Value,
    account: &[u8],
    ids: &mut IdMap,
    used: &mut BTreeSet<EntryId>,
    rng: &mut (impl TryCryptoRng + ?Sized),
) -> Result<()> {
    allocate(value, account, ids, used, rng)?;
    for child in json::optional_array(value, "subCollections")? {
        allocate_tree(child, account, ids, used, rng)?;
    }
    Ok(())
}

fn rewrite_link(
    link: &mut Value,
    account: &[u8],
    items: &IdMap,
    report: &mut ImportReport,
) -> Result<()> {
    let target_account = match link.get("account") {
        Some(v) => json::id(v)?,
        None => account.to_vec(),
    };
    let item = json::id(&link["item"])?;
    if let Some(id) = items.get(&(target_account.clone(), item)) {
        link["item"] = encoded(*id);
        link.as_object_mut().unwrap().remove("account");
    } else {
        // Explicit source-account qualification prevents accidental resolution
        // against unrelated local IDs after flattening accounts into a wallet.
        link["account"] = data_encoding::BASE64URL_NOPAD
            .encode(&target_account)
            .into();
        report.unresolved_links += 1;
    }
    Ok(())
}

fn rewrite_tree(
    value: &mut Value,
    account: &[u8],
    ids: &IdMap,
    items: &IdMap,
    report: &mut ImportReport,
) -> Result<()> {
    value["id"] = encoded(ids[&(account.to_vec(), json::id(&value["id"])?)]);
    for link in value["items"].as_array_mut().unwrap() {
        rewrite_link(link, account, items, report)?;
    }
    if let Some(children) = value.get_mut("subCollections") {
        for child in children.as_array_mut().ok_or(Error::InvalidDocument)? {
            rewrite_tree(child, account, ids, items, report)?;
        }
    }
    Ok(())
}

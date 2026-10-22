//! Bounded encrypted transport preserving the complete signed Git graph.
use crate::{Error, Result, Store};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use gix::objs::Write;

pub(crate) fn validate_browser(
    value: &serde_json::Value,
    encryption: &kagitaba_core::crypto::PublicKey,
    signing: &kagitaba_core::crypto::PublicKey,
) -> Result<()> {
    let obj = value.as_object().ok_or(Error::Invalid)?;
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
    if obj.len() != allowed.len()
        || obj.keys().any(|k| !allowed.contains(&k.as_str()))
        || value["format"] != "kagitaba-browser-installation"
        || value["version"] != 1
        || value["participantPem"] != encryption.to_pem()
        || value["participantId"] != encryption.id().to_string()
        || value["signingPem"] != signing.to_pem()
        || value["signingId"] != signing.id().to_string()
        || serde_json::to_vec(value).map_err(|_| Error::Invalid)?.len() > 65536
    {
        return Err(Error::Invalid);
    }
    let id = value["installationId"].as_str().ok_or(Error::Invalid)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Invalid);
    }
    let unlock = value["unlock"].as_object().ok_or(Error::Invalid)?;
    if unlock.len() != 3
        || !unlock.contains_key("rpId")
        || !unlock.contains_key("prfInput")
        || !unlock.contains_key("credentialId")
        || unlock["rpId"] != "kagitaba.local"
    {
        return Err(Error::Invalid);
    }
    for (field, min, max) in [("prfInput", 32, 32), ("credentialId", 1, 1024)] {
        let bytes = URL_SAFE_NO_PAD
            .decode(unlock[field].as_str().ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        if bytes.len() < min || bytes.len() > max {
            return Err(Error::Invalid);
        }
    }
    let envelope = URL_SAFE_NO_PAD
        .decode(value["envelope"].as_str().ok_or(Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    if envelope.len() != 144 || !envelope.starts_with(b"KTC1") {
        return Err(Error::Invalid);
    }
    Ok(())
}

impl Store {
    /// Export committed encrypted records, history and public trust hints. The
    /// receiving client must independently confirm the root/checkpoint.
    pub fn export_transfer(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.export_transfer_to(&mut bytes)?;
        Ok(bytes)
    }

    /// Stream encrypted transport to a caller-owned staging sink. Discard the
    /// sink on failure. JSON bridge callers can use the buffered convenience API.
    pub fn export_transfer_to(&self, output: &mut impl std::io::Write) -> Result<()> {
        use std::io::Write;
        super::verify_history(&self.repo, self.head, &self.root_signer, Some(self.head))?;
        output
            .write_all(b"{\"format\":\"kagitaba-git-transfer\",\"version\":1,\"head\":")
            .map_err(|_| Error::Io)?;
        serde_json::to_writer(&mut *output, &self.head.to_string()).map_err(|_| Error::Io)?;
        output.write_all(b",\"root\":").map_err(|_| Error::Io)?;
        serde_json::to_writer(&mut *output, &self.root_signer.to_pem()).map_err(|_| Error::Io)?;
        output.write_all(b",\"objects\":[").map_err(|_| Error::Io)?;
        let mut pending = vec![self.head];
        let mut seen = std::collections::BTreeSet::new();
        let mut budget = 512 * 1024 * 1024u64;
        let mut first = true;
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let header = self.repo.find_header(id).map_err(|_| Error::Invalid)?;
            if seen.len() > 200_000
                || header.size() > kagitaba_cxf::attachments::MAX_BLOB_BYTES as u64
                || header.size() > budget
            {
                return Err(Error::Invalid);
            }
            budget -= header.size();
            let kind = match header.kind() {
                gix::objs::Kind::Commit => {
                    let c = super::commit(&self.repo, id)?;
                    pending.push(c.tree);
                    pending.extend(c.parents);
                    "commit"
                }
                gix::objs::Kind::Tree => {
                    let obj = self.repo.find_object(id).map_err(|_| Error::Invalid)?;
                    let tree = gix::objs::TreeRef::from_bytes(&obj.data, gix::hash::Kind::Sha1)
                        .map_err(|_| Error::Invalid)?;
                    pending.extend(tree.entries.iter().map(|e| e.oid.to_owned()));
                    "tree"
                }
                gix::objs::Kind::Blob => "blob",
                _ => return Err(Error::Invalid),
            };
            if !first {
                output.write_all(b",").map_err(|_| Error::Io)?;
            }
            first = false;
            write!(output, "{{\"oid\":\"{id}\",\"type\":\"{kind}\",\"data\":\"")
                .map_err(|_| Error::Io)?;
            {
                let mut encoded = base64::write::EncoderWriter::new(&mut *output, &URL_SAFE_NO_PAD);
                if header.kind() == gix::objs::Kind::Blob {
                    let blob =
                        super::AttachmentBlob::from_git(&self.repo, id, header.size() as usize);
                    std::io::copy(&mut blob.open()?, &mut encoded).map_err(|_| Error::Io)?;
                } else {
                    let obj = self.repo.find_object(id).map_err(|_| Error::Invalid)?;
                    if gix::objs::compute_hash(gix::hash::Kind::Sha1, obj.kind, &obj.data)
                        .map_err(|_| Error::Invalid)?
                        != id
                    {
                        return Err(Error::Invalid);
                    }
                    encoded.write_all(&obj.data).map_err(|_| Error::Io)?;
                }
                encoded.finish().map_err(|_| Error::Io)?;
            }
            output.write_all(b"\"}").map_err(|_| Error::Io)?;
        }
        output.write_all(b"]}").map_err(|_| Error::Io)
    }

    /// Import objects in quarantine, then verify signatures and ancestry before
    /// changing the accepted branch. Transfer trust hints are never authoritative.
    pub fn import_transfer(&mut self, input: &[u8]) -> Result<()> {
        if input.len() > 768 * 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let value: serde_json::Value = serde_json::from_slice(input).map_err(|_| Error::Invalid)?;
        // The extension's encrypted backup includes installation recovery data
        // beside the Git transfer. Only signed Git bytes are imported here.
        let value = value.get("wallet").unwrap_or(&value);
        if value["format"] != "kagitaba-git-transfer" || value["version"] != 1 {
            return Err(Error::Invalid);
        }
        let head = super::parse_oid(value["head"].as_str().ok_or(Error::Invalid)?)?;
        let objects = value["objects"].as_array().ok_or(Error::Invalid)?;
        if objects.len() > 200_000 {
            return Err(Error::Invalid);
        }
        let mut budget = 512 * 1024 * 1024usize;
        for object in objects {
            let id = super::parse_oid(object["oid"].as_str().ok_or(Error::Invalid)?)?;
            let kind = match object["type"].as_str() {
                Some("commit") => gix::objs::Kind::Commit,
                Some("tree") => gix::objs::Kind::Tree,
                Some("blob") => gix::objs::Kind::Blob,
                _ => return Err(Error::Invalid),
            };
            let text = object["data"].as_str().ok_or(Error::Invalid)?;
            if text.len() > kagitaba_cxf::attachments::MAX_BLOB_BYTES.div_ceil(3) * 4 {
                return Err(Error::Invalid);
            }
            let data = URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Invalid)?;
            if data.len() > kagitaba_cxf::attachments::MAX_BLOB_BYTES || data.len() > budget {
                return Err(Error::Invalid);
            }
            budget -= data.len();
            if gix::objs::compute_hash(gix::hash::Kind::Sha1, kind, &data)
                .map_err(|_| Error::Invalid)?
                != id
            {
                return Err(Error::Invalid);
            }
            if self
                .repo
                .objects
                .write_buf(kind, &data)
                .map_err(|_| Error::Io)?
                != id
            {
                return Err(Error::Invalid);
            }
        }
        self.accept(head)
    }
}

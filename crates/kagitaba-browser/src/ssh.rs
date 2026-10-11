//! Wire-compatible with kagitaba-store's SSHSIG P-256 Git signatures.
use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToSec1Point,
    pkcs8::DecodePublicKey,
};
use ssh_key::{HashAlg, SshSig};

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn mpint(out: &mut Vec<u8>, mut bytes: &[u8]) {
    while bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    let mut n = Vec::new();
    if bytes.first().is_some_and(|b| b & 128 != 0) {
        n.push(0);
    }
    n.extend_from_slice(bytes);
    field(out, &n);
}
fn ssh_public(key: &PublicKey) -> Result<ssh_key::PublicKey> {
    let key = p256::PublicKey::from_public_key_der(&key.to_der()).map_err(|_| Error)?;
    let mut bytes = Vec::new();
    field(&mut bytes, b"ecdsa-sha2-nistp256");
    field(&mut bytes, b"nistp256");
    field(&mut bytes, key.to_sec1_point(false).as_bytes());
    ssh_key::PublicKey::from_bytes(&bytes).map_err(|_| Error)
}
pub(super) fn operation(request: &Value) -> Result<Value> {
    match string(request, "op")? {
        "ssh_sign" => {
            let identity = Identity::parse(&binary(request, "identity")?)?;
            let key = ssh_public(&public(&identity.signing)?)?;
            let bytes = binary(request, "message")?;
            let signed = SshSig::signed_data("git", HashAlg::Sha512, &bytes).map_err(|_| Error)?;
            let signing = SigningKey::from(identity.signing);
            let signature: Signature = signing.sign(&signed);
            let (r, s) = signature.split_bytes();
            let mut wire = Vec::new();
            mpint(&mut wire, &r);
            mpint(&mut wire, &s);
            let signature = ssh_key::Signature::new(
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256,
                },
                wire,
            )
            .map_err(|_| Error)?;
            let signature = SshSig::new(key.key_data().clone(), "git", HashAlg::Sha512, signature)
                .map_err(|_| Error)?;
            key.verify("git", &bytes, &signature).map_err(|_| Error)?;
            Ok(json!({"signature": signature.to_pem(ssh_key::LineEnding::LF).map_err(|_| Error)?}))
        }
        "ssh_verify" => {
            let key = PublicKey::from_pem(string(request, "publicKey")?).map_err(|_| Error)?;
            let signature = SshSig::from_pem(string(request, "signature")?).map_err(|_| Error)?;
            ssh_public(&key)?
                .verify("git", &binary(request, "message")?, &signature)
                .map_err(|_| Error)?;
            Ok(json!({"valid": true}))
        }
        "ssh_inspect" => {
            let signature = SshSig::from_pem(string(request, "signature")?).map_err(|_| Error)?;
            let ssh_key::public::EcdsaPublicKey::NistP256(point) =
                signature.public_key().ecdsa().ok_or(Error)?
            else {
                return Err(Error);
            };
            let key = p256::PublicKey::from_sec1_bytes(point.as_bytes()).map_err(|_| Error)?;
            let key = PublicKey::from_der(key.to_public_key_der().map_err(|_| Error)?.as_bytes())
                .map_err(|_| Error)?;
            Ok(json!({"publicKey": key.to_pem(), "id": key.id().to_string()}))
        }
        _ => Err(Error),
    }
}

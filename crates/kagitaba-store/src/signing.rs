use crate::{Error, Result};
use kagitaba_core::crypto::PublicKey;
use p256::{
    elliptic_curve::sec1::ToSec1Point,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use ssh_key::{HashAlg, SshSig};
pub trait Signer {
    fn public_key(&self) -> &PublicKey;
    /// ECDSA/SHA-256, DER encoded. Transport and touch/PIN belong to the caller.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}
pub fn ssh_public(key: &PublicKey) -> Result<ssh_key::PublicKey> {
    let key = p256::PublicKey::from_public_key_der(&key.to_der()).map_err(|_| Error::Signature)?;
    let mut wire = Vec::new();
    field(&mut wire, b"ecdsa-sha2-nistp256");
    field(&mut wire, b"nistp256");
    field(&mut wire, key.to_sec1_point(false).as_bytes());
    ssh_key::PublicKey::from_bytes(&wire).map_err(|_| Error::Signature)
}
pub fn from_ssh(key: &ssh_key::public::KeyData) -> Result<PublicKey> {
    let key = key.ecdsa().ok_or(Error::Signature)?;
    let point = match key {
        ssh_key::public::EcdsaPublicKey::NistP256(p) => p.as_bytes(),
        _ => return Err(Error::Signature),
    };
    let key = p256::PublicKey::from_sec1_bytes(point).map_err(|_| Error::Signature)?;
    PublicKey::from_der(
        key.to_public_key_der()
            .map_err(|_| Error::Signature)?
            .as_bytes(),
    )
    .map_err(Error::Core)
}
pub fn sign(signer: &impl Signer, commit: &[u8]) -> Result<String> {
    let public = ssh_public(signer.public_key())?;
    let message =
        SshSig::signed_data("git", HashAlg::Sha512, commit).map_err(|_| Error::Signature)?;
    let der = signer.sign(&message)?;
    let signature = p256::ecdsa::Signature::from_der(&der).map_err(|_| Error::Signature)?;
    let (r, s) = signature.split_bytes();
    let mut wire = Vec::new();
    mpint(&mut wire, &r);
    mpint(&mut wire, &s);
    let sig = ssh_key::Signature::new(
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
        wire,
    )
    .map_err(|_| Error::Signature)?;
    let sig = SshSig::new(public.key_data().clone(), "git", HashAlg::Sha512, sig)
        .map_err(|_| Error::Signature)?;
    public
        .verify("git", commit, &sig)
        .map_err(|_| Error::Signature)?;
    sig.to_pem(ssh_key::LineEnding::LF)
        .map_err(|_| Error::Signature)
}
fn field(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}
fn mpint(out: &mut Vec<u8>, mut data: &[u8]) {
    while data.first() == Some(&0) {
        data = &data[1..];
    }
    let mut value = Vec::new();
    if data.first().is_some_and(|v| v & 128 != 0) {
        value.push(0);
    }
    value.extend_from_slice(data);
    field(out, &value);
}

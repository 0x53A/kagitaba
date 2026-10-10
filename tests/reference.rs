use futures::executor::block_on;
use kagitaba_core::{
    Error,
    crypto::{Ciphertext, ContentKey, PublicKey, SoftwareIdentity, WrappedKey},
};
use rand_core::{TryCryptoRng, TryRng};

#[path = "fixtures/reference.rs"]
mod vectors;

// Only for public test fixtures. Production callers must provide a real CSPRNG.
struct ScriptedRng(Vec<u8>);
impl TryRng for ScriptedRng {
    type Error = Error;
    fn try_next_u32(&mut self) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() > self.0.len() {
            return Err(Error::Randomness);
        }
        out.copy_from_slice(&self.0[..out.len()]);
        self.0.drain(..out.len());
        Ok(())
    }
}
impl TryCryptoRng for ScriptedRng {}

#[test]
fn independent_openssl_and_libsodium_vectors_match_both_directions() {
    let context = hex::decode(vectors::CONTEXT).unwrap();
    let plaintext = hex::decode(vectors::PLAINTEXT).unwrap();
    let expected_payload = hex::decode(vectors::PAYLOAD).unwrap();
    let expected_grant = hex::decode(vectors::GRANT).unwrap();
    let public = PublicKey::from_der(&hex::decode(vectors::PUBLIC_DER).unwrap()).unwrap();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let identity = SoftwareIdentity::from_bytes(&scalar).unwrap();
    assert_eq!(identity.public_key(), public);
    let key = block_on(
        WrappedKey::from_bytes(&expected_grant)
            .unwrap()
            .unwrap(&public, &context, &identity),
    )
    .unwrap();
    assert_eq!(key.as_bytes(), &[0x42; 32]);
    assert_eq!(
        Ciphertext::from_bytes(&expected_payload)
            .unwrap()
            .open(&key, &context)
            .unwrap()
            .as_bytes(),
        plaintext
    );

    let generated = Ciphertext::seal(
        &plaintext,
        &ContentKey::from_bytes([0x42; 32]),
        &context,
        &mut ScriptedRng((0..24).collect()),
    )
    .unwrap();
    assert_eq!(generated.as_bytes(), expected_payload);

    // Force ephemeral scalar 2, then the same nonce used by the reference tool.
    scalar[31] = 2;
    let mut random_bytes = scalar.to_vec();
    random_bytes.extend(0..24);
    let wrapped =
        WrappedKey::wrap(&key, &public, &context, &mut ScriptedRng(random_bytes)).unwrap();
    assert_eq!(wrapped.as_bytes(), expected_grant);
}

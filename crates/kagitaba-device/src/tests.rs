use super::*;
use std::collections::VecDeque;
use zeroize::Zeroizing;
struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);
impl Transport for Script {
    fn exchange(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (expected, response) = self.0.pop_front().expect("unexpected hardware operation");
        assert_eq!(command, expected);
        Ok(Zeroizing::new(response))
    }
}
impl Drop for Script {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.0.is_empty(), "not all hardware operations performed");
        }
    }
}
fn script(steps: Vec<(Vec<u8>, Vec<u8>)>) -> Piv<Script> {
    let mut all = VecDeque::from([(
        vec![0, 0xa4, 4, 0, 9, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0],
        vec![0x90, 0],
    )]);
    all.extend(steps);
    Piv::new(Script(all)).unwrap()
}
#[test]
fn pin_padding_and_single_attempt_failure() {
    let mut card = script(vec![(
        vec![
            0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
        ],
        vec![0x63, 0xc2],
    )]);
    assert!(matches!(card.verify_pin("123456"), Err(Error::Pin(2))));
}
#[test]
fn blocked_pin_and_invalid_input_do_not_retry() {
    let mut card = script(vec![(
        vec![
            0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
        ],
        vec![0x69, 0x83],
    )]);
    assert!(matches!(card.verify_pin("x"), Err(Error::InvalidPin)));
    assert!(matches!(card.verify_pin("123456"), Err(Error::Blocked)));
}
#[test]
fn provisioning_never_overwrites_occupied_or_unknown_slots() {
    let mut card = script(vec![
        (vec![0, 0xf7, 0, 0x82], vec![1, 1, 0x11, 0x90, 0]),
        (vec![0, 0xf7, 0, 0x83], vec![0x6d, 0]),
    ]);
    assert!(matches!(
        card.generate_empty(0x82, true),
        Err(Error::Occupied)
    ));
    assert!(matches!(
        card.generate_empty(0x83, false),
        Err(Error::Status(0x6d00))
    ));
    assert!(matches!(
        card.generate_empty(0x9a, false),
        Err(Error::Unsupported)
    ));
}
#[test]
fn agreement_apdu_and_continued_response() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let secret = p256::SecretKey::from_slice(&[7; 32]).unwrap();
    let point = secret.public_key().to_sec1_point(false);
    let peer: &[u8; 65] = point.as_bytes().try_into().unwrap();
    let mut command = vec![0, 0x87, 0x11, 0x82, 71, 0x7c, 69, 0x82, 0, 0x85, 65];
    command.extend_from_slice(peer);
    let mut first = vec![0x7c, 34, 0x82, 32];
    first.extend_from_slice(&[9; 16]);
    first.extend_from_slice(&[0x61, 16]);
    let mut last = vec![9; 16];
    last.extend_from_slice(&[0x90, 0]);
    let mut card = script(vec![(command, first), (vec![0, 0xc0, 0, 0, 16], last)]);
    assert!(card.agree(0x82, peer).is_ok());
}
#[test]
fn malformed_ecdh_response_is_rejected() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = p256::SecretKey::from_slice(&[7; 32])
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    let peer: &[u8; 65] = point.as_bytes().try_into().unwrap();
    let mut command = vec![0, 0x87, 0x11, 0x82, 71, 0x7c, 69, 0x82, 0, 0x85, 65];
    command.extend_from_slice(peer);
    let mut card = script(vec![(command, vec![0x7c, 3, 0x82, 1, 0, 0x90, 0])]);
    assert!(matches!(card.agree(0x82, peer), Err(Error::Protocol)));
}
#[test]
fn management_authentication_matches_aes_known_answer() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let challenge = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let expected = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
    let mut response = vec![0x7c, 18, 0x81, 16];
    response.extend(challenge);
    response.extend([0x90, 0]);
    let mut command = vec![0, 0x87, 8, 0x9b, 20, 0x7c, 18, 0x82, 16];
    command.extend(expected);
    let mut card = script(vec![
        (vec![0, 0xf7, 0, 0x9b], vec![1, 1, 8, 0x90, 0]),
        (vec![0, 0x87, 8, 0x9b, 4, 0x7c, 2, 0x81, 0], response),
        (command, vec![0x90, 0]),
    ]);
    card.authenticate_management(&key).unwrap();
}
#[test]
fn generation_sets_pin_and_touch_policy_explicitly() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = p256::SecretKey::from_slice(&[7; 32])
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    let mut response = vec![0x7f, 0x49, 67, 0x86, 65];
    response.extend_from_slice(point.as_bytes());
    response.extend([0x90, 0]);
    for (slot, touch) in [(0x82, 3), (0x83, 2)] {
        let mut card = script(vec![
            (vec![0, 0xf7, 0, slot], vec![0x6a, 0x88]),
            (
                vec![
                    0, 0x47, 0, slot, 11, 0xac, 9, 0x80, 1, 0x11, 0xaa, 1, 2, 0xab, 1, touch,
                ],
                response.clone(),
            ),
        ]);
        assert!(card.generate_empty(slot, touch == 3).is_ok());
    }
}

#[test]
fn hardware_session_unwraps_real_envelopes_and_signs_verifiable_messages() {
    use kagitaba_core::crypto::{ContentKey, WrappedKey};
    use p256::{
        ecdsa::{
            Signature, SigningKey,
            signature::{Verifier, hazmat::PrehashSigner},
        },
        elliptic_curve::sec1::ToSec1Point,
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    struct Card {
        encryption: p256::SecretKey,
        signing: SigningKey,
        verified: bool,
    }
    impl Transport for Card {
        fn exchange(&mut self, apdu: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let mut out = match apdu[1] {
                0xa4 => vec![],
                0x20 => {
                    self.verified = true;
                    vec![]
                }
                0xf7 => {
                    let point = if apdu[3] == 0x82 {
                        self.encryption.public_key().to_sec1_point(false)
                    } else {
                        self.signing.verifying_key().to_sec1_point(false)
                    };
                    let mut v = vec![1, 1, 0x11, 4, 67, 0x86, 65];
                    v.extend_from_slice(point.as_bytes());
                    v
                }
                0x87 => {
                    assert!(self.verified);
                    let value = if apdu[3] == 0x82 {
                        assert_eq!(&apdu[5..11], &[0x7c, 69, 0x82, 0, 0x85, 65]);
                        let peer = p256::PublicKey::from_sec1_bytes(&apdu[11..]).unwrap();
                        p256::ecdh::diffie_hellman(
                            self.encryption.to_nonzero_scalar(),
                            peer.as_affine(),
                        )
                        .raw_secret_bytes()
                        .to_vec()
                    } else {
                        assert_eq!(&apdu[5..11], &[0x7c, 36, 0x82, 0, 0x81, 32]);
                        let sig: Signature = self.signing.sign_prehash(&apdu[11..]).unwrap();
                        sig.to_der().as_bytes().to_vec()
                    };
                    let mut v = vec![0x7c, (value.len() + 2) as u8, 0x82, value.len() as u8];
                    v.extend(value);
                    v
                }
                _ => panic!("unexpected APDU"),
            };
            out.extend([0x90, 0]);
            Ok(Zeroizing::new(out))
        }
    }
    let signing = SigningKey::from_slice(&[6; 32]).unwrap();
    let verifier = *signing.verifying_key();
    let card = Card {
        encryption: p256::SecretKey::from_slice(&[8; 32]).unwrap(),
        signing,
        verified: false,
    };
    let session = Session::unlock(Piv::new(card).unwrap(), "123456").unwrap();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = ContentKey::generate(&mut rng).unwrap();
    let wrap = WrappedKey::wrap(&key, &session.encryption, b"fixture", &mut rng).unwrap();
    let recovered =
        futures::executor::block_on(wrap.unwrap(&session.encryption, b"fixture", &session))
            .unwrap();
    let ciphertext =
        kagitaba_core::crypto::Ciphertext::seal(b"synthetic secret", &key, b"payload", &mut rng)
            .unwrap();
    assert_eq!(
        ciphertext.open(&recovered, b"payload").unwrap().as_bytes(),
        b"synthetic secret"
    );
    let signature = Signature::from_der(&session.sign(b"signed wallet commit").unwrap()).unwrap();
    verifier
        .verify(b"signed wallet commit", &signature)
        .unwrap();
    assert!(verifier.verify(b"altered commit", &signature).is_err());
}

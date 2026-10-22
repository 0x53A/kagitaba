use kagitaba_cxf::{Payload, otp, password::Rules};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::json;

#[test]
fn generation_respects_every_rule_and_has_no_fixed_positions() {
    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let defaults = Rules::default();
    assert_eq!(defaults.alphabet().unwrap(), "acdefhjkmnprtuvwxy347");
    let mut first_digit = false;
    let mut first_letter = false;
    for _ in 0..128 {
        let p = defaults.generate(&mut rng).unwrap();
        assert_eq!(p.len(), 12);
        assert!(
            p.bytes()
                .all(|b| defaults.alphabet().unwrap().contains(b as char))
        );
        assert!(p.bytes().any(|b| b.is_ascii_digit()));
        assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
        first_digit |= p.as_bytes()[0].is_ascii_digit();
        first_letter |= p.as_bytes()[0].is_ascii_lowercase();
    }
    assert!(first_digit && first_letter);
    let rules = Rules {
        length: 4,
        uppercase: true,
        symbols: true,
        symbol_set: "!!!".into(),
        ..defaults
    };
    for _ in 0..32 {
        let p = rules.generate(&mut rng).unwrap();
        assert!(p.contains('!'));
        assert!(p.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(p.bytes().any(|b| b.is_ascii_digit()));
    }
    for rules in [
        Rules {
            length: 0,
            ..Rules::default()
        },
        Rules {
            length: 1,
            ..Rules::default()
        },
        Rules {
            digits: false,
            lowercase: false,
            ..Rules::default()
        },
        Rules {
            exclusions: "abcdefghijklmnopqrstuvwxyz".into(),
            ..Rules::default()
        },
    ] {
        assert!(rules.generate(&mut rng).is_err());
    }
    assert_eq!(
        Rules {
            length: 1024,
            ..Rules::default()
        }
        .generate(&mut rng)
        .unwrap()
        .len(),
        1024
    );
}

#[test]
fn totp_storage_preserves_large_period_and_unknown_fields() {
    let id = kagitaba_core::EntryId::from_bytes([7; 16]);
    let credential = otp::parse(
        "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=300&digits=9",
    )
    .unwrap();
    let raw = json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"item","entity":{"id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Test","credentials":[credential],"vendor":{"type":"totp","period":"opaque"},"scope":{"urls":["http://localhost/path?q=a#b","ssh://host","bare host"],"androidApps":[]}}});
    let payload = Payload::from_json(id, raw.to_string().as_bytes()).unwrap();
    let roundtrip: serde_json::Value = serde_json::from_slice(&payload.to_json().unwrap()).unwrap();
    assert_eq!(roundtrip, raw);
    assert!(otp::code(&credential, 59).is_err());
    let mut supported = credential;
    supported["digits"] = 8.into();
    supported["period"] = 30.into();
    assert_eq!(otp::code(&supported, 59).unwrap().0.as_str(), "94287082");
    supported["period"] = 300.into();
    assert!(otp::code(&supported, 59).is_ok());
    for uri in [
        "https://example.com",
        "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&secret=AAAA",
    ] {
        assert!(otp::parse(uri).is_err());
    }
}

#[test]
fn qr_camera_frames_and_images_share_decoder() {
    let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=300";
    let qr = qrcode::QrCode::new(uri).unwrap();
    let width = (qr.width() + 8) * 5;
    let mut gray = vec![255; width * width];
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr[(x, y)] == qrcode::Color::Dark {
                for dy in 0..5 {
                    for dx in 0..5 {
                        gray[((y + 4) * 5 + dy) * width + (x + 4) * 5 + dx] = 0;
                    }
                }
            }
        }
    }
    assert_eq!(otp::scan(width, width, &gray).unwrap()[0].as_str(), uri);
    let rotated: Vec<u8> = (0..width * width)
        .map(|i| gray[(width - 1 - i % width) * width + i / width])
        .collect();
    assert_eq!(otp::scan(width, width, &rotated).unwrap()[0].as_str(), uri);
    assert!(otp::scan(2049, 1, &vec![255; 2049]).is_err());
    assert!(otp::scan(8, 8, &[255; 64]).is_err());
}

struct FixedEntropy(bool);
impl rand_chacha::rand_core::TryRng for FixedEntropy {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        if self.0 {
            Err(std::io::Error::other("synthetic failure"))
        } else {
            Ok(0)
        }
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.try_next_u32().map(u64::from)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.try_next_u32()?;
        dst.fill(0);
        Ok(())
    }
}
impl rand_chacha::rand_core::TryCryptoRng for FixedEntropy {}
#[test]
fn entropy_failure_and_cross_client_rank_zero_vector() {
    assert!(Rules::default().generate(&mut FixedEntropy(true)).is_err());
    assert_eq!(
        Rules::default()
            .generate(&mut FixedEntropy(false))
            .unwrap()
            .as_str(),
        "aaaaaaaaaaa3"
    );
}

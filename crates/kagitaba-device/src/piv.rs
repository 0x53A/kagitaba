use aes::cipher::{BlockCipherEncrypt, KeyInit};
use kagitaba_core::{
    KeyId,
    crypto::{AgreementRequest, AgreementSecret, KeyAgreement, PublicKey},
};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use zeroize::Zeroizing;
pub const ENCRYPTION_SLOT: u8 = 0x82;
pub const SIGNING_SLOT: u8 = 0x83;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    Never,
    Once,
    Always,
    Unknown(u8),
}
impl PinPolicy {
    pub fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Never,
            2 => Self::Once,
            3 => Self::Always,
            other => Self::Unknown(other),
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::Never => 1,
            Self::Once => 2,
            Self::Always => 3,
            Self::Unknown(value) => value,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
    Unknown(u8),
}
impl TouchPolicy {
    pub fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Never,
            2 => Self::Always,
            3 => Self::Cached,
            other => Self::Unknown(other),
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::Never => 1,
            Self::Always => 2,
            Self::Cached => 3,
            Self::Unknown(value) => value,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    pub pin: PinPolicy,
    pub touch: TouchPolicy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policies {
    pub encryption: KeyPolicy,
    pub signing: KeyPolicy,
}
impl Default for Policies {
    fn default() -> Self {
        Self {
            encryption: KeyPolicy {
                pin: PinPolicy::Once,
                touch: TouchPolicy::Cached,
            },
            signing: KeyPolicy {
                pin: PinPolicy::Once,
                touch: TouchPolicy::Always,
            },
        }
    }
}
pub struct KeyMetadata {
    pub public_key: PublicKey,
    pub policy: Option<KeyPolicy>,
}
/// A private command is in flight, not proof that the card is waiting for touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOperation {
    Started(Option<TouchPolicy>),
    Finished,
}
/// Application keys use two distinct retired key-management slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slots {
    encryption: u8,
    signing: u8,
}
impl Slots {
    pub fn new(encryption: u8, signing: u8) -> Result<Self> {
        check_slot(encryption)?;
        check_slot(signing)?;
        if encryption == signing {
            return Err(Error::InvalidSlots);
        }
        Ok(Self {
            encryption,
            signing,
        })
    }
    pub fn encryption(self) -> u8 {
        self.encryption
    }
    pub fn signing(self) -> u8 {
        self.signing
    }
}
impl Default for Slots {
    fn default() -> Self {
        Self {
            encryption: ENCRYPTION_SLOT,
            signing: SIGNING_SLOT,
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("USB unavailable, busy, or permission denied")]
    Usb,
    #[error("invalid smart-card response")]
    Protocol,
    #[error("PIV command failed (status {0:04x})")]
    Status(u16),
    #[error("incorrect PIN; {0} attempts remaining")]
    Pin(u8),
    #[error("PIN is blocked; do not retry")]
    Blocked,
    #[error("PIN must contain 6–8 ASCII characters")]
    InvalidPin,
    #[error("unsupported algorithm or firmware (requires YubiKey 5.3+ PIV)")]
    Unsupported,
    #[error("slot already contains a key; nothing overwritten")]
    Occupied,
    #[error("choose two distinct PIV slots from 82–95 (hex)")]
    InvalidSlots,
}
pub type Result<T> = std::result::Result<T, Error>;
/// APDU exchanges must be exclusive for the session's lifetime.
pub trait Transport: Send {
    fn exchange(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
pub struct Piv<T: Transport> {
    transport: T,
}
/// A card whose PIN was explicitly verified, retained while the caller selects
/// existing slots or authorizes generation. No PIN is retained or retried.
pub struct AuthenticatedPiv<T: Transport> {
    card: Piv<T>,
}
impl<T: Transport> AuthenticatedPiv<T> {
    pub fn new(mut card: Piv<T>, pin: &str) -> Result<Self> {
        card.verify_pin(pin)?;
        Ok(Self { card })
    }
    pub fn p256_slots(&mut self) -> Result<Vec<u8>> {
        let mut slots = Vec::new();
        for slot in 0x82..=0x95 {
            match self.card.public_key(slot) {
                Ok(_) => slots.push(slot),
                Err(Error::Status(0x6a88) | Error::Unsupported) => {},
                Err(error) => return Err(error),
            }
        }
        Ok(slots)
    }
    pub fn use_slots(mut self, slots: Slots) -> Result<Session<T>> {
        let encryption = self.card.key_metadata(slots.encryption())?;
        let signing = self.card.key_metadata(slots.signing())?;
        Ok(Session { card: Mutex::new(self.card), slots,
            encryption: encryption.public_key, signing: signing.public_key,
            encryption_policy: encryption.policy, signing_policy: signing.policy, observer: None })
    }
    pub fn provision(self, slots: Slots, management_key: &[u8]) -> Result<Session<T>> {
        self.provision_with_policies(slots, management_key, Policies::default())
    }
    pub fn provision_with_policies(mut self, slots: Slots, management_key: &[u8], policies: Policies) -> Result<Session<T>> {
        // Read raw metadata, not only supported keys: any occupied or unreadable
        // slot must prevent BOTH writes, including an unsupported algorithm.
        for slot in [slots.encryption(), slots.signing()] {
            match self.card.command(0xf7, 0, slot, &[]) {
                Err(Error::Status(0x6a88)) => {},
                Ok(_) => return Err(Error::Occupied),
                Err(error) => return Err(error),
            }
        }
        self.card.authenticate_management(management_key)?;
        self.card.generate_empty_with_policy(slots.encryption(), policies.encryption)?;
        self.card.generate_empty_with_policy(slots.signing(), policies.signing)?;
        self.use_slots(slots)
    }
}
impl<T: Transport> Piv<T> {
    pub fn new(transport: T) -> Result<Self> {
        let mut card = Self { transport };
        card.command(0xa4, 4, 0, &[0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0])?;
        Ok(card)
    }
    fn command(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() > 255 {
            return Err(Error::Protocol);
        }
        let mut apdu = Zeroizing::new(vec![0, ins, p1, p2]);
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        let mut out = Zeroizing::new(Vec::new());
        for _ in 0..32 {
            let response = self.transport.exchange(&apdu)?;
            if response.len() < 2 {
                return Err(Error::Protocol);
            }
            let split = response.len() - 2;
            let sw = u16::from_be_bytes([response[split], response[split + 1]]);
            out.extend_from_slice(&response[..split]);
            if out.len() > 8192 {
                return Err(Error::Protocol);
            }
            match sw {
                0x9000 => return Ok(out),
                0x6983 => return Err(Error::Blocked),
                _ if sw & 0xfff0 == 0x63c0 => return Err(Error::Pin((sw & 15) as u8)),
                _ if sw & 0xff00 == 0x6100 => {
                    *apdu = vec![0, 0xc0, 0, 0, (sw & 255) as u8];
                }
                _ => return Err(Error::Status(sw)),
            }
        }
        Err(Error::Protocol)
    }
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        self.command(0x20, 0, 0x80, &*pin_bytes(pin)?)?;
        Ok(())
    }
    /// Read the public device serial without PIN or management authentication.
    pub fn serial_number(&mut self) -> Result<u32> {
        let bytes = self.command(0xf8, 0, 0, &[])?;
        Ok(u32::from_be_bytes(
            bytes.as_slice().try_into().map_err(|_| Error::Protocol)?,
        ))
    }
    pub fn change_pin(&mut self, old: &str, new: &str) -> Result<()> {
        let mut data = Zeroizing::new(Vec::from(&*pin_bytes(old)?));
        data.extend_from_slice(&*pin_bytes(new)?);
        self.command(0x24, 0, 0x80, &data)?;
        Ok(())
    }
    pub fn public_key(&mut self, slot: u8) -> Result<PublicKey> {
        Ok(self.key_metadata(slot)?.public_key)
    }
    pub fn key_metadata(&mut self, slot: u8) -> Result<KeyMetadata> {
        check_slot(slot)?;
        let metadata = self.command(0xf7, 0, slot, &[])?;
        if tag(&metadata, 1)? != [0x11] {
            return Err(Error::Unsupported);
        }
        let policy = optional_tag(&metadata, 2)?
            .map(|bytes| {
                let [pin, touch] = bytes else {
                    return Err(Error::Protocol);
                };
                Ok(KeyPolicy {
                    pin: PinPolicy::from_byte(*pin),
                    touch: TouchPolicy::from_byte(*touch),
                })
            })
            .transpose()?;
        Ok(KeyMetadata {
            public_key: point_key(tag(tag(&metadata, 4)?, 0x86)?)?,
            policy,
        })
    }
    /// Requires explicit user authorization and management authentication.
    /// Never overwrites any slot that cannot be proven empty via metadata.
    pub fn generate_empty(&mut self, slot: u8, touch_cached: bool) -> Result<PublicKey> {
        self.generate_empty_with_policy(
            slot,
            KeyPolicy {
                pin: PinPolicy::Once,
                touch: if touch_cached {
                    TouchPolicy::Cached
                } else {
                    TouchPolicy::Always
                },
            },
        )
    }
    pub fn generate_empty_with_policy(&mut self, slot: u8, policy: KeyPolicy) -> Result<PublicKey> {
        if matches!(policy.pin, PinPolicy::Unknown(_))
            || matches!(policy.touch, TouchPolicy::Unknown(_))
        {
            return Err(Error::Unsupported);
        }
        check_slot(slot)?;
        match self.command(0xf7, 0, slot, &[]) {
            Err(Error::Status(0x6a88)) => {}
            Ok(_) => return Err(Error::Occupied),
            Err(e) => return Err(e),
        }
        let response = self.command(
            0x47,
            0,
            slot,
            &[
                0xac,
                9,
                0x80,
                1,
                0x11,
                0xaa,
                1,
                policy.pin.code(),
                0xab,
                1,
                policy.touch.code(),
            ],
        )?;
        point_key(tag(tag(&response, 0x7f49)?, 0x86)?)
    }
    pub fn authenticate_management(&mut self, key: &[u8]) -> Result<()> {
        let metadata = self.command(0xf7, 0, 0x9b, &[])?;
        let algorithm = *tag(&metadata, 1)?.first().ok_or(Error::Protocol)?;
        let challenge = self.command(0x87, algorithm, 0x9b, &[0x7c, 2, 0x81, 0])?;
        let mut block = Zeroizing::new(tag(tag(&challenge, 0x7c)?, 0x81)?.to_vec());
        macro_rules! encrypt {
            ($ty:ty,$size:expr) => {{
                if block.len() != $size {
                    return Err(Error::Protocol);
                }
                let cipher = <$ty>::new_from_slice(key).map_err(|_| Error::Unsupported)?;
                cipher.encrypt_block(
                    block
                        .as_mut_slice()
                        .try_into()
                        .map_err(|_| Error::Protocol)?,
                );
            }};
        }
        match algorithm {
            3 => encrypt!(des::TdesEde3, 8),
            8 => encrypt!(aes::Aes128, 16),
            10 => encrypt!(aes::Aes192, 16),
            12 => encrypt!(aes::Aes256, 16),
            _ => return Err(Error::Unsupported),
        }
        let mut data = Zeroizing::new(vec![0x7c, (block.len() + 2) as u8, 0x82, block.len() as u8]);
        data.extend_from_slice(&block);
        self.command(0x87, algorithm, 0x9b, &data)?;
        Ok(())
    }
    fn private_operation(
        &mut self,
        slot: u8,
        kind: u8,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        check_slot(slot)?;
        let mut data = Zeroizing::new(vec![
            0x7c,
            (input.len() + 4) as u8,
            0x82,
            0,
            kind,
            input.len() as u8,
        ]);
        data.extend_from_slice(input);
        let response = self.command(0x87, 0x11, slot, &data)?;
        Ok(Zeroizing::new(tag(tag(&response, 0x7c)?, 0x82)?.to_vec()))
    }
    pub fn agree(&mut self, slot: u8, peer: &[u8; 65]) -> Result<AgreementSecret> {
        p256::PublicKey::from_sec1_bytes(peer).map_err(|_| Error::Protocol)?;
        let value = self.private_operation(slot, 0x85, peer)?;
        Ok(AgreementSecret::from_bytes(
            value.as_slice().try_into().map_err(|_| Error::Protocol)?,
        ))
    }
    pub fn sign(&mut self, slot: u8, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.private_operation(slot, 0x81, &Sha256::digest(message))?;
        p256::ecdsa::Signature::from_der(&signature).map_err(|_| Error::Protocol)?;
        Ok(signature.to_vec())
    }
}
pub struct Session<T: Transport> {
    card: Mutex<Piv<T>>,
    slots: Slots,
    pub encryption: PublicKey,
    pub signing: PublicKey,
    pub encryption_policy: Option<KeyPolicy>,
    pub signing_policy: Option<KeyPolicy>,
    observer: Option<Box<dyn Fn(PrivateOperation) + Send + Sync>>,
}
impl<T: Transport> Session<T> {
    pub fn unlock(card: Piv<T>, pin: &str) -> Result<Self> {
        Self::unlock_with_slots(card, pin, Slots::default())
    }
    pub fn unlock_with_slots(mut card: Piv<T>, pin: &str, slots: Slots) -> Result<Self> {
        let encryption = card.key_metadata(slots.encryption)?;
        let signing = card.key_metadata(slots.signing)?;
        card.verify_pin(pin)?;
        Ok(Self {
            card: Mutex::new(card),
            slots,
            encryption: encryption.public_key,
            signing: signing.public_key,
            encryption_policy: encryption.policy,
            signing_policy: signing.policy,
            observer: None,
        })
    }
    /// One explicit PIN verification on the selected card, even in an unlocked session.
    /// Callers own prompts and retry policy; errors are never retried here.
    pub fn verify_pin(&self, pin: &str) -> Result<()> {
        self.card.lock().map_err(|_| Error::Usb)?.verify_pin(pin)
    }
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut card = self.card.lock().map_err(|_| Error::Usb)?;
        self.notify(PrivateOperation::Started(
            self.signing_policy.map(|p| p.touch),
        ));
        let result = card.sign(self.slots.signing, message);
        self.notify(PrivateOperation::Finished);
        result
    }
    pub fn set_observer(&mut self, observer: impl Fn(PrivateOperation) + Send + Sync + 'static) {
        self.observer = Some(Box::new(observer));
    }
    fn notify(&self, event: PrivateOperation) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}
impl<T: Transport> KeyAgreement for Session<T> {
    fn key_id(&self) -> KeyId {
        self.encryption.id()
    }
    async fn agree(&self, request: &AgreementRequest) -> kagitaba_core::Result<AgreementSecret> {
        if request.recipient() != self.key_id() {
            return Err(kagitaba_core::Error::WrongRecipient);
        }
        let mut card = self
            .card
            .lock()
            .map_err(|_| kagitaba_core::Error::KeyUnavailable)?;
        self.notify(PrivateOperation::Started(
            self.encryption_policy.map(|p| p.touch),
        ));
        let result = card.agree(self.slots.encryption, request.peer_public_key());
        self.notify(PrivateOperation::Finished);
        result.map_err(|_| kagitaba_core::Error::KeyUnavailable)
    }
}
fn check_slot(slot: u8) -> Result<()> {
    if (0x82..=0x95).contains(&slot) {
        Ok(())
    } else {
        Err(Error::InvalidSlots)
    }
}
fn pin_bytes(pin: &str) -> Result<Zeroizing<[u8; 8]>> {
    if !(6..=8).contains(&pin.len()) || !pin.is_ascii() {
        return Err(Error::InvalidPin);
    }
    let mut out = Zeroizing::new([0xff; 8]);
    out[..pin.len()].copy_from_slice(pin.as_bytes());
    Ok(out)
}
fn point_key(point: &[u8]) -> Result<PublicKey> {
    let key = p256::PublicKey::from_sec1_bytes(point).map_err(|_| Error::Protocol)?;
    PublicKey::from_der(
        key.to_public_key_der()
            .map_err(|_| Error::Protocol)?
            .as_bytes(),
    )
    .map_err(|_| Error::Protocol)
}
fn tag(bytes: &[u8], wanted: u16) -> Result<&[u8]> {
    optional_tag(bytes, wanted)?.ok_or(Error::Protocol)
}
fn optional_tag(mut bytes: &[u8], wanted: u16) -> Result<Option<&[u8]>> {
    let mut found = None;
    while !bytes.is_empty() {
        let mut t = bytes[0] as u16;
        bytes = &bytes[1..];
        if t & 31 == 31 {
            let next = *bytes.first().ok_or(Error::Protocol)?;
            if next & 128 != 0 {
                return Err(Error::Protocol);
            }
            t = (t << 8) | next as u16;
            bytes = &bytes[1..];
        }
        let first = *bytes.first().ok_or(Error::Protocol)?;
        bytes = &bytes[1..];
        let len = match first {
            0..=127 => first as usize,
            0x81 => {
                let n = *bytes.first().ok_or(Error::Protocol)? as usize;
                bytes = &bytes[1..];
                n
            }
            0x82 => {
                let n =
                    u16::from_be_bytes(bytes.get(..2).ok_or(Error::Protocol)?.try_into().unwrap())
                        as usize;
                bytes = &bytes[2..];
                n
            }
            _ => return Err(Error::Protocol),
        };
        let value = bytes.get(..len).ok_or(Error::Protocol)?;
        bytes = &bytes[len..];
        if t == wanted {
            if found.is_some() {
                return Err(Error::Protocol);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

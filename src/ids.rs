use core::{fmt, str::FromStr};
use rand_core::TryCryptoRng;

use crate::{Error, Result};

macro_rules! identifier {
    ($name:ident, $size:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) [u8; $size]);

        impl $name {
            /// Construct an identifier from its binary representation.
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            /// Access the canonical binary representation.
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                // One canonical representation; case variations are not aliases.
                if value.len() != $size * 2
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(Error::InvalidEncoding);
                }
                let mut bytes = [0; $size];
                hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::InvalidEncoding)?;
                Ok(Self(bytes))
            }
        }
    };
}

identifier!(
    KeyId,
    32,
    "SHA-256 fingerprint of canonical DER SubjectPublicKeyInfo."
);
identifier!(
    EntryId,
    16,
    "Stable opaque identity of an entry, independent of its revisions."
);
identifier!(
    RevisionId,
    16,
    "Opaque identifier of one primary-record revision."
);

impl EntryId {
    /// Generate a fresh identifier using the application's cryptographic RNG.
    pub fn generate(rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<Self> {
        let mut bytes = [0; 16];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| Error::Randomness)?;
        Ok(Self(bytes))
    }
}

impl RevisionId {
    /// Generate a fresh revision using the application's cryptographic RNG.
    pub fn generate(rng: &mut (impl TryCryptoRng + ?Sized)) -> Result<Self> {
        let mut bytes = [0; 16];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| Error::Randomness)?;
        Ok(Self(bytes))
    }
}

//! Configurable, uniformly sampled passwords. No platform randomness or persistence.
use num_bigint::BigUint;
use rand_core::TryCryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Characters excluded by the readable preset.
pub const LOOKALIKES: &str = "iIlL1oO0sS5zZ2bB8gG6qQ9";
/// User-selected generation rules, independent of stored-password validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    /// Output length (1–1024).
    pub length: usize,
    /// Include lowercase ASCII letters.
    pub lowercase: bool,
    /// Include uppercase ASCII letters.
    pub uppercase: bool,
    /// Include ASCII digits.
    pub digits: bool,
    /// Include the custom symbol alphabet.
    pub symbols: bool,
    /// Printable ASCII punctuation, deduplicated before use.
    pub symbol_set: String,
    /// Exclude the readable preset's lookalikes.
    pub lookalikes: bool,
    /// Additional characters to exclude.
    pub exclusions: String,
    /// Require at least one character from each selected class.
    pub require_each: bool,
}
impl Default for Rules {
    fn default() -> Self {
        Self {
            length: 12,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
            symbol_set: "!@#$%^&*()-_=+[]{}:,.?".into(),
            lookalikes: true,
            exclusions: String::new(),
            require_each: true,
        }
    }
}
impl Rules {
    fn classes(&self) -> Result<Vec<Vec<u8>>, &'static str> {
        if !(1..=1024).contains(&self.length) {
            return Err("Choose a length from 1 to 1024");
        }
        if self.symbol_set.len() > 128
            || self.exclusions.len() > 1024
            || !self.symbol_set.bytes().all(|b| b.is_ascii_punctuation())
        {
            return Err("Symbols must be printable ASCII punctuation");
        }
        let mut classes = Vec::new();
        for (enabled, alphabet) in [
            (self.lowercase, "abcdefghijklmnopqrstuvwxyz"),
            (self.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            (self.digits, "0123456789"),
            (self.symbols, self.symbol_set.as_str()),
        ] {
            if !enabled {
                continue;
            }
            let mut class = Vec::new();
            for b in alphabet.bytes() {
                if !(self.exclusions.contains(b as char)
                    || self.lookalikes && LOOKALIKES.contains(b as char)
                    || class.contains(&b))
                {
                    class.push(b);
                }
            }
            if class.is_empty() {
                return Err("Exclusions remove an enabled character class");
            }
            classes.push(class);
        }
        if classes.is_empty() {
            return Err("Enable at least one character class");
        }
        if self.require_each && self.length < classes.len() {
            return Err("Length is shorter than the required class count");
        }
        Ok(classes)
    }
    /// Effective, unique alphabet after exclusions.
    pub fn alphabet(&self) -> Result<String, &'static str> {
        Ok(self
            .classes()?
            .into_iter()
            .flatten()
            .map(char::from)
            .collect())
    }
    /// Sample a uniform index into all valid strings, then unrank it. Integer
    /// completion counts avoid modulo bias and rare-rule rejection loops.
    pub fn generate(&self, rng: &mut impl TryCryptoRng) -> Result<Zeroizing<String>, &'static str> {
        let classes = self.classes()?;
        let required = if self.require_each {
            (1usize << classes.len()) - 1
        } else {
            0
        };
        let mut counts = vec![vec![BigUint::from(0u8); 16]; self.length + 1];
        counts[0][0] = BigUint::from(1u8);
        for remaining in 1..=self.length {
            for mask in 0..=required {
                let mut total = BigUint::from(0u8);
                for (i, class) in classes.iter().enumerate() {
                    total += &counts[remaining - 1][mask & !(1 << i)] * class.len();
                }
                counts[remaining][mask] = total;
            }
        }
        let total = &counts[self.length][required];
        let bits = total.bits();
        let mut bytes = Zeroizing::new(vec![0u8; bits.div_ceil(8) as usize]);
        let mut rank = None;
        for _ in 0..128 {
            rng.try_fill_bytes(&mut bytes)
                .map_err(|_| "Randomness unavailable")?;
            if bits % 8 != 0 {
                *bytes.last_mut().expect("nonzero total") &= (1u8 << (bits % 8)) - 1;
            }
            let candidate = BigUint::from_bytes_le(&bytes);
            if &candidate < total {
                rank = Some(candidate);
                break;
            }
        }
        let mut rank = rank.ok_or("Randomness unavailable")?;
        let mut result = Zeroizing::new(String::with_capacity(self.length));
        let mut mask = required;
        for remaining in (0..self.length).rev() {
            'choose: for (i, class) in classes.iter().enumerate() {
                let next = mask & !(1 << i);
                for b in class {
                    let count = &counts[remaining][next];
                    if &rank < count {
                        result.push(*b as char);
                        mask = next;
                        break 'choose;
                    }
                    rank -= count;
                }
            }
        }
        Ok(result)
    }
}

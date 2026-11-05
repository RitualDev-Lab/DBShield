//! Wire-Level Dynamic PII Masking & Format-Preserving Pseudonymization.
//!
//! Masks sensitive fields directly on DataRow wire streams before emitting
//! result sets to autonomous agent LLM inference windows.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct WirePiiMasker {
    salt: String,
}

impl WirePiiMasker {
    pub fn new(salt: impl Into<String>) -> Self {
        Self { salt: salt.into() }
    }

    /// Computes deterministic format-preserving pseudonym preserving relational integrity
    pub fn pseudonymize(&self, val: &str, category: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.salt.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(val.as_bytes());
        let hash_hex = format!("{:x}", mac.finalize().into_bytes());
        let short_hash = &hash_hex[..8];

        match category.to_uppercase().as_str() {
            "EMAIL" => {
                if let Some(at) = val.find('@') {
                    format!("user_{}{}", short_hash, &val[at..])
                } else {
                    format!("user_{}@masked.local", short_hash)
                }
            }
            "PHONE" => {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                let last4 = if digits.len() >= 4 {
                    &digits[digits.len() - 4..]
                } else {
                    "0000"
                };
                format!("+***-***-{}", last4)
            }
            "CREDIT_CARD" => {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                let last4 = if digits.len() >= 4 {
                    &digits[digits.len() - 4..]
                } else {
                    "0000"
                };
                format!("****-****-****-{}", last4)
            }
            "SSN" => {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                let last4 = if digits.len() >= 4 {
                    &digits[digits.len() - 4..]
                } else {
                    "0000"
                };
                format!("***-**-{}", last4)
            }
            _ => format!("[MASKED_{}_{}]", category.to_uppercase(), short_hash),
        }
    }
}

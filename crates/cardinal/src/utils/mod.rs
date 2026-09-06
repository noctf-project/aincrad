use std::fmt;
use std::io;

use sha2::{Digest, Sha256};

pub mod naming;
pub mod ttl;
pub mod versions;

pub const CARDINAL_LB_CLASS: &str = "aincrad.noctf.dev/cardinal";

pub struct HashWriter<'a, D: sha2::digest::Update>(pub &'a mut D);
impl<'a, D: sha2::digest::Update> io::Write for HashWriter<'a, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a, D: sha2::digest::Update> fmt::Write for HashWriter<'a, D> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

/// Computes the full lowercase Crockford Base32 SHA-256 hash of a string.
pub fn hash_str_crockford(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    base32::encode(base32::Alphabet::Crockford, &result).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_str_crockford() {
        let h = hash_str_crockford("test-string");
        assert!(!h.is_empty());
        assert!(
            h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }
}

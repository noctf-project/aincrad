use sha2::{Digest, Sha256};

pub mod labels;
pub mod naming;
pub mod ttl;

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

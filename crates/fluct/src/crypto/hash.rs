use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET_ROOT: &str = "aincrad:fluct";

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hmac.update(message);
    hmac.finalize().into_bytes().to_vec()
}

pub fn derive_key(secret: &str, role: &str) -> Vec<u8> {
    let role_tag = format!("{SECRET_ROOT}:{role}");
    hmac_sha256(secret.as_bytes(), role_tag.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let secret = "my_secret_key";
        let key_challenge = derive_key(secret, "challenge");
        let key_flag = derive_key(secret, "flag");

        assert_eq!(key_challenge.len(), 32);
        assert_eq!(key_flag.len(), 32);
        assert_ne!(key_challenge, key_flag);

        // Verify determinism
        assert_eq!(key_challenge, derive_key(secret, "challenge"));
        assert_eq!(
            key_challenge,
            hmac_sha256(b"my_secret_key", b"aincrad:fluct:challenge")
        );
    }
}

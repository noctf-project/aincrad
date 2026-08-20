use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hmac.update(&message);
    hmac.finalize().into_bytes().to_vec()
}

pub fn sha256(message: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(&message);
    hash.finalize().to_vec()
}

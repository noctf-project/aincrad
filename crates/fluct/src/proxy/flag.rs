use std::cell::{Cell, RefCell};
use std::net::IpAddr;

use aes::Aes256;
use aes::cipher::KeyInit;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::Timelike;
use crypto::cipher::BlockEncrypt;
use crypto::common::generic_array::GenericArray;
use fluct::Session;
use rand::Rng;
use rand::rngs::StdRng;

use crate::crypto::hash::hmac_sha256;

const V6_V4: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
pub trait FlagGenerator {
    fn generate(flag_prefix: &str, prefix: &str, secret: &[u8], session: &Session) -> String;
}

pub struct V1FlagGenerator {}

impl V1FlagGenerator {
    const VERSION: &'static [u8] = b"DUCTF1";
    const MAGIC: &'static [u8] = b"TOM0NK3$";
    thread_local! {
      pub static COUNTER: Cell<u8> = const { Cell::new(0) };
      pub static RNG: RefCell<StdRng> = RefCell::new(rand::make_rng());
    }
}

impl FlagGenerator for V1FlagGenerator {
    fn generate(flag_prefix: &str, prefix: &str, secret: &[u8], session: &Session) -> String {
        if prefix.is_empty() {
            return String::new();
        }

        let timestamp = (session.timestamp.timestamp() as u64) * 1_000_000_000
            + (session.timestamp.nanosecond() as u64);
        let ip_bytes: [u8; 12] = match session.addr {
            IpAddr::V4(ip) => {
                let o = ip.octets();
                [0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3]]
            }
            IpAddr::V6(ip) => {
                // get the first 8 bytes of an ipv6 address, that should be enough to track
                let o = ip.octets();
                if V6_V4.iter().zip(&o[0..12]).filter(|&(a, b)| a == b).count() == 12 {
                    // check if its ipv4
                    [0, 0, 0, 0, 0, 0, 0xff, 0xff, o[12], o[13], o[14], o[15]]
                } else {
                    o[..12].try_into().unwrap_or([0u8; 12])
                }
            }
        };
        let mut buf = vec![0u8; 32];
        buf[0..8].copy_from_slice(&timestamp.to_be_bytes());
        Self::RNG.with(|rng| rng.borrow_mut().fill_bytes(&mut buf[8..11]));
        Self::COUNTER.with(|c| {
            buf[11] = c.get();
            c.set(c.get().wrapping_add(1));
        });
        buf[12..20].clone_from_slice(Self::MAGIC);
        buf[20..32].clone_from_slice(&ip_bytes[0..12]);

        let key = hmac_sha256(Self::VERSION, secret);
        let key = hmac_sha256(&key, prefix.as_bytes());
        // Chain 2nd block to plaintext of first block
        {
            let key = hmac_sha256(&key, &session.uid);
            let key = hmac_sha256(&key, &buf[0..16]);
            let Ok(cipher) = Aes256::new_from_slice(&key) else {
                return String::new();
            };
            let block = GenericArray::from_mut_slice(&mut buf[16..32]);
            cipher.encrypt_block(block);
        }

        let Ok(cipher) = Aes256::new_from_slice(&key) else {
            return String::new();
        };
        let block = GenericArray::from_mut_slice(&mut buf[0..16]);
        cipher.encrypt_block(block);

        let payload = BASE64_URL_SAFE_NO_PAD.encode(&buf);
        format!("{}{{{}|{}}}", flag_prefix, prefix, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::Ipv4Addr;

    #[test]
    fn test_v1_flag_generator_empty_prefix() {
        let session = Session {
            uid: vec![],
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            timestamp: Utc::now(),
        };

        let flag_empty = V1FlagGenerator::generate("CTF", "", b"secret", &session);
        assert_eq!(flag_empty, "");

        let flag_valid = V1FlagGenerator::generate("CTF", "test_prefix", b"secret", &session);
        assert!(flag_valid.starts_with("CTF{test_prefix|"));
    }

    #[test]
    fn test_v1_flag_generator_ipv4_and_ipv6() {
        let session_v4 = Session {
            uid: b"user1".to_vec(),
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            timestamp: Utc::now(),
        };
        let flag_v4 = V1FlagGenerator::generate("CTF", "pwn", b"secret_key", &session_v4);
        assert!(flag_v4.starts_with("CTF{pwn|"));

        let session_v6 = Session {
            uid: b"user2".to_vec(),
            addr: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            timestamp: Utc::now(),
        };
        let flag_v6 = V1FlagGenerator::generate("CTF", "pwn", b"secret_key", &session_v6);
        assert!(flag_v6.starts_with("CTF{pwn|"));
        assert_ne!(flag_v4, flag_v6);
    }
}

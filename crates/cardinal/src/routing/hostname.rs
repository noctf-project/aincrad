use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use super::ports_store::RouteKey;

const HOSTNAME_ID_LEN: usize = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDeriver {
    route_seed: String,
    hostname_suffix: String,
}

impl RouteDeriver {
    pub fn new(route_seed: impl Into<String>, hostname_suffix: impl Into<String>) -> Self {
        Self {
            route_seed: route_seed.into(),
            hostname_suffix: hostname_suffix.into(),
        }
    }

    /// Derives the base hostname label (`{prefix}-{hash14}`) for CTFProxyRoute.
    pub fn derive_hostname(&self, key: &RouteKey, prefix: Option<&str>) -> String {
        let raw_prefix = prefix.filter(|s| !s.is_empty()).unwrap_or(&key.name);
        let clean_prefix = sanitize_prefix(raw_prefix);

        let seed_tag = format!("aincrad:route:v1:{}:{}", self.route_seed, key);
        let mut hasher = Sha256::new();
        hasher.update(seed_tag.as_bytes());
        let hash = hasher.finalize();

        let mut id = base32::encode(base32::Alphabet::Crockford, &hash).to_lowercase();
        id.truncate(HOSTNAME_ID_LEN);
        format!("{clean_prefix}-{id}")
    }

    /// Formats a base hostname with the configured `hostname_suffix` for CTFInstance status endpoints.
    pub fn format_tls_host(&self, base: &str) -> String {
        if self.hostname_suffix.is_empty() {
            base.to_string()
        } else if self.hostname_suffix.starts_with('.') {
            format!("{base}{}", self.hostname_suffix)
        } else {
            format!("{base}.{}", self.hostname_suffix)
        }
    }
}

fn sanitize_prefix(input: &str) -> String {
    static RE_INVALID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9-]+").unwrap());
    const MAX_PREFIX_LEN: usize = 63 - HOSTNAME_ID_LEN - 1; // 48

    let lowered = input.to_lowercase();
    let replaced = RE_INVALID.replace_all(&lowered, "-");

    let truncated = if replaced.len() > MAX_PREFIX_LEN {
        &replaced[..MAX_PREFIX_LEN]
    } else {
        &replaced
    };

    let trimmed = truncated.trim_matches('-');

    if trimmed.is_empty() {
        "chal".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_deriver_lifecycle() {
        let deriver = RouteDeriver::new("link-start", "c.sk8.dog");
        let key = RouteKey {
            namespace: "default".into(),
            name: "web-app".into(),
        };

        let base_host = deriver.derive_hostname(&key, Some("whoami"));
        assert!(base_host.starts_with("whoami-"));
        assert_eq!(base_host.len(), "whoami-".len() + HOSTNAME_ID_LEN);

        let full_host = deriver.format_tls_host(&base_host);
        assert_eq!(full_host, format!("{base_host}.c.sk8.dog"));
    }

    #[test]
    fn test_derive_hostname_prefix_and_default() {
        let deriver = RouteDeriver::new("link-start", "");
        let key1 = RouteKey {
            namespace: "default".into(),
            name: "r1".into(),
        };
        let key2 = RouteKey {
            namespace: "default".into(),
            name: "r2".into(),
        };

        let host1 = deriver.derive_hostname(&key1, Some("my-chal"));
        let host2 = deriver.derive_hostname(&key1, Some("web"));
        let host3 = deriver.derive_hostname(&key2, Some("my-chal"));
        let host4 = deriver.derive_hostname(&key1, None);

        assert!(host1.starts_with("my-chal-"));
        assert!(host2.starts_with("web-"));
        assert!(host3.starts_with("my-chal-"));
        assert!(host4.starts_with("r1-"));

        assert_ne!(host1, host2);
        assert_ne!(host1, host3);
        assert_eq!(host1.len(), "my-chal-".len() + HOSTNAME_ID_LEN);
        assert_eq!(host2.len(), "web-".len() + HOSTNAME_ID_LEN);
    }

    #[test]
    fn test_derive_hostname_collision_prevention() {
        let deriver = RouteDeriver::new("link-start", "");
        let key1 = RouteKey {
            namespace: "ns".into(),
            name: "a".into(),
        };
        let key2 = RouteKey {
            namespace: "ns".into(),
            name: "b".into(),
        };
        let key3 = RouteKey {
            namespace: "ns".into(),
            name: "c".into(),
        };

        let h1 = deriver.derive_hostname(&key1, Some("web-chal1-service1-team1"));
        let h2 = deriver.derive_hostname(&key2, Some("web-chal1-service2-team1"));
        assert!(h1.starts_with("web-chal1-service1-team1-"));
        assert!(h2.starts_with("web-chal1-service2-team1-"));
        assert_ne!(h1, h2);

        let h_metadata = deriver.derive_hostname(&key3, Some("web"));
        let h_key = deriver.derive_hostname(&key3, Some("chal-web"));
        assert_ne!(h_metadata, h_key);
    }

    #[test]
    fn test_sanitize_prefix() {
        assert_eq!(sanitize_prefix("web"), "web");
        assert_eq!(sanitize_prefix("Web_Chal_1.2"), "web-chal-1-2");
        assert_eq!(sanitize_prefix("---foo---bar---"), "foo---bar");
        assert_eq!(sanitize_prefix(""), "chal");
        assert_eq!(sanitize_prefix("___"), "chal");

        // Truncation at 48 characters (63 - 14 - 1)
        let long_input = "a".repeat(100);
        let sanitized = sanitize_prefix(&long_input);
        assert_eq!(sanitized.len(), 48);
        assert_eq!(sanitized, "a".repeat(48));

        // Truncating trailing hyphens after truncation
        let trailing_dash = format!("{}-something", "a".repeat(48));
        assert_eq!(sanitize_prefix(&trailing_dash), "a".repeat(48));
    }

    #[test]
    fn test_format_tls_host() {
        let deriver1 = RouteDeriver::new("seed", "c.sk8.dog");
        assert_eq!(
            deriver1.format_tls_host("whoami-1234567890abcd"),
            "whoami-1234567890abcd.c.sk8.dog"
        );

        let deriver2 = RouteDeriver::new("seed", ".c.sk8.dog");
        assert_eq!(
            deriver2.format_tls_host("whoami-1234567890abcd"),
            "whoami-1234567890abcd.c.sk8.dog"
        );

        let deriver3 = RouteDeriver::new("seed", "");
        assert_eq!(
            deriver3.format_tls_host("whoami-1234567890abcd"),
            "whoami-1234567890abcd"
        );
    }
}

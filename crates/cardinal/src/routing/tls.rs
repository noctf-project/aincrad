use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::cache::ResourceKey;

const HOSTNAME_ID_LEN: usize = 14;
const MAX_PREFIX_LEN: usize = 56 - HOSTNAME_ID_LEN - 1;

/// Derives the base hostname label (`{prefix}-{hash14}`).
pub fn derive_hostname(route_seed: &str, key: &ResourceKey, prefix: Option<&str>) -> String {
    let clean_prefix = sanitize_prefix(prefix.filter(|s| !s.is_empty()).unwrap_or(&key.resource));

    let seed_tag = format!("aincrad:route:v1:{route_seed}:{key}");
    let mut hasher = Sha256::new();
    hasher.update(seed_tag.as_bytes());
    let hash = hasher.finalize();

    let mut id = base32::encode(base32::Alphabet::Crockford, &hash).to_lowercase();
    id.truncate(HOSTNAME_ID_LEN);
    format!("{clean_prefix}-{id}")
}

/// Resolves the default prefix from template name and route name.
pub fn default_tls_prefix(template_name: &str, route_name: &str) -> String {
    if route_name == "main" || route_name == template_name {
        template_name.to_string()
    } else {
        format!("{template_name}-{route_name}")
    }
}

/// Formats a base hostname into an FQDN with `hostname_suffix`.
pub fn format_tls_host(hostname_suffix: &str, base: &str) -> String {
    if hostname_suffix.is_empty() {
        base.to_string()
    } else if hostname_suffix.starts_with('.') {
        format!("{base}{hostname_suffix}")
    } else {
        format!("{base}.{hostname_suffix}")
    }
}

pub fn sanitize_prefix(input: &str) -> String {
    static RE_INVALID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9-]+").unwrap());

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
    fn test_sanitize_prefix() {
        assert_eq!(sanitize_prefix("web"), "web");
        assert_eq!(sanitize_prefix("Web_Chal_1.2"), "web-chal-1-2");
        assert_eq!(sanitize_prefix("---foo---bar---"), "foo---bar");
        assert_eq!(sanitize_prefix(""), "chal");
        assert_eq!(sanitize_prefix("___"), "chal");

        let long_input = "a".repeat(100);
        let sanitized = sanitize_prefix(&long_input);
        assert_eq!(sanitized.len(), MAX_PREFIX_LEN);
        assert_eq!(sanitized, "a".repeat(MAX_PREFIX_LEN));
    }

    #[test]
    fn test_derive_hostname_determinism() {
        let key = ResourceKey::new("default", "chal-1", "web");
        let h1 = derive_hostname("seed", &key, Some("whoami"));
        let h2 = derive_hostname("seed", &key, Some("whoami"));
        assert_eq!(h1, h2);
        assert!(h1.starts_with("whoami-"));
    }

    #[test]
    fn test_format_tls_host() {
        assert_eq!(
            format_tls_host("c.noctf.dev", "web-abc"),
            "web-abc.c.noctf.dev"
        );
        assert_eq!(
            format_tls_host(".c.noctf.dev", "web-abc"),
            "web-abc.c.noctf.dev"
        );
        assert_eq!(format_tls_host("", "web-abc"), "web-abc");
    }

    #[test]
    fn test_default_tls_prefix() {
        assert_eq!(default_tls_prefix("my-chal", "web"), "my-chal-web");
        assert_eq!(default_tls_prefix("my-chal", "main"), "my-chal");
        assert_eq!(default_tls_prefix("my-chal", "my-chal"), "my-chal");
    }

    #[test]
    fn test_long_template_and_route_prefix_clipping() {
        let long_template = "super-long-challenge-name-that-is-very-descriptive";
        let long_route = "super-long-internal-route-backend-target";
        let raw_prefix = default_tls_prefix(long_template, long_route);

        let key = ResourceKey::new("default", "chal-1", long_route);
        let hostname = derive_hostname("test-seed", &key, Some(&raw_prefix));

        // Total label length must not exceed DNS 63-char limit
        assert!(hostname.len() <= 63);

        // Hostname format is {prefix}-{hash14}
        let parts: Vec<&str> = hostname.rsplitn(2, '-').collect();
        assert_eq!(parts.len(), 2);
        let id = parts[0];
        let prefix = parts[1];

        assert_eq!(id.len(), HOSTNAME_ID_LEN);
        assert_eq!(prefix.len(), MAX_PREFIX_LEN);
        assert!(!prefix.ends_with('-'));
        assert_eq!(hostname.len(), MAX_PREFIX_LEN + 1 + HOSTNAME_ID_LEN);
    }
}

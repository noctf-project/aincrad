use crate::utils::hash_str_crockford;

pub const HASH_LEN: usize = 8;

/// Generates a DNS-1123 compliant Kubernetes resource name (<= 63 chars).
///
/// Joins `name` and non-empty `suffix` (`name-suffix`).
/// If `name-suffix.len() > 63`: preserves `suffix` 100% intact, truncates `name`,
/// and appends an `HASH_LEN`-character Crockford Base32 hash directly (`prefixhash-suffix`).
pub fn resource_name(name: &str, suffix: &str) -> String {
    const MAX_LEN: usize = 63;
    let name = name.trim_matches('-');
    let suffix = suffix.trim_matches('-');

    if suffix.is_empty() {
        if name.len() <= MAX_LEN {
            return name.to_string();
        }
        let full_hash = hash_str_crockford(name);
        let hash = &full_hash[..HASH_LEN];
        let max_prefix_len = MAX_LEN.saturating_sub(HASH_LEN);
        let safe_prefix_len = name
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|&idx| idx <= max_prefix_len)
            .last()
            .unwrap_or(0);
        let prefix = name[..safe_prefix_len].trim_end_matches('-');
        return format!("{prefix}{hash}");
    }

    let out = format!("{name}-{suffix}");
    if out.len() <= MAX_LEN {
        out
    } else {
        let full_hash = hash_str_crockford(name);
        let hash = &full_hash[..HASH_LEN]; // 8-character Crockford Base32 hash slice

        // Available space for prefix while preserving suffix intact:
        // MAX_LEN - HASH_LEN - 1 (dash before suffix) - suffix.len()
        let max_prefix_len = MAX_LEN.saturating_sub(HASH_LEN + 1 + suffix.len());

        let safe_prefix_len = name
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|&idx| idx <= max_prefix_len)
            .last()
            .unwrap_or(0);

        let prefix = name[..safe_prefix_len].trim_end_matches('-');

        if prefix.is_empty() {
            format!("{hash}-{suffix}")
        } else {
            format!("{prefix}{hash}-{suffix}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_name_short() {
        assert_eq!(resource_name("team-alpha", "web"), "team-alpha-web");
        assert_eq!(resource_name("team-alpha", "np"), "team-alpha-np");
    }

    #[test]
    fn test_resource_name_exact_63() {
        let name_58_chars = "a".repeat(58);
        let res = resource_name(&name_58_chars, "1234"); // 58 + 1 (dash) + 4 (1234) = 63
        assert_eq!(res.len(), 63);
        assert_eq!(res, format!("{name_58_chars}-1234"));
    }

    #[test]
    fn test_resource_name_long_truncation_preserves_suffix() {
        let long_name = "my-super-long-ctf-challenge-instance-name-for-team-alpha-group-123456789";
        let suffix = "web";
        let res = resource_name(long_name, suffix);

        assert!(res.len() <= 63);
        assert!(
            res.ends_with("-web"),
            "Suffix must be preserved 100% intact"
        );
    }

    #[test]
    fn test_resource_name_crockford_base32_character_set() {
        let long_name = "extremely-long-instance-name-that-triggers-crockford-base32-truncation";
        let res = resource_name(long_name, "svc");

        assert!(res.len() <= 63);
        // Valid DNS-1123 label check (only lowercase a-z, 0-9, and hyphens)
        assert!(
            res.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "Generated name must be valid DNS-1123: {res}"
        );
    }

    #[test]
    fn test_resource_name_determinism() {
        let name = "extremely-long-instance-name-that-triggers-truncation";
        let res1 = resource_name(name, "svc");
        let res2 = resource_name(name, "svc");

        assert_eq!(res1, res2);
        assert!(res1.len() <= 63);
    }
}

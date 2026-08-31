use clap::Parser;
use k8s_common::{PortRange, parse_port_range};

#[derive(Parser, Debug, Clone)]
#[command(name = "cardinal", about = "Control plane controller for Aincrad CTF")]
pub struct Opts {
    #[arg(
        long,
        env = "RESERVED_PORTS",
        default_value = "20000-29999",
        value_parser = parse_port_range
    )]
    pub reserved_ports: PortRange,

    #[arg(
        long,
        env = "AUTO_PORTS",
        default_value = "30000-32767",
        value_parser = parse_port_range
    )]
    pub auto_ports: PortRange,

    #[arg(long, env = "ROUTE_SEED", default_value = "link-start")]
    pub route_seed: String,

    #[arg(long, env = "HOSTNAME_SUFFIX", default_value = "c.noctf.dev")]
    pub hostname_suffix: String,

    #[arg(long, env = "TLS_PORT", default_value = "4433")]
    pub tls_port: u16,

    #[arg(long, env = "SYSTEM_NAMESPACE")]
    pub system_namespace: Option<String>,

    #[arg(long, env = "CLUSTER_DOMAIN", default_value = "cluster.local")]
    pub cluster_domain: String,

    #[arg(
        long = "namespace",
        visible_alias = "managed-namespace",
        action = clap::ArgAction::Append
    )]
    pub managed_namespaces: Vec<String>,

    #[arg(
        long,
        value_parser = parse_image_alias,
        visible_alias = "image-alias",
        action = clap::ArgAction::Append
    )]
    pub image_aliases: Option<Vec<(String, String)>>,
}

/// Parses a single `key=value` image alias argument, validating the key and
/// normalizing the registry prefix. A trailing slash on the prefix is stripped
/// so the later `{prefix}/{rest}` construction never produces a double slash.
fn parse_image_alias(s: &str) -> Result<(String, String), String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("image alias must be in the form 'key=value': '{s}'"))?;
    validate_image_alias_key(key)?;
    if value.is_empty() {
        return Err(format!("image alias '{s}' has an empty registry prefix"));
    }
    if value.starts_with('/') {
        return Err(format!(
            "image alias '{s}' has a registry prefix that starts with a slash"
        ));
    }
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        return Err(format!("image alias '{s}' has an empty registry prefix"));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Validates an image alias key: non-empty, no slashes (including leading or
/// trailing), and only safe characters.
fn validate_image_alias_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("image alias key must not be empty".into());
    }
    if key.starts_with('/') || key.ends_with('/') || key.contains('/') {
        return Err(format!(
            "image alias key '{key}' must not contain a slash (leading, trailing, or internal)"
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(format!(
            "image alias key '{key}' contains invalid characters (allowed: alphanumeric, '_', '-', '.')"
        ));
    }
    Ok(())
}

impl Opts {
    pub fn validate(&self) -> Result<(), String> {
        if self.reserved_ports.overlaps(&self.auto_ports) {
            return Err(format!(
                "reserved_ports ({:?}) overlaps with auto_ports ({:?})",
                self.reserved_ports.0, self.auto_ports.0
            ));
        }

        if self.reserved_ports.contains(self.tls_port) {
            return Err(format!(
                "tls_port ({}) overlaps with reserved_ports ({:?})",
                self.tls_port, self.reserved_ports.0
            ));
        }

        if self.auto_ports.contains(self.tls_port) {
            return Err(format!(
                "tls_port ({}) overlaps with auto_ports ({:?})",
                self.tls_port, self.auto_ports.0
            ));
        }

        // Duplicate image alias keys would make lookup ambiguous; reject them.
        let mut seen = std::collections::HashSet::new();
        if let Some(aliases) = &self.image_aliases {
            for (key, _) in aliases {
                if !seen.insert(key) {
                    return Err(format!("duplicate image alias key '{key}'"));
                }
            }
        }

        Ok(())
    }

    /// Builds the deduplicated image alias map.
    pub fn image_alias_map(&self) -> std::collections::BTreeMap<String, String> {
        self.image_aliases
            .iter()
            .flatten()
            .cloned()
            .collect::<std::collections::BTreeMap<String, String>>()
    }
}

#[cfg(test)]
mod tests {
    use k8s_common::PortRange;

    use super::*;

    #[test]
    fn test_opts_validation_success() {
        let opts = Opts {
            reserved_ports: PortRange(20000..=29999),
            auto_ports: PortRange(30000..=32767),
            route_seed: "seed".into(),
            hostname_suffix: "c.noctf.dev".into(),
            tls_port: 4433,
            system_namespace: None,
            cluster_domain: "cluster.local".into(),
            managed_namespaces: vec![],
            image_aliases: None,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_opts_validation_overlapping_ports() {
        let opts = Opts {
            reserved_ports: PortRange(20000..=25000),
            auto_ports: PortRange(24000..=30000),
            route_seed: "seed".into(),
            hostname_suffix: "c.noctf.dev".into(),
            tls_port: 4433,
            system_namespace: None,
            cluster_domain: "cluster.local".into(),
            managed_namespaces: vec![],
            image_aliases: None,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("overlaps with auto_ports"));
    }

    #[test]
    fn test_opts_validation_tls_port_in_reserved() {
        let opts = Opts {
            reserved_ports: PortRange(4000..=5000),
            auto_ports: PortRange(30000..=32767),
            route_seed: "seed".into(),
            hostname_suffix: "c.noctf.dev".into(),
            tls_port: 4433,
            system_namespace: None,
            cluster_domain: "cluster.local".into(),
            managed_namespaces: vec![],
            image_aliases: None,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("tls_port (4433) overlaps with reserved_ports"));
    }

    #[test]
    fn test_opts_validation_tls_port_in_auto() {
        let opts = Opts {
            reserved_ports: PortRange(20000..=29999),
            auto_ports: PortRange(4000..=5000),
            route_seed: "seed".into(),
            hostname_suffix: "c.noctf.dev".into(),
            tls_port: 4433,
            system_namespace: None,
            cluster_domain: "cluster.local".into(),
            managed_namespaces: vec![],
            image_aliases: None,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("tls_port (4433) overlaps with auto_ports"));
    }

    fn base_opts(image_aliases: Option<Vec<(String, String)>>) -> Opts {
        Opts {
            reserved_ports: PortRange(20000..=29999),
            auto_ports: PortRange(30000..=32767),
            route_seed: "seed".into(),
            hostname_suffix: "c.noctf.dev".into(),
            tls_port: 4433,
            system_namespace: None,
            cluster_domain: "cluster.local".into(),
            managed_namespaces: vec![],
            image_aliases,
        }
    }

    #[test]
    fn test_validate_duplicate_image_alias_key() {
        let opts = base_opts(Some(vec![
            ("_challenges".to_string(), "a".into()),
            ("_challenges".to_string(), "b".into()),
        ]));
        assert!(
            opts.validate()
                .unwrap_err()
                .contains("duplicate image alias key")
        );
    }

    #[test]
    fn test_validate_unique_image_alias_keys_ok() {
        let opts = base_opts(Some(vec![
            ("_challenges".to_string(), "a".into()),
            ("_infra".to_string(), "b".into()),
        ]));
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn test_image_alias_map_build() {
        let opts = base_opts(Some(vec![
            ("_challenges".to_string(), "registry/foo".into()),
            ("_infra".to_string(), "registry/bar".into()),
        ]));
        let map = opts.image_alias_map();
        assert_eq!(map.get("_challenges"), Some(&"registry/foo".to_string()));
        assert_eq!(map.get("_infra"), Some(&"registry/bar".to_string()));
    }

    #[test]
    fn test_parse_image_alias_valid() {
        let (k, v) = parse_image_alias("_challenges=australia.some-registry/infra").unwrap();
        assert_eq!(k, "_challenges");
        assert_eq!(v, "australia.some-registry/infra");
    }

    #[test]
    fn test_parse_image_alias_strips_trailing_slash() {
        let (_, v) = parse_image_alias("_challenges=australia.some-registry/infra/").unwrap();
        assert_eq!(v, "australia.some-registry/infra");
    }

    #[test]
    fn test_parse_image_alias_leading_or_blank_prefix_rejected() {
        assert!(parse_image_alias("_challenges=/registry").is_err());
        assert!(parse_image_alias("_challenges=/").is_err());
        assert!(parse_image_alias("_challenges=").is_err());
    }

    #[test]
    fn test_parse_image_alias_key_slash_rejected() {
        assert!(parse_image_alias("_challenges/foo=registry/x").is_err());
        assert!(parse_image_alias("/challenges=registry/x").is_err());
        assert!(parse_image_alias("challenges/=registry/x").is_err());
    }

    #[test]
    fn test_parse_image_alias_bad_chars_rejected() {
        assert!(parse_image_alias("ch@llenges=registry/x").is_err());
        assert!(parse_image_alias("_cha llenge=registry/x").is_err());
    }

    #[test]
    fn test_parse_image_alias_missing_equals_rejected() {
        assert!(parse_image_alias("_challenges").is_err());
    }

    #[test]
    fn test_parse_namespace_args() {
        let opts = Opts::try_parse_from(["cardinal", "--namespace", "ns-a", "--namespace", "ns-b"])
            .unwrap();
        assert_eq!(opts.managed_namespaces, vec!["ns-a", "ns-b"]);
    }

    #[test]
    fn test_parse_managed_namespace_alias() {
        let opts = Opts::try_parse_from(["cardinal", "--managed-namespace", "team-1"]).unwrap();
        assert_eq!(opts.managed_namespaces, vec!["team-1"]);
    }

    #[test]
    fn test_parse_no_namespaces_defaults_empty() {
        let opts = Opts::try_parse_from(["cardinal"]).unwrap();
        assert!(opts.managed_namespaces.is_empty());
    }
}

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use k8s_common::{PortRange, parse_port_range};
use k8s_openapi::api::networking::v1::NetworkPolicySpec;
use serde::{Deserialize, Deserializer, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/cardinal/config.yaml";

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardinalConfig {
    #[serde(flatten)]
    pub controller: ControllerConfig,

    #[serde(default)]
    pub api: ApiConfig,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllerConfig {
    #[serde(default)]
    pub namespaces: Vec<String>,

    #[serde(default)]
    pub system_namespace: Option<String>,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub ports: PortsConfig,

    #[serde(default)]
    pub image_aliases: BTreeMap<String, String>,

    #[serde(default)]
    pub network_policies: NetworkPoliciesConfig,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPoliciesConfig {
    #[serde(default)]
    pub template: TemplateNetworkPolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateNetworkPolicyConfig {
    #[serde(default)]
    pub available: Option<NetworkPolicySpec>,

    #[serde(default)]
    pub unavailable: Option<NetworkPolicySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    #[serde(default = "default_hostname_suffix")]
    pub hostname_suffix: String,

    #[serde(default = "default_tls_port")]
    pub tls_port: u16,

    #[serde(default = "default_seed")]
    pub seed: String,

    #[serde(default)]
    pub load_balancer_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortsConfig {
    #[serde(
        default = "default_reserved_ports",
        deserialize_with = "deserialize_port_ranges"
    )]
    pub reserved: Vec<PortRange>,

    #[serde(
        default = "default_auto_ports",
        deserialize_with = "deserialize_port_ranges"
    )]
    pub auto: Vec<PortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    #[serde(default = "default_max_clock_skew")]
    pub max_clock_skew_seconds: u64,

    #[serde(default)]
    pub swagger: bool,

    #[serde(default)]
    pub keys: BTreeMap<String, ApiKeyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyConfig {
    pub secret: String,

    #[serde(default)]
    pub namespaces: Vec<String>,
}

impl ApiKeyConfig {
    pub fn resolve_secret(&self) -> Result<Vec<u8>, String> {
        if let Some(var_name) = self.secret.strip_prefix("env:") {
            std::env::var(var_name)
                .map(String::into_bytes)
                .map_err(|e| format!("missing environment variable '{var_name}': {e}"))
        } else {
            Ok(self.secret.as_bytes().to_vec())
        }
    }

    pub fn allows_namespace(&self, ns: &str) -> bool {
        self.namespaces.is_empty() || self.namespaces.iter().any(|allowed| allowed == ns)
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_max_clock_skew(),
            swagger: false,
            keys: BTreeMap::new(),
        }
    }
}

fn default_max_clock_skew() -> u64 {
    15
}

fn default_hostname_suffix() -> String {
    "c.noctf.dev".to_string()
}

fn default_tls_port() -> u16 {
    443
}

fn default_seed() -> String {
    "link-start".to_string()
}

fn default_reserved_ports() -> Vec<PortRange> {
    vec![parse_port_range("20000-29999").expect("valid default reserved ports")]
}

fn default_auto_ports() -> Vec<PortRange> {
    vec![parse_port_range("30000-32767").expect("valid default auto ports")]
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            hostname_suffix: default_hostname_suffix(),
            tls_port: default_tls_port(),
            seed: default_seed(),
            load_balancer_ip: None,
        }
    }
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            reserved: default_reserved_ports(),
            auto: default_auto_ports(),
        }
    }
}

/// Helper deserializer to parse either a single string, list of strings/numbers, or string ranges into `Vec<PortRange>`.
fn deserialize_port_ranges<'de, D>(deserializer: D) -> Result<Vec<PortRange>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RangeItem {
        Int(u16),
        Str(String),
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RangeInput {
        Single(RangeItem),
        List(Vec<RangeItem>),
    }

    let input = RangeInput::deserialize(deserializer)?;
    let items = match input {
        RangeInput::Single(item) => vec![item],
        RangeInput::List(list) => list,
    };

    let mut result = Vec::new();
    for item in items {
        match item {
            RangeItem::Int(port) => result.push(PortRange(port..=port)),
            RangeItem::Str(s) => {
                let range = parse_port_range(&s).map_err(serde::de::Error::custom)?;
                result.push(range);
            }
        }
    }

    Ok(result)
}

impl CardinalConfig {
    /// Loads a config from a file, or falls back to `/etc/cardinal/config.yaml` if no path is given.
    /// If no path is given and `/etc/cardinal/config.yaml` does not exist, returns `Ok(Default::default())`.
    pub fn load_or_default(
        path_override: Option<&Path>,
    ) -> Result<(Self, Option<PathBuf>), String> {
        if let Some(path) = path_override {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read config file '{path:?}': {e}"))?;
            let cfg = Self::from_yaml(&content)
                .map_err(|e| format!("Failed to parse config file '{path:?}': {e}"))?;
            cfg.validate()?;
            return Ok((cfg, Some(path.to_path_buf())));
        }

        let default_path = Path::new(DEFAULT_CONFIG_PATH);
        if default_path.exists() {
            let content = fs::read_to_string(default_path).map_err(|e| {
                format!("Failed to read default config file '{DEFAULT_CONFIG_PATH}': {e}")
            })?;
            let cfg = Self::from_yaml(&content).map_err(|e| {
                format!("Failed to parse default config file '{DEFAULT_CONFIG_PATH}': {e}")
            })?;
            cfg.validate()?;
            return Ok((cfg, Some(default_path.to_path_buf())));
        }

        let cfg = Self::default();
        cfg.validate()?;
        Ok((cfg, None))
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.controller.validate()?;
        self.api.validate()?;
        Ok(())
    }
}

impl ControllerConfig {
    pub fn validate(&self) -> Result<(), String> {
        for r_res in &self.ports.reserved {
            for r_auto in &self.ports.auto {
                if r_res.overlaps(r_auto) {
                    return Err(format!(
                        "reserved ports ({:?}) overlaps with auto ports ({:?})",
                        r_res.0, r_auto.0
                    ));
                }
            }
        }

        for r_res in &self.ports.reserved {
            if r_res.contains(self.routing.tls_port) {
                return Err(format!(
                    "tls_port ({}) overlaps with reserved ports ({:?})",
                    self.routing.tls_port, r_res.0
                ));
            }
        }

        for r_auto in &self.ports.auto {
            if r_auto.contains(self.routing.tls_port) {
                return Err(format!(
                    "tls_port ({}) overlaps with auto ports ({:?})",
                    self.routing.tls_port, r_auto.0
                ));
            }
        }

        for key in self.image_aliases.keys() {
            validate_image_alias_key(key)?;
        }

        Ok(())
    }
}

impl ApiConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (key_id, key_cfg) in &self.keys {
            if key_id.trim().is_empty() {
                return Err("api.keys identifier must not be empty".into());
            }
            if key_cfg.secret.trim().is_empty() {
                return Err(format!("api.keys['{key_id}'].secret must not be empty"));
            }
        }

        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let cfg = CardinalConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.controller.routing.tls_port, 443);
        assert_eq!(cfg.controller.routing.hostname_suffix, "c.noctf.dev");
        assert_eq!(cfg.controller.ports.auto, vec![PortRange(30000..=32767)]);
    }

    #[test]
    fn test_from_yaml_full() {
        let yaml = r#"
namespaces:
  - challenges
  - test-challenges
systemNamespace: cardinal-system
routing:
  hostnameSuffix: c.example.com
  tlsPort: 4433
  seed: custom-seed
  loadBalancerIp: 1.2.3.4
ports:
  reserved:
    - 20000-24999
  auto:
    - 25000-30000
imageAliases:
  registry: gcr.io/challenges
"#;
        let cfg = CardinalConfig::from_yaml(yaml).unwrap();
        assert_eq!(
            cfg.controller.namespaces,
            vec!["challenges", "test-challenges"]
        );
        assert_eq!(
            cfg.controller.system_namespace.as_deref(),
            Some("cardinal-system")
        );
        assert_eq!(cfg.controller.routing.hostname_suffix, "c.example.com");
        assert_eq!(cfg.controller.routing.tls_port, 4433);
        assert_eq!(cfg.controller.routing.seed, "custom-seed");
        assert_eq!(
            cfg.controller.routing.load_balancer_ip.as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            cfg.controller.ports.reserved,
            vec![PortRange(20000..=24999)]
        );
        assert_eq!(cfg.controller.ports.auto, vec![PortRange(25000..=30000)]);
        assert_eq!(
            cfg.controller.image_aliases.get("registry").unwrap(),
            "gcr.io/challenges"
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validation_port_overlap() {
        let yaml = r#"
ports:
  reserved:
    - 20000-30000
  auto:
    - 25000-35000
"#;
        let cfg = CardinalConfig::from_yaml(yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_tls_overlap() {
        let yaml = r#"
routing:
  tlsPort: 20050
ports:
  reserved:
    - 20000-29999
"#;
        let cfg = CardinalConfig::from_yaml(yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_network_policies_deserialization() {
        let yaml = r#"
networkPolicies:
  template:
    available:
      ingress:
        - from:
            - ipBlock:
                cidr: 0.0.0.0/0
            - namespaceSelector:
                matchExpressions:
                  - key: kubernetes.io/metadata.name
                    operator: In
                    values:
                      - kubectf-infra
                      - envoy-gateway-system
      policyTypes:
        - Ingress
        - Egress
"#;
        let cfg = CardinalConfig::from_yaml(yaml).unwrap();
        let template_np = &cfg.controller.network_policies.template;
        assert!(template_np.available.is_some());
        assert!(template_np.unavailable.is_none());

        let avail = template_np.available.as_ref().unwrap();
        assert_eq!(
            avail.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );
        let ingress = avail.ingress.as_ref().unwrap();
        assert_eq!(ingress.len(), 1);
        let peers = ingress[0].from.as_ref().unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_api_config_deserialization_and_validation() {
        let yaml = r#"
api:
  maxClockSkewSeconds: 30
  keys:
    ctfd-prod:
      secret: "super-secret"
      namespaces:
        - challenges
    admin:
      secret: "env:CARDINAL_SECRET"
"#;
        let cfg = CardinalConfig::from_yaml(yaml).unwrap();
        assert_eq!(cfg.api.max_clock_skew_seconds, 30);
        assert_eq!(cfg.api.keys.len(), 2);

        let ctfd_key = cfg.api.keys.get("ctfd-prod").unwrap();
        assert_eq!(ctfd_key.secret, "super-secret");
        assert!(ctfd_key.allows_namespace("challenges"));
        assert!(!ctfd_key.allows_namespace("other-namespace"));
        assert_eq!(ctfd_key.resolve_secret().unwrap(), b"super-secret");

        let admin_key = cfg.api.keys.get("admin").unwrap();
        assert!(admin_key.allows_namespace("anything"));

        assert!(cfg.validate().is_ok());

        // Validate that an empty secret fails validation
        let bad_yaml = r#"
api:
  keys:
    bad-key:
      secret: "   "
"#;
        let bad_cfg = CardinalConfig::from_yaml(bad_yaml).unwrap();
        assert!(bad_cfg.validate().is_err());
    }
}

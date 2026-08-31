use std::{fmt, str::FromStr};

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crd::RoutePolicySpec;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProxyRouteKeyError {
    #[error("invalid route name '{0}': must start with 'p' (TCP) or 'r' (route)")]
    InvalidPrefix(String),
    #[error("invalid TCP port '{0}': must be between 1 and 65535")]
    InvalidPort(String),
    #[error("empty route name")]
    EmptyRouteName,
    #[error(
        "invalid route name '{0}': must contain only lowercase alphanumeric characters and hyphens, and cannot start or end with a hyphen"
    )]
    InvalidRouteName(String),
}

/// Represents the parsed route target type and key encoded within `CTFProxyRoute`'s `metadata.name`.
///
/// Format conventions:
/// - TCP routes: `p<port>` (e.g. `p80`, `p30005`), where `1 <= port <= 65535`.
/// - Hostname routes: `r<hostname>` (e.g. `rwhoami`, `rweb12345`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProxyRouteKey {
    Tcp(u16),
    Route(String),
}

impl ProxyRouteKey {
    pub fn tcp(port: u16) -> Self {
        Self::Tcp(port)
    }

    pub fn route(hostname: impl Into<String>) -> Self {
        Self::Route(hostname.into())
    }
}

impl FromStr for ProxyRouteKey {
    type Err = ProxyRouteKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(port_str) = s.strip_prefix('p') {
            if port_str.is_empty() {
                return Err(ProxyRouteKeyError::InvalidPort(port_str.to_string()));
            }
            let port = port_str
                .parse::<u16>()
                .map_err(|_| ProxyRouteKeyError::InvalidPort(port_str.to_string()))?;
            if port == 0 {
                return Err(ProxyRouteKeyError::InvalidPort(port_str.to_string()));
            }
            Ok(Self::Tcp(port))
        } else if let Some(hostname) = s.strip_prefix('r') {
            if hostname.is_empty() {
                return Err(ProxyRouteKeyError::EmptyRouteName);
            }
            if !hostname
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                || hostname.starts_with('-')
                || hostname.ends_with('-')
            {
                return Err(ProxyRouteKeyError::InvalidRouteName(hostname.to_string()));
            }
            Ok(Self::Route(hostname.to_string()))
        } else {
            Err(ProxyRouteKeyError::InvalidPrefix(s.to_string()))
        }
    }
}

impl fmt::Display for ProxyRouteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(port) => write!(f, "p{port}"),
            Self::Route(hostname) => write!(f, "r{hostname}"),
        }
    }
}

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFProxyRoute",
    namespaced
)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "self.backend.matches('^.+:[0-9]+$')",
            "message": "backend must be in 'host:port' format"
        },
    ])
)]
#[serde(rename_all = "camelCase")]
/// Internal data-plane route configuration managed exclusively by Cardinal.
pub struct CTFProxyRouteSpec {
    /// Target backend address (host:port or IP:port).
    pub backend: String,
    #[serde(default)]
    pub policy: RoutePolicySpec,
}

impl CTFProxyRoute {
    /// Extracts and parses the `ProxyRouteKey` directly from `metadata.name`.
    pub fn route_key(&self) -> Result<ProxyRouteKey, ProxyRouteKeyError> {
        let name = self.metadata.name.as_deref().unwrap_or_default();
        ProxyRouteKey::from_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[test]
    fn test_proxy_route_key_tcp_parsing() {
        assert_eq!(
            ProxyRouteKey::from_str("p80").unwrap(),
            ProxyRouteKey::Tcp(80)
        );
        assert_eq!(
            ProxyRouteKey::from_str("p30005").unwrap(),
            ProxyRouteKey::Tcp(30005)
        );
        assert_eq!(
            ProxyRouteKey::from_str("p65535").unwrap(),
            ProxyRouteKey::Tcp(65535)
        );

        // Invalid TCP port names
        assert_eq!(
            ProxyRouteKey::from_str("p0"),
            Err(ProxyRouteKeyError::InvalidPort("0".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("p65536"),
            Err(ProxyRouteKeyError::InvalidPort("65536".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("p"),
            Err(ProxyRouteKeyError::InvalidPort("".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("p-80"),
            Err(ProxyRouteKeyError::InvalidPort("-80".to_string()))
        );
    }

    #[test]
    fn test_proxy_route_key_route_parsing() {
        assert_eq!(
            ProxyRouteKey::from_str("rwhoami").unwrap(),
            ProxyRouteKey::Route("whoami".to_string())
        );
        assert_eq!(
            ProxyRouteKey::from_str("rweb-chal-12345").unwrap(),
            ProxyRouteKey::Route("web-chal-12345".to_string())
        );

        // Invalid route hostnames
        assert_eq!(
            ProxyRouteKey::from_str("r"),
            Err(ProxyRouteKeyError::EmptyRouteName)
        );
        assert_eq!(
            ProxyRouteKey::from_str("r-whoami"),
            Err(ProxyRouteKeyError::InvalidRouteName("-whoami".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("rwhoami-"),
            Err(ProxyRouteKeyError::InvalidRouteName("whoami-".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("rWhoami_Upper"),
            Err(ProxyRouteKeyError::InvalidRouteName(
                "Whoami_Upper".to_string()
            ))
        );
    }

    #[test]
    fn test_proxy_route_key_invalid_prefix() {
        assert_eq!(
            ProxyRouteKey::from_str("twhoami"),
            Err(ProxyRouteKeyError::InvalidPrefix("twhoami".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str("x12345"),
            Err(ProxyRouteKeyError::InvalidPrefix("x12345".to_string()))
        );
        assert_eq!(
            ProxyRouteKey::from_str(""),
            Err(ProxyRouteKeyError::InvalidPrefix("".to_string()))
        );
    }

    #[test]
    fn test_proxy_route_key_display() {
        assert_eq!(ProxyRouteKey::Tcp(80).to_string(), "p80");
        assert_eq!(ProxyRouteKey::Tcp(30005).to_string(), "p30005");
        assert_eq!(
            ProxyRouteKey::Route("whoami-123".to_string()).to_string(),
            "rwhoami-123"
        );
    }

    #[test]
    fn test_ctf_proxy_route_route_key() {
        let route_tcp = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p30005".to_string()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:80".to_string(),
                ..Default::default()
            },
        };
        assert_eq!(route_tcp.route_key().unwrap(), ProxyRouteKey::Tcp(30005));

        let route_hostname = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami".to_string()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:80".to_string(),
                ..Default::default()
            },
        };
        assert_eq!(
            route_hostname.route_key().unwrap(),
            ProxyRouteKey::Route("whoami".to_string())
        );
    }

    #[test]
    fn test_ctf_proxy_route_spec_deserialization() {
        let json = serde_json::json!({
            "backend": "chal-1-c-web.default.svc.cluster.local:8080",
            "policy": {
                "flag": "CTF{test}",
                "pow": {
                    "difficulty": 10000,
                    "enableAdminBypass": true
                }
            }
        });

        let spec: CTFProxyRouteSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.backend, "chal-1-c-web.default.svc.cluster.local:8080");
        assert_eq!(spec.policy.flag.as_deref(), Some("CTF{test}"));
        assert_eq!(spec.policy.pow.as_ref().unwrap().difficulty, 10000);
        assert!(spec.policy.pow.as_ref().unwrap().enable_admin_bypass);
    }
}

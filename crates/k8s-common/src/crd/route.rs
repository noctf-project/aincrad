use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::crd::util::{KubeListKey, json_patch_schema};

fn clamp_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    i64::deserialize(d).map(|v| v.max(0) as u64)
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteBackend {
    pub service: String,
    pub port: u16,
}

impl RouteBackend {
    /// Returns the target address string `host:port`.
    /// If `host` contains a dot or colon, namespace is ignored and `host:port` is returned.
    /// Otherwise, it formats as a local K8s service: `{host}.{namespace}.svc.{cluster_domain}:{port}`.
    pub fn address(&self, namespace: &str, cluster_domain: &str) -> String {
        if self.service.contains('.') || self.service.contains(':') {
            format!("{}:{}", self.service, self.port)
        } else {
            format!(
                "{}.{}.svc.{}:{}",
                self.service, namespace, cluster_domain, self.port
            )
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSpecTCP {
    /// Dedicated TCP port (0 or omitted for auto-allocation, or fixed port in reserved range).
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSpecTLS {
    /// Subdomain prefix for the derived TLS hostname (e.g. 'web' in 'web-xxxx.c.noctf.dev'). Defaults to the route metadata name if omitted.
    #[schemars(length(max = 48), regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget<'a> {
    Tcp(&'a RouteSpecTCP),
    Tls(&'a RouteSpecTLS),
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
/// Policy applied to player traffic for the route.
pub struct RoutePolicySpec {
    /// Flag string or template string for the challenge route.
    #[serde(default)]
    pub flag: Option<String>,
    /// Optional UTC timestamp after which this route becomes active and accessible to players.
    pub available_at: Option<DateTime<Utc>>,
    /// Cryptographic secret used for Proof-of-Work verification and AES flag encryption.
    pub secret: Option<String>,
    /// Request the team's id in the TCP tunnel.
    #[serde(default)]
    pub request_uid: bool,
    /// Optional Proof-of-Work configuration requiring clients to solve a PoW challenge before connecting.
    pub pow: Option<RouteSpecPOW>,
    /// When true, enables logging of player TCP/TLS session traffic.
    #[serde(default)]
    pub logs: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "has(self.tcp) != has(self.tls)",
            "message": "Route must specify either 'tcp' or 'tls', but not both"
        },
        {
            "rule": "!has(self.tcp) || !has(self.tcp.port) || self.tcp.port == 0",
            "message": "Explicit external ports cannot be set; port must be omitted or set to 0"
        }
    ])
)]
#[serde(rename_all = "camelCase")]
/// Specification for dynamic L4 TCP/TLS routing and traffic inspection.
pub struct RouteSpec {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 24)
    )]
    pub name: String,
    #[serde(default)]
    pub policy: RoutePolicySpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "json_patch_schema")]
    pub patch_policy: Option<json_patch::Patch>,
    /// Target backend Kubernetes service name and port.
    pub backend: RouteBackend,
    /// TCP routing configuration (mutually exclusive with 'tls').
    pub tcp: Option<RouteSpecTCP>,
    /// TLS routing configuration (mutually exclusive with 'tcp').
    pub tls: Option<RouteSpecTLS>,
}

impl KubeListKey for RouteSpec {
    const KEYS: &'static [&'static str] = &["name"];
}

impl RouteSpec {
    pub fn target(&self) -> Option<RouteTarget<'_>> {
        match (&self.tcp, &self.tls) {
            (Some(tcp), None) => Some(RouteTarget::Tcp(tcp)),
            (None, Some(tls)) => Some(RouteTarget::Tls(tls)),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSpecPOW {
    #[serde(deserialize_with = "clamp_u64")]
    pub difficulty: u64,
    #[serde(default)]
    pub enable_admin_bypass: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_spec_deserialization() {
        let json_tcp = serde_json::json!({
            "name": "pwn",
            "backend": {
                "service": "127.0.0.1",
                "port": 8080
            },
            "tcp": {
                "port": 20001
            },
            "policy": {
                "flag": "my_flag"
            }
        });
        let spec_tcp: RouteSpec = serde_json::from_value(json_tcp).unwrap();
        assert_eq!(spec_tcp.backend.service, "127.0.0.1");
        assert_eq!(spec_tcp.backend.port, 8080);
        assert_eq!(spec_tcp.policy.flag, Some("my_flag".to_string()));
        assert_eq!(
            spec_tcp.target(),
            Some(RouteTarget::Tcp(&RouteSpecTCP { port: Some(20001) }))
        );

        let json_tls = serde_json::json!({
            "name": "web",
            "backend": {
                "service": "127.0.0.1",
                "port": 8080
            },
            "tls": {
                "prefix": "web"
            }
        });
        let spec_tls: RouteSpec = serde_json::from_value(json_tls).unwrap();
        assert_eq!(
            spec_tls.target(),
            Some(RouteTarget::Tls(&RouteSpecTLS {
                prefix: Some("web".to_string())
            }))
        );
    }

    #[test]
    fn test_backend_address() {
        let b1 = RouteBackend {
            service: "web-service".to_string(),
            port: 80,
        };
        assert_eq!(
            b1.address("default", "cluster.local"),
            "web-service.default.svc.cluster.local:80"
        );
        assert_eq!(
            b1.address("default", "custom.domain"),
            "web-service.default.svc.custom.domain:80"
        );

        let b2 = RouteBackend {
            service: "127.0.0.1".to_string(),
            port: 8080,
        };
        assert_eq!(b2.address("default", "cluster.local"), "127.0.0.1:8080");

        let b3 = RouteBackend {
            service: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(b3.address("custom-ns", "cluster.local"), "example.com:443");

        let b4 = RouteBackend {
            service: "svc.other-ns.svc.cluster.local".to_string(),
            port: 8080,
        };
        assert_eq!(
            b4.address("custom-ns", "cluster.local"),
            "svc.other-ns.svc.cluster.local:8080"
        );

        let b5 = RouteBackend {
            service: "::1".to_string(),
            port: 80,
        };
        assert_eq!(b5.address("custom-ns", "cluster.local"), "::1:80");
    }
}

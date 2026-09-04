use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::crd::util::KubeListKey;

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

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, JsonSchema, PartialEq, Eq)]
pub enum RouteProtocol {
    #[default]
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "UDP")]
    Udp,
}

impl RouteProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouteProtocol::Tcp => "TCP",
            RouteProtocol::Udp => "UDP",
        }
    }
}

impl std::fmt::Display for RouteProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteBackend {
    pub service: String,
    pub port: u16,
    /// Transport protocol for the backend service (TCP or UDP). Defaults to TCP if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<RouteProtocol>,
}

impl RouteBackend {
    pub fn protocol(&self) -> RouteProtocol {
        self.protocol.unwrap_or(RouteProtocol::Tcp)
    }

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
pub struct RouteSpecTLS {
    /// Subdomain prefix for the derived TLS hostname (e.g. 'web' in 'web-xxxx.c.noctf.dev'). Defaults to the route metadata name if omitted.
    #[schemars(length(max = 48), regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget<'a> {
    Port(Option<u16>, RouteProtocol),
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
    /// Optional idle timeout in seconds (clamped to cluster max-idle-timeout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "has(self.port) != has(self.tls)",
            "message": "Route must specify either 'port' or 'tls', but not both"
        },
        {
            "rule": "!has(self.tls) || !has(self.backend.protocol) || self.backend.protocol == 'TCP'",
            "message": "TLS routes cannot target a UDP backend"
        },
        {
            "rule": "!has(self.port) || self.port == 0",
            "message": "Explicit external ports cannot be set; port must be omitted or set to 0"
        }
    ])
)]
#[serde(rename_all = "camelCase")]
/// Specification for dynamic L4 TCP/UDP and L7 TLS routing.
pub struct RouteSpec {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 24)
    )]
    pub name: String,
    /// Target backend Kubernetes service name, port, and protocol.
    pub backend: RouteBackend,
    /// Dedicated external L4 port (0 or omitted for auto-allocation, or fixed port in reserved range). Mutually exclusive with 'tls'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// TLS routing configuration (mutually exclusive with 'port').
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<RouteSpecTLS>,
}

impl KubeListKey for RouteSpec {
    const KEYS: &'static [&'static str] = &["name"];
}

impl RouteSpec {
    pub fn target(&self) -> Option<RouteTarget<'_>> {
        match (self.port, &self.tls) {
            (Some(p), None) => Some(RouteTarget::Port(Some(p), self.backend.protocol())),
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
            "port": 20001
        });
        let spec_tcp: RouteSpec = serde_json::from_value(json_tcp).unwrap();
        assert_eq!(spec_tcp.backend.service, "127.0.0.1");
        assert_eq!(spec_tcp.backend.port, 8080);
        assert_eq!(spec_tcp.backend.protocol(), RouteProtocol::Tcp);
        assert_eq!(
            spec_tcp.target(),
            Some(RouteTarget::Port(Some(20001), RouteProtocol::Tcp))
        );

        let json_udp = serde_json::json!({
            "name": "dns",
            "backend": {
                "service": "127.0.0.1",
                "port": 53,
                "protocol": "UDP"
            },
            "port": 0
        });
        let spec_udp: RouteSpec = serde_json::from_value(json_udp).unwrap();
        assert_eq!(spec_udp.backend.protocol(), RouteProtocol::Udp);
        assert_eq!(
            spec_udp.target(),
            Some(RouteTarget::Port(Some(0), RouteProtocol::Udp))
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
            protocol: None,
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
            protocol: None,
        };
        assert_eq!(b2.address("default", "cluster.local"), "127.0.0.1:8080");

        let b3 = RouteBackend {
            service: "example.com".to_string(),
            port: 443,
            protocol: None,
        };
        assert_eq!(b3.address("custom-ns", "cluster.local"), "example.com:443");

        let b4 = RouteBackend {
            service: "svc.other-ns.svc.cluster.local".to_string(),
            port: 8080,
            protocol: None,
        };
        assert_eq!(
            b4.address("custom-ns", "cluster.local"),
            "svc.other-ns.svc.cluster.local:8080"
        );

        let b5 = RouteBackend {
            service: "::1".to_string(),
            port: 80,
            protocol: None,
        };
        assert_eq!(b5.address("custom-ns", "cluster.local"), "::1:80");
    }
}

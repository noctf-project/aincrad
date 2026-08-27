use chrono::{DateTime, Utc};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

fn clamp_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    i64::deserialize(d).map(|v| v.max(0) as u64)
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteEndpoints {
    #[serde(default)]
    pub tls: Option<EndpointTarget>,
    #[serde(default)]
    pub tcp: Option<EndpointTarget>,
}

use crate::crd::util::list_schema;

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteStatus {
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub endpoints: Option<CTFRouteEndpoints>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<Condition>")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteBackend {
    pub service: String,
    pub port: u16,
}

impl CTFRouteBackend {
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

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFRoute",
    namespaced,
    status = CTFRouteStatus,
)]
#[serde(rename_all = "camelCase")]
/// Specification for dynamic L4 TCP/TLS routing and traffic inspection.
pub struct CTFRouteSpec {
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
    pub pow: Option<CTFRouteSpecPOW>,
    /// When true, enables logging of player TCP/TLS session traffic.
    #[serde(default)]
    pub logs: bool,
    /// Target backend Kubernetes service name and port.
    pub backend: CTFRouteBackend,
    /// Dedicated TCP port requested for raw TCP routing.
    pub port: Option<u16>,
    /// Optional TLS SNI routing configuration.
    pub tls: Option<CTFRouteSpecTLS>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteSpecPOW {
    #[serde(deserialize_with = "clamp_u64")]
    pub difficulty: u64,
    #[serde(default)]
    pub enable_admin_bypass: bool,
}

use aincrad_macros::PatchValue;

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, PatchValue)]
#[serde(rename_all = "camelCase")]
pub struct CTFRouteSpecTLS {
    /// Subdomain prefix for the derived TLS hostname (e.g. 'web' in 'web-xxxx.c.noctf.dev'). Defaults to the route metadata name if omitted.
    #[schemars(length(max = 48), regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub prefix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_spec_deserialization() {
        let json_omitted = serde_json::json!({
            "backend": {
                "service": "127.0.0.1",
                "port": 8080
            }
        });
        let spec_omitted: CTFRouteSpec = serde_json::from_value(json_omitted).unwrap();
        assert_eq!(spec_omitted.backend.service, "127.0.0.1");
        assert_eq!(spec_omitted.backend.port, 8080);
        assert_eq!(spec_omitted.flag, None);
        assert_eq!(spec_omitted.tls, None);
        assert_eq!(spec_omitted.port, None);

        let json_empty_tag = serde_json::json!({
            "backend": {
                "service": "127.0.0.1",
                "port": 8080
            },
            "tls": {},
        });
        let spec_empty_tag: CTFRouteSpec = serde_json::from_value(json_empty_tag).unwrap();
        assert_eq!(spec_empty_tag.tls, Some(CTFRouteSpecTLS { prefix: None }));

        let json_full = serde_json::json!({
            "backend": {
                "service": "127.0.0.1",
                "port": 8080
            },
            "flag": "my_flag",
            "port": 20001,
            "tls": {
                "prefix": "web"
            },
        });
        let spec_full: CTFRouteSpec = serde_json::from_value(json_full).unwrap();
        assert_eq!(spec_full.flag, Some("my_flag".to_string()));
        assert_eq!(spec_full.port, Some(20001));
        assert_eq!(
            spec_full.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
            })
        );
    }

    #[test]
    fn test_backend_address() {
        let b1 = CTFRouteBackend {
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

        let b2 = CTFRouteBackend {
            service: "127.0.0.1".to_string(),
            port: 8080,
        };
        assert_eq!(b2.address("default", "cluster.local"), "127.0.0.1:8080");

        let b3 = CTFRouteBackend {
            service: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(b3.address("custom-ns", "cluster.local"), "example.com:443");

        let b4 = CTFRouteBackend {
            service: "svc.other-ns.svc.cluster.local".to_string(),
            port: 8080,
        };
        assert_eq!(
            b4.address("custom-ns", "cluster.local"),
            "svc.other-ns.svc.cluster.local:8080"
        );

        let b5 = CTFRouteBackend {
            service: "::1".to_string(),
            port: 80,
        };
        assert_eq!(b5.address("custom-ns", "cluster.local"), "::1:80");
    }
}

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    EndpointTarget, RouteSpecTCP, RouteSpecTLS,
    util::{KubeListKey, PatchValue, immutable_property_schema, list_schema},
};

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceStatusEndpoint {
    /// Endpoint or route name.
    pub name: String,
    /// Protocol type (e.g. 'tls' or 'tcp').
    #[serde(rename = "type")]
    pub type_: String,
    /// Host and port target details.
    pub target: EndpointTarget,
}

impl KubeListKey for CTFInstanceStatusEndpoint {
    const KEYS: &'static [&'static str] = &["name"];
}

/// Per-instance typed status resources exposed to downstream consumers.
#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<CTFInstanceStatusEndpoint>>,
}

impl CTFInstanceResources {
    pub fn overlay(&mut self, from: CTFInstanceResources) {
        if from.endpoints.is_some() {
            self.endpoints = from.endpoints;
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceStatus {
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarted_at: Option<String>,
    #[serde(default)]
    pub resources: CTFInstanceResources,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub children: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<Condition>")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceSpecParam {
    /// Name of the parameter to set or override.
    #[schemars(
        regex(pattern = r"^[_a-z0-9]([-_a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 32)
    )]
    pub name: String,
    /// Parameter value override:
    /// - Set to string value (e.g. `"val"`) to override parameter value.
    /// - Set to `null` to remove parameter.
    #[serde(default)]
    pub value: PatchValue<String>,
}

impl KubeListKey for CTFInstanceSpecParam {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceSpecPodOverride {
    /// Name of the template pod specification to override replicas for.
    #[schemars(length(min = 1, max = 24))]
    pub name: String,
    /// Replica count override for this pod.
    pub replicas: i32,
}

impl KubeListKey for CTFInstanceSpecPodOverride {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "!(has(self.tcp) && has(self.tls))",
            "message": "Route override must not specify both 'tcp' and 'tls'; inherit from the template for the default route type"
        }
    ])
)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceSpecRouteOverride {
    /// Name of the template route to override.
    #[schemars(length(min = 1, max = 24))]
    pub name: String,
    /// TCP route override (explicit port or auto). Omitted: inherit from
    /// CTFTemplate.
    #[serde(default)]
    pub tcp: Option<RouteSpecTCP>,
    /// TLS route override. Omitted: inherit from CTFTemplate.
    #[serde(default)]
    pub tls: Option<RouteSpecTLS>,
}

impl KubeListKey for CTFInstanceSpecRouteOverride {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFInstance",
    namespaced,
    status = CTFInstanceStatus,
)]
#[serde(rename_all = "camelCase")]
/// Specification for an ephemeral CTF challenge instance sandbox.
pub struct CTFInstanceSpec {
    /// Name of the CTFTemplate resource to instantiate.
    #[schemars(schema_with = "immutable_property_schema")]
    pub template: String,
    /// Sync instance with the upstream template if enabled.
    #[serde(default)]
    pub sync: bool,
    /// Parameter overrides for this specific challenge instance.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFInstanceSpecParam>")]
    pub params: Vec<CTFInstanceSpecParam>,
    /// Pod replica count overrides for this specific challenge instance.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFInstanceSpecPodOverride>")]
    pub pods: Vec<CTFInstanceSpecPodOverride>,
    /// Route port and TLS overrides for this specific challenge instance.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFInstanceSpecRouteOverride>")]
    pub routes: Vec<CTFInstanceSpecRouteOverride>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_override_deserialization() {
        let json_inherit = r#"{"name": "pwn-tcp"}"#;
        let inherit: CTFInstanceSpecRouteOverride = serde_json::from_str(json_inherit).unwrap();
        assert_eq!(inherit.tcp, None);
        assert_eq!(inherit.tls, None);

        let json_tcp = r#"{"name": "pwn-tcp", "tcp": {"port": 20001}}"#;
        let tcp_override: CTFInstanceSpecRouteOverride = serde_json::from_str(json_tcp).unwrap();
        assert_eq!(tcp_override.tcp, Some(RouteSpecTCP { port: Some(20001) }));
        assert_eq!(tcp_override.tls, None);

        let json_tls = r#"{"name": "web", "tls": {"prefix": "custom"}}"#;
        let tls_override: CTFInstanceSpecRouteOverride = serde_json::from_str(json_tls).unwrap();
        assert_eq!(tls_override.tcp, None);
        assert_eq!(
            tls_override.tls,
            Some(RouteSpecTLS {
                prefix: Some("custom".to_string())
            })
        );
    }
}

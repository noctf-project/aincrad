use chrono::{DateTime, Utc};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    CTFRouteSpecTLSPatch, EndpointTarget,
    util::{KubeListKey, PatchValue, immutable_property_schema, list_schema},
};

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
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
    const KEYS: &'static [&'static str] = &["name", "type"];
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceStatus {
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<CTFInstanceStatusEndpoint>")]
    pub endpoints: Vec<CTFInstanceStatusEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<Condition>")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceSpecParam {
    /// Name of the parameter to set or override.
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 24)
    )]
    pub name: String,
    /// Parameter value override:
    /// - `PatchValue::Value("val")`: Set parameter value.
    /// - `PatchValue::Null` (`value: null`): Remove parameter.
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
    #[schemars(length(min = 1, max = 20))]
    pub name: String,
    /// Replica count override for this pod.
    pub replicas: i32,
}

impl KubeListKey for CTFInstanceSpecPodOverride {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFInstanceSpecRouteOverride {
    /// Name of the template route to override.
    #[schemars(length(min = 1, max = 20))]
    pub name: String,
    /// Dedicated TCP port override for this route:
    /// - `PatchValue::Unset` (omitted): Inherit port from CTFTemplate.
    /// - `PatchValue::Null` (`port: null`): Disable TCP.
    /// - `PatchValue::Value(port)` (`port: 20001`): Force a specific fixed TCP port.
    #[serde(default)]
    pub port: PatchValue<u16>,
    /// TLS configuration override for this route:
    /// - `PatchValue::Unset` (omitted): Inherit TLS configuration from CTFTemplate.
    /// - `PatchValue::Null` (`tls: null`): Disable TLS.
    /// - `PatchValue::Value(tls)`: Enable TLS.
    #[serde(default)]
    pub tls: PatchValue<CTFRouteSpecTLSPatch>,
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
pub struct CTFInstanceSpec {
    /// Name of the CTFTemplate resource to instantiate.
    #[schemars(schema_with = "immutable_property_schema")]
    pub template: String,
    /// Optional UTC timestamp when this ephemeral player sandbox expires.
    pub expires_at: Option<DateTime<Utc>>,
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
    fn test_nullable_deserialization() {
        let json_unset = r#"{"name": "pwn-tcp"}"#;
        let override_unset: CTFInstanceSpecRouteOverride =
            serde_json::from_str(json_unset).unwrap();
        assert_eq!(override_unset.port, PatchValue::Unset);
        assert_eq!(override_unset.tls, PatchValue::Unset);

        let json_null = r#"{"name": "pwn-tcp", "port": null, "tls": null}"#;
        let override_null: CTFInstanceSpecRouteOverride = serde_json::from_str(json_null).unwrap();
        assert_eq!(override_null.port, PatchValue::Null);
        assert_eq!(override_null.tls, PatchValue::Null);

        let json_value = r#"{"name": "pwn-tcp", "port": 20001, "tls": {"prefix": null}}"#;
        let override_value: CTFInstanceSpecRouteOverride =
            serde_json::from_str(json_value).unwrap();
        assert_eq!(override_value.port, PatchValue::Value(20001));
        assert_eq!(
            override_value.tls,
            PatchValue::Value(CTFRouteSpecTLSPatch {
                prefix: PatchValue::Null
            })
        );
    }
}

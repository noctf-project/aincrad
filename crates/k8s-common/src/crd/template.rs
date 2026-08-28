use k8s_openapi::{api::core::v1::PodSpec, apimachinery::pkg::apis::meta::v1::Condition};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    CTFRouteSpec,
    util::{KubeListKey, default_val, embedded_resource_schema, json_patch_schema, list_schema},
};

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<Condition>")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpecParam {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 24)
    )]
    pub name: String,
    pub value: String,
}

impl KubeListKey for CTFTemplateSpecParam {
    const KEYS: &'static [&'static str] = &["name"];
}

impl KubeListKey for CTFTemplateSpecPod {
    const KEYS: &'static [&'static str] = &["name"];
}

impl KubeListKey for CTFTemplateSpecRoute {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[kube(
    group = "aincrad.noctf.dev",
    version = "v1",
    kind = "CTFTemplate",
    namespaced,
    status = CTFTemplateStatus,
)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "self.routes.all(r, self.pods.exists(p, p.name == r.spec.backend.service))",
            "message": "Each route backend service must match a valid pod name defined in 'spec.pods'"
        },
    ])
)]
#[serde(rename_all = "camelCase")]
/// Specification for a reusable CTF challenge workload template.
pub struct CTFTemplateSpec {
    /// Key-value parameters passed to challenge pods as environment variables or configuration values.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFTemplateSpecParam>")]
    pub params: Vec<CTFTemplateSpecParam>,
    /// List of pod specifications that make up a challenge instance.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFTemplateSpecPod>")]
    pub pods: Vec<CTFTemplateSpecPod>,
    /// List of CTFRoute definitions that expose backend services.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFTemplateSpecRoute>")]
    pub routes: Vec<CTFTemplateSpecRoute>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpecPod {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 20)
    )]
    pub name: String,
    #[serde(default)]
    pub allow_internet: bool,
    #[serde(default = "default_val::<1>")]
    pub replicas: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "json_patch_schema")]
    pub patch: Option<json_patch::Patch>,
    #[schemars(schema_with = "embedded_resource_schema::<PodSpec>")]
    pub spec: PodSpec,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "has(self.spec.tcp) != has(self.spec.tls)",
            "message": "Route must specify either 'tcp' or 'tls', but not both"
        },
        {
            "rule": "!has(self.spec.tcp) || !has(self.spec.tcp.port) || self.spec.tcp.port == 0",
            "message": "Explicit external ports cannot be set; port must be omitted or set to 0"
        }
    ])
)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpecRoute {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 20)
    )]
    pub name: String,
    pub spec: CTFRouteSpec,
}

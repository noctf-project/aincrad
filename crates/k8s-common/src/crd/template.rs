use k8s_openapi::{api::core::v1::PodSpec, apimachinery::pkg::apis::meta::v1::Condition};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    RouteSpec,
    util::{KubeListKey, default_val, embedded_resource_schema, json_patch_schema, list_schema},
};

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TemplateStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "list_schema::<Condition>")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSpecParam {
    #[schemars(
        regex(pattern = r"^[_a-z0-9]([-_a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 32)
    )]
    pub name: String,
    pub value: String,
}

impl KubeListKey for TemplateSpecParam {
    const KEYS: &'static [&'static str] = &["name"];
}

impl KubeListKey for TemplateSpecPod {
    const KEYS: &'static [&'static str] = &["name"];
}

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[kube(
    group = "cardinal.noctf.dev",
    version = "v1",
    kind = "Template",
    namespaced,
    status = TemplateStatus,
    shortname = "ctmpl",
)]
#[schemars(
        extend("x-kubernetes-validations" = [
            {
                "rule": "self.routes.all(r, self.pods.exists(p, p.name == r.backend.service))",
                "message": "Each route backend service must match a valid pod name defined in 'spec.pods'"
            },
        ])
    )]
#[serde(rename_all = "camelCase")]
/// Specification for a reusable CTF challenge workload template.
pub struct TemplateSpec {
    /// Key-value parameters passed to challenge pods as environment variables or configuration values.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<TemplateSpecParam>")]
    pub params: Vec<TemplateSpecParam>,
    /// List of pod specifications that make up a challenge instance.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<TemplateSpecPod>")]
    pub pods: Vec<TemplateSpecPod>,
    /// List of RouteSpec definitions that expose backend services.
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<RouteSpec>")]
    pub routes: Vec<RouteSpec>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSpecPod {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 24)
    )]
    pub name: String,
    #[serde(default)]
    pub allow_internet: bool,
    #[serde(default = "default_val::<1>")]
    pub replicas: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "json_patch_schema")]
    pub patch_spec: Option<json_patch::Patch>,
    #[schemars(schema_with = "embedded_resource_schema::<PodSpec>")]
    pub spec: PodSpec,
}

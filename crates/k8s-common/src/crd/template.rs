use chrono::{DateTime, Utc};
use k8s_openapi::{api::core::v1::PodSpec, apimachinery::pkg::apis::meta::v1::Condition};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    CTFRouteSpec,
    util::{KubeListKey, default_val, list_schema},
};

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateStatus {
    pub conditions: Vec<Condition>,
}

impl KubeListKey for CTFTemplateSpecPod {
    const KEY: &'static str = "name";
}

impl KubeListKey for CTFTemplateSpecRoute {
    const KEY: &'static str = "name";
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
            "rule": "self.routes.all(r, self.pods.exists(p, p.name == r.backend.service))",
            "message": "Each route backend service must match a valid pod name defined in 'spec.pods'"
        },
    ])
)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpec {
    pub available_at: Option<DateTime<Utc>>,
    #[serde(default)]
    #[schemars(schema_with = "list_schema::<CTFTemplateSpecPod>")]
    pub pods: Vec<CTFTemplateSpecPod>,

    #[schemars(schema_with = "list_schema::<CTFTemplateSpecRoute>")]
    #[serde(default)]
    pub routes: Vec<CTFTemplateSpecRoute>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpecPod {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 63)
    )]
    pub name: String,
    #[serde(default = "default_val::<1>")]
    pub replicas: i32,
    pub spec: PodSpec,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema, PartialEq)]
#[schemars(
    extend("x-kubernetes-validations" = [
        {
            "rule": "!has(self.spec.port) || self.spec.port == 0",
            "message": "Explicit external ports cannot be set; port must be omitted or set to 0"
        }
    ])
)]
#[serde(rename_all = "camelCase")]
pub struct CTFTemplateSpecRoute {
    #[schemars(
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
        length(min = 1, max = 63)
    )]
    pub name: String,
    pub spec: CTFRouteSpec,
}

use k8s_common::crd::{InstanceSpec, InstanceStatusEndpoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutInstanceRequest {
    /// Desired specification of the challenge sandbox.
    #[schema(value_type = Object)]
    pub spec: InstanceSpec,

    /// Optional metadata labels to attach to the instance.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,

    /// Optional explicit TTL override in seconds.
    /// If omitted, falls back to the template's defaultTtl annotation, or permanent if neither is set.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceResponse {
    /// Name of the instance.
    pub name: String,

    /// Namespace where the instance resides.
    pub namespace: String,

    /// High-level lifecycle phase: "Ready", "Pending", or "Failed".
    pub phase: String,

    /// Challenge template instantiated.
    pub template: String,

    /// RFC 3339 expiration timestamp, if the instance has a TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Live exposed endpoints (host, port, protocol).
    #[schema(value_type = Vec<Object>)]
    pub endpoints: Vec<InstanceStatusEndpoint>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenewInstanceRequest {
    /// Optional number of seconds to set the expiration to. If omitted, resets to template default TTL ("auto").
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenewInstanceResponse {
    pub name: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error: String,
}

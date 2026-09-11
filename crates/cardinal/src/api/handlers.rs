use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration as ChronoDuration, Utc};
use k8s_common::crd::Instance;
use k8s_common::labels::{
    EXPIRES_AT_ANNOTATION, INSTANCE_LABEL, MANAGED_BY_LABEL, RESTARTED_AT_ANNOTATION,
    TEMPLATE_LABEL,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams, Patch, PatchParams},
};
use serde::Deserialize;
use std::sync::Arc;

use super::{
    auth::VerifiedKeyId,
    models::{
        ApiErrorResponse, InstanceResponse, PutInstanceRequest, RenewInstanceRequest,
        RenewInstanceResponse,
    },
};
use crate::config::ApiConfig;

use parking_lot::RwLock;

#[derive(Clone)]
pub struct ApiState {
    pub client: Client,
    pub config: Arc<RwLock<Arc<ApiConfig>>>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(rename = "labelSelector")]
    pub label_selector: Option<String>,
}

/// Ensure or create an instance (idempotent PUT).
#[utoipa::path(
    put,
    path = "/v1/namespaces/{namespace}/instances/{id}",
    request_body = PutInstanceRequest,
    responses(
        (status = 200, description = "Instance already exists, returned current state", body = InstanceResponse),
        (status = 201, description = "Instance created", body = InstanceResponse),
        (status = 400, description = "Invalid request or template not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("id" = String, Path, description = "Unique instance identifier")
    )
)]
pub async fn put_instance(
    State(state): State<ApiState>,
    Path((namespace, id)): Path<(String, String)>,
    Extension(key_id): Extension<VerifiedKeyId>,
    Json(payload): Json<PutInstanceRequest>,
) -> Result<Response, (StatusCode, Json<ApiErrorResponse>)> {
    let instance_api: Api<Instance> = Api::namespaced(state.client.clone(), &namespace);

    let mut annotations = std::collections::BTreeMap::new();
    if let Some(ttl_secs) = payload.ttl_seconds {
        let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs as i64);
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), expires_at.to_rfc3339());
    } else {
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), "auto".to_string());
    }

    let mut labels = payload.labels;
    labels.insert(MANAGED_BY_LABEL.to_string(), "cardinal-api".to_string());
    labels.insert(INSTANCE_LABEL.to_string(), id.clone());
    labels.insert(TEMPLATE_LABEL.to_string(), payload.spec.template.clone());

    let instance = Instance {
        metadata: ObjectMeta {
            name: Some(id.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: payload.spec,
        status: None,
    };

    let patch_params = PatchParams::apply("cardinal-api").force();
    let applied = instance_api
        .patch(&id, &patch_params, &Patch::Apply(&instance))
        .await
        .map_err(|e| {
            tracing::error!(target: "cardinal::api", error = %e, "Failed to apply instance CRD");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    error: format!("Failed to apply instance: {e}"),
                }),
            )
        })?;

    tracing::info!(
        action = "put_instance",
        key_id = %key_id.0,
        namespace = %namespace,
        instance = %id
    );

    Ok((StatusCode::OK, Json(to_instance_response(&applied))).into_response())
}

/// Get an instance status and endpoints.
#[utoipa::path(
    get,
    path = "/v1/namespaces/{namespace}/instances/{id}",
    responses(
        (status = 200, description = "Instance found", body = InstanceResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Instance not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("id" = String, Path, description = "Instance identifier")
    )
)]
pub async fn get_instance(
    State(state): State<ApiState>,
    Path((namespace, id)): Path<(String, String)>,
) -> Result<Json<InstanceResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    let api: Api<Instance> = Api::namespaced(state.client, &namespace);
    let inst = api.get(&id).await.map_err(|e| match e {
        kube::Error::Api(ref err) if err.code == 404 => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                error: format!("Instance '{id}' not found in namespace '{namespace}'"),
            }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                error: format!("Failed to get instance: {e}"),
            }),
        ),
    })?;

    Ok(Json(to_instance_response(&inst)))
}

/// Trigger a rolling restart for an instance, preserving allocated ports and routes.
#[utoipa::path(
    post,
    path = "/v1/namespaces/{namespace}/instances/{id}/restart",
    responses(
        (status = 200, description = "Restart triggered"),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Instance not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("id" = String, Path, description = "Instance identifier")
    )
)]
pub async fn restart_instance(
    State(state): State<ApiState>,
    Path((namespace, id)): Path<(String, String)>,
    Extension(key_id): Extension<VerifiedKeyId>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let api: Api<Instance> = Api::namespaced(state.client, &namespace);
    let now = Utc::now().to_rfc3339();

    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                RESTARTED_AT_ANNOTATION: now
            }
        }
    });

    api.patch_metadata(&id, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| match e {
            kube::Error::Api(ref err) if err.code == 404 => (
                StatusCode::NOT_FOUND,
                Json(ApiErrorResponse {
                    error: format!("Instance '{id}' not found"),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    error: format!("Failed to patch restartedAt: {e}"),
                }),
            ),
        })?;

    tracing::info!(
        action = "restart_instance",
        key_id = %key_id.0,
        namespace = %namespace,
        instance = %id
    );

    Ok(StatusCode::OK)
}

/// Renew or extend an instance's TTL.
#[utoipa::path(
    post,
    path = "/v1/namespaces/{namespace}/instances/{id}/renew",
    request_body = RenewInstanceRequest,
    responses(
        (status = 200, description = "TTL extended", body = RenewInstanceResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Instance not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("id" = String, Path, description = "Instance identifier")
    )
)]
pub async fn renew_instance(
    State(state): State<ApiState>,
    Path((namespace, id)): Path<(String, String)>,
    Extension(key_id): Extension<VerifiedKeyId>,
    Json(payload): Json<RenewInstanceRequest>,
) -> Result<Json<RenewInstanceResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    let api: Api<Instance> = Api::namespaced(state.client, &namespace);

    let new_expires_str = if let Some(ttl_secs) = payload.ttl_seconds {
        (Utc::now() + ChronoDuration::seconds(ttl_secs as i64)).to_rfc3339()
    } else {
        "auto".to_string()
    };

    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                EXPIRES_AT_ANNOTATION: new_expires_str
            }
        }
    });

    api.patch_metadata(&id, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| match e {
            kube::Error::Api(ref err) if err.code == 404 => (
                StatusCode::NOT_FOUND,
                Json(ApiErrorResponse {
                    error: format!("Instance '{id}' not found"),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    error: format!("Failed to renew instance: {e}"),
                }),
            ),
        })?;

    tracing::info!(
        action = "renew_instance",
        key_id = %key_id.0,
        namespace = %namespace,
        instance = %id,
        expires = %new_expires_str
    );

    Ok(Json(RenewInstanceResponse {
        name: id,
        expires_at: new_expires_str,
    }))
}

/// Delete an instance
#[utoipa::path(
    delete,
    path = "/v1/namespaces/{namespace}/instances/{id}",
    responses(
        (status = 204, description = "Instance deleted"),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Instance not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("id" = String, Path, description = "Instance identifier")
    )
)]
pub async fn delete_instance(
    State(state): State<ApiState>,
    Path((namespace, id)): Path<(String, String)>,
    Extension(key_id): Extension<VerifiedKeyId>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let api: Api<Instance> = Api::namespaced(state.client, &namespace);

    api.delete(&id, &DeleteParams::default())
        .await
        .map_err(|e| match e {
            kube::Error::Api(ref err) if err.code == 404 => (
                StatusCode::NOT_FOUND,
                Json(ApiErrorResponse {
                    error: format!("Instance '{id}' not found"),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    error: format!("Failed to delete instance: {e}"),
                }),
            ),
        })?;

    tracing::info!(
        action = "delete_instance",
        key_id = %key_id.0,
        namespace = %namespace,
        instance = %id
    );

    Ok(StatusCode::NO_CONTENT)
}

/// List instances in a namespace with optional label selector filtering.
#[utoipa::path(
    get,
    path = "/v1/namespaces/{namespace}/instances",
    responses(
        (status = 200, description = "List of instances", body = Vec<InstanceResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(
        ("namespace" = String, Path, description = "Target Kubernetes namespace"),
        ("labelSelector" = Option<String>, Query, description = "Kubernetes label selector filter e.g. cardinal.noctf.dev/owner=team-42")
    )
)]
pub async fn list_instances(
    State(state): State<ApiState>,
    Path(namespace): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<InstanceResponse>>, (StatusCode, Json<ApiErrorResponse>)> {
    let api: Api<Instance> = Api::namespaced(state.client, &namespace);
    let mut lp = ListParams::default();
    if let Some(ref ls) = query.label_selector {
        lp = lp.labels(ls);
    }

    let list = api.list(&lp).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                error: format!("Failed to list instances: {e}"),
            }),
        )
    })?;

    let responses: Vec<InstanceResponse> = list.iter().map(to_instance_response).collect();
    Ok(Json(responses))
}

fn to_instance_response(inst: &Instance) -> InstanceResponse {
    let name = inst.metadata.name.clone().unwrap_or_default();
    let namespace = inst.metadata.namespace.clone().unwrap_or_default();
    let template = inst.spec.template.clone();

    let expires_at = inst
        .metadata
        .annotations
        .as_ref()
        .and_then(|ann| ann.get(EXPIRES_AT_ANNOTATION))
        .cloned();

    let (phase, endpoints) = if let Some(ref status) = inst.status {
        let phase = match status.conditions.iter().find(|c| c.type_ == "Ready") {
            Some(c) if c.status == "True" => "Ready",
            Some(c) if c.status == "False" => "Unhealthy",
            _ => "Pending",
        };

        let eps = status.resources.endpoints.clone().unwrap_or_default();
        (phase.to_string(), eps)
    } else {
        ("Pending".to_string(), Vec::new())
    };

    InstanceResponse {
        name,
        namespace,
        phase,
        template,
        expires_at,
        endpoints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::recording_kube_client;
    use k8s_common::crd::InstanceSpec;

    fn test_state(client: Client) -> ApiState {
        ApiState {
            client,
            config: Arc::new(RwLock::new(Arc::new(ApiConfig::default()))),
        }
    }

    #[tokio::test]
    async fn test_put_instance_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let req = PutInstanceRequest {
            spec: InstanceSpec {
                template: "whoami-template".to_string(),
                ..Default::default()
            },
            ttl_seconds: Some(1800),
            labels: Default::default(),
        };

        let res = put_instance(
            State(state),
            Path(("default".to_string(), "chal-1".to_string())),
            Extension(VerifiedKeyId("test-key".to_string())),
            Json(req),
        )
        .await
        .unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        // Verify strictly 1 Kubernetes API call
        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("PATCH"));
        assert!(calls[0].contains("/namespaces/default/instances/chal-1"));
        assert!(calls[0].contains("fieldManager=cardinal-api"));
    }

    #[tokio::test]
    async fn test_get_instance_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let res = get_instance(
            State(state),
            Path(("default".to_string(), "chal-1".to_string())),
        )
        .await
        .unwrap();

        assert_eq!(res.0.name, "chal-1");
        assert_eq!(res.0.phase, "Ready");

        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("GET"));
        assert!(calls[0].contains("/namespaces/default/instances/chal-1"));
    }

    #[tokio::test]
    async fn test_restart_instance_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let status = restart_instance(
            State(state),
            Path(("default".to_string(), "chal-1".to_string())),
            Extension(VerifiedKeyId("test-key".to_string())),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::OK);

        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("PATCH"));
        assert!(calls[0].contains("/namespaces/default/instances/chal-1"));
    }

    #[tokio::test]
    async fn test_renew_instance_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let req = RenewInstanceRequest { ttl_seconds: None };

        let res = renew_instance(
            State(state),
            Path(("default".to_string(), "chal-1".to_string())),
            Extension(VerifiedKeyId("test-key".to_string())),
            Json(req),
        )
        .await
        .unwrap();

        assert_eq!(res.0.expires_at, "auto");

        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("PATCH"));
        assert!(calls[0].contains("/namespaces/default/instances/chal-1"));
    }

    #[tokio::test]
    async fn test_delete_instance_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let status = delete_instance(
            State(state),
            Path(("default".to_string(), "chal-1".to_string())),
            Extension(VerifiedKeyId("test-key".to_string())),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::NO_CONTENT);

        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("DELETE"));
        assert!(calls[0].contains("/namespaces/default/instances/chal-1"));
    }

    #[tokio::test]
    async fn test_list_instances_single_kube_call() {
        let (client, log) = recording_kube_client();
        let state = test_state(client);

        let res = list_instances(
            State(state),
            Path("default".to_string()),
            Query(ListQuery {
                label_selector: Some("cardinal.noctf.dev/instance=chal-1".to_string()),
            }),
        )
        .await
        .unwrap();

        assert_eq!(res.0.len(), 0);

        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("GET"));
        assert!(calls[0].contains("/namespaces/default/instances"));
        assert!(calls[0].contains("labelSelector="));
    }
}

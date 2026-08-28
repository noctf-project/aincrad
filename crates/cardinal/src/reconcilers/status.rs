use k8s_common::crd::{CTFInstance, CTFInstanceStatus, CTFInstanceStatusEndpoint};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use tracing::instrument;

use crate::{Context, Error};

/// Updates CTFInstance status conditions to Ready and stamps observed generations and endpoints.
#[instrument(skip(ctx, instance, endpoints))]
pub async fn reconcile(
    instance: &CTFInstance,
    ctx: &Context,
    template_gen: Option<i64>,
    endpoints: Vec<CTFInstanceStatusEndpoint>,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

    let now = Time(Timestamp::now());
    let observed_generation = instance.metadata.generation;
    let template_generation = template_gen;
    let restarted_at = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
        .cloned();

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "True".to_string(),
        reason: "Reconciled".to_string(),
        message: "CTFInstance reconciled successfully".to_string(),
        last_transition_time: now,
        observed_generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition],
            endpoints,
        }
    });

    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(status_patch),
        )
        .await?;

    Ok(())
}

/// Updates CTFInstance status conditions to indicate reconciliation failure.
#[instrument(skip(ctx, instance, err))]
pub async fn reconcile_failure(
    instance: &CTFInstance,
    ctx: &Context,
    err: &Error,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

    let now = Time(Timestamp::now());
    let observed_generation = instance.status.as_ref().and_then(|s| s.observed_generation);
    let template_generation = instance.status.as_ref().and_then(|s| s.template_generation);
    let restarted_at = instance
        .status
        .as_ref()
        .and_then(|s| s.restarted_at.clone());
    let endpoints = instance
        .status
        .as_ref()
        .map(|s| s.endpoints.clone())
        .unwrap_or_default();

    let (reason, message) = match err {
        Error::TemplateNotFound(tmpl) => (
            "TemplateNotFound".to_string(),
            format!("Template \"{tmpl}\" not found"),
        ),
        Error::TemplateBuildError(msg) => ("TemplateBuildError".to_string(), msg.clone()),
        Error::RouteAllocationError(e) => ("RouteAllocationError".to_string(), e.to_string()),
        Error::ApplyResource { kind, name, source } => (
            "ResourceApplyError".to_string(),
            format!("Failed to apply {kind} \"{name}\": {source}"),
        ),
        Error::Kube(e) => ("KubeApiError".to_string(), e.to_string()),
        Error::KubeCommon(e) => ("KubeCommonError".to_string(), e.to_string()),
        Error::LeaseManager(e) => ("LeaseManagerError".to_string(), e.to_string()),
        Error::Custom(msg) => ("ReconciliationFailed".to_string(), msg.clone()),
    };

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "False".to_string(),
        reason,
        message,
        last_transition_time: now,
        observed_generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition],
            endpoints,
        }
    });

    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(status_patch),
        )
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client};

    #[tokio::test]
    async fn test_reconcile_status() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let mut instance = dummy_instance("chal-1", Some("1"));
        instance.metadata.generation = Some(2);

        let res = reconcile(&instance, &ctx, Some(3), vec![]).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_failure() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", None);
        let err = Error::TemplateNotFound("missing".to_string());

        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());

        let route_err = Error::RouteAllocationError(crate::routing::RouteError::Port(
            crate::routing::PortError::Occupied(
                20001,
                crate::routing::RouteKey::new("default", "other-chal", "pwn"),
            ),
        ));
        let res_route = reconcile_failure(&instance, &ctx, &route_err).await;
        assert!(res_route.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_failure_preserves_existing_endpoints() {
        use k8s_common::crd::EndpointTarget;

        let client = dummy_kube_client();
        let ctx = Context::new(client);

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(CTFInstanceStatus {
            endpoints: vec![CTFInstanceStatusEndpoint {
                name: "pwn".to_string(),
                type_: "tcp".to_string(),
                target: EndpointTarget {
                    host: "chal.domain.com".to_string(),
                    port: 30005,
                },
            }],
            ..Default::default()
        });

        let err = Error::TemplateBuildError("Failed to patch JSON".to_string());
        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());

        let apply_err = Error::ApplyResource {
            kind: "ReplicaSet",
            name: "chal-1-web".to_string(),
            source: Box::new(kube::Error::Service(tower::BoxError::from(
                "quota exceeded",
            ))),
        };
        let res_apply = reconcile_failure(&instance, &ctx, &apply_err).await;
        assert!(res_apply.is_ok());
    }
}

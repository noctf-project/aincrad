use k8s_common::crd::{CTFInstance, CTFInstanceStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error,
    planners::{
        NetworkPolicyPlanner, Planner, ProxyRoutePlanner, ReplicaSetPlanner, ServicePlanner,
        apply_condition,
    },
};

/// Outcome of a status reconciliation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    NotReady,
}

/// Synchronously evaluates the instance's readiness by collecting conditions from each
/// child resource planner and the template cache. Writes all conditions to the API server.
///
/// Returns `Ready` if all conditions have status "True" and writes `Ready=True` + observed
/// generations. Returns `NotReady` otherwise, writing only the conditions without Ready.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: &CTFInstance, ctx: &Context) -> Result<Readiness, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let mut status = instance.status.clone().unwrap_or_default();
    // Clear existing conditions so we write fresh ones
    status.conditions.clear();

    let (template_condition, template_gen) = evaluate_template_condition(instance, ctx);
    apply_condition(&mut status, template_condition);
    reconcile_child_statuses(instance, &mut status, ctx)?;

    let all_true = status.conditions.iter().all(|c| c.status == "True");

    if all_true {
        status.observed_generation = instance.metadata.generation;
        status.template_generation = template_gen;
        status.restarted_at = instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
            .cloned();

        apply_condition(
            &mut status,
            Condition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                reason: "Reconciled".to_string(),
                message: "CTFInstance reconciled successfully".to_string(),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: instance.metadata.generation,
            },
        );

        let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
        instances
            .patch_status(
                name,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(serde_json::json!({ "status": &status })),
            )
            .await?;

        return Ok(Readiness::Ready);
    }

    // Don't stamp observed_generation, only set when fully Ready.
    // Patch the full status so endpoint updates from check_status are preserved.
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(serde_json::json!({ "status": &status })),
        )
        .await?;

    Ok(Readiness::NotReady)
}

/// Reconciles child resource status conditions, propagating the first failure
/// wrapped with the resource kind.
fn reconcile_child_statuses(
    instance: &CTFInstance,
    status: &mut CTFInstanceStatus,
    ctx: &Context,
) -> Result<(), Error> {
    ReplicaSetPlanner::check_status(instance, status, ctx).map_err(|e| {
        Error::StatusReconciliationError {
            kind: ReplicaSetPlanner::KIND.to_string(),
            source: Box::new(e),
        }
    })?;
    NetworkPolicyPlanner::check_status(instance, status, ctx).map_err(|e| {
        Error::StatusReconciliationError {
            kind: NetworkPolicyPlanner::KIND.to_string(),
            source: Box::new(e),
        }
    })?;
    ServicePlanner::check_status(instance, status, ctx).map_err(|e| {
        Error::StatusReconciliationError {
            kind: ServicePlanner::KIND.to_string(),
            source: Box::new(e),
        }
    })?;
    ProxyRoutePlanner::check_status(instance, status, ctx).map_err(|e| {
        Error::StatusReconciliationError {
            kind: ProxyRoutePlanner::KIND.to_string(),
            source: Box::new(e),
        }
    })?;

    Ok(())
}

/// Evaluates the "Template" condition and returns the current template generation.
fn evaluate_template_condition(instance: &CTFInstance, ctx: &Context) -> (Condition, Option<i64>) {
    let tmpl_name = &instance.spec.template;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let entry = ctx
        .template_cache
        .as_ref()
        .and_then(|cache| cache.get(ns, tmpl_name));

    let Some(cached) = entry else {
        return (
            Condition {
                type_: "Template".to_string(),
                status: "False".to_string(),
                reason: "TemplateNotFound".to_string(),
                message: format!("Template \"{tmpl_name}\" not found"),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: None,
            },
            None,
        );
    };

    let template_gen = cached.template.metadata.generation;

    // If sync is on, check that the template is not newer than this instance's
    // last observed state. The first time this instance sees a template, the number
    // of the template generation becomes the observed template generation once it
    // is reconciled, so an absent observed generation is treated as "in sync".
    if instance.spec.sync {
        let observed_tmpl_gen = instance.status.as_ref()
            .and_then(|s| s.template_generation);
        if let (Some(observed), Some(current)) = (observed_tmpl_gen, template_gen)
            && observed < current
        {
            return (
                Condition {
                    type_: "Template".to_string(),
                    status: "False".to_string(),
                    reason: "TemplateOutOfSync".to_string(),
                    message: format!(
                        "Template gen {:?} is newer than observed gen {:?}",
                        template_gen, observed_tmpl_gen
                    ),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        Timestamp::now(),
                    ),
                    observed_generation: None,
                },
                template_gen,
            );
        }
    }

    // Check that pod patchers compiled successfully
    if let Err(err) = &cached.pod_patchers {
        return (
            Condition {
                type_: "Template".to_string(),
                status: "False".to_string(),
                reason: "TemplateBuildError".to_string(),
                message: err.clone(),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: None,
            },
            template_gen,
        );
    }

    (
        Condition {
            type_: "Template".to_string(),
            status: "True".to_string(),
            reason: "TemplateResolved".to_string(),
            message: format!("Template gen {:?}", template_gen),
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Timestamp::now(),
            ),
            observed_generation: None,
        },
        template_gen,
    )
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

    let now = k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(Timestamp::now());
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
        Error::StatusReconciliationError { kind, source } => (
            "StatusReconciliationFailed".to_string(),
            format!("Status reconciliation failed for {kind}: {source}"),
        ),
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
    use crate::test_utils::tests::{
        dummy_context, dummy_context_with_routes, dummy_instance, dummy_kube_client,
    };
    use k8s_common::crd::CTFInstanceStatusEndpoint;

    #[tokio::test]
    async fn test_reconcile_status() {
        let (_store, ctx) = dummy_context();
        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);

        let res = reconcile(&instance, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_synced_instance_reaches_ready() {
        use k8s_common::crd::{CTFTemplateSpecRoute, RouteBackend, RouteSpec, RouteSpecTCP};

        let tcp_route = CTFTemplateSpecRoute {
            name: "chal".to_string(),
            spec: RouteSpec {
                backend: RouteBackend {
                    service: "web".into(),
                    port: 80,
                },
                tcp: Some(RouteSpecTCP { port: Some(0) }),
                ..Default::default()
            },
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route]);

        let mut synced = dummy_instance("chal-1", None);
        synced.spec.sync = true;
        synced.metadata.generation = Some(1);
        synced.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: None,
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });

        assert_eq!(
            reconcile(&synced, &ctx).await.unwrap(),
            Readiness::Ready,
            "synced instance at current template generation must become Ready"
        );
    }

    #[tokio::test]
    async fn test_synced_instance_returns_to_ready_after_template_bump() {
        use k8s_common::crd::{CTFTemplateSpecRoute, RouteBackend, RouteSpec, RouteSpecTCP};

        let tcp_route = CTFTemplateSpecRoute {
            name: "chal".to_string(),
            spec: RouteSpec {
                backend: RouteBackend {
                    service: "web".into(),
                    port: 80,
                },
                tcp: Some(RouteSpecTCP { port: Some(0) }),
                ..Default::default()
            },
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route.clone()]);

        let mut synced = dummy_instance("chal-1", None);
        synced.spec.sync = true;
        synced.metadata.generation = Some(1);
        synced.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });
        assert_eq!(reconcile(&synced, &ctx).await.unwrap(), Readiness::Ready);

        let bump_tmpl = k8s_common::crd::CTFTemplate {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFTemplateSpec {
                routes: vec![tcp_route],
                ..Default::default()
            },
            status: None,
        };
        ctx.template_cache.as_ref().unwrap().update(&bump_tmpl);

        let mut bumped = synced.clone();
        bumped.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });
        assert_eq!(
            reconcile(&bumped, &ctx).await.unwrap(),
            Readiness::NotReady,
            "template bump surfaces as NotReady so children get re-applied"
        );

        let mut caught_up = bumped.clone();
        caught_up.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(2),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });
        assert_eq!(
            reconcile(&caught_up, &ctx).await.unwrap(),
            Readiness::Ready,
            "after the applied template generation is recorded, the instance returns to Ready"
        );
    }

    #[tokio::test]
    async fn test_reconcile_failure() {
        let client = dummy_kube_client();
        let ctx = crate::Context::new(client);
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
        let client = dummy_kube_client();
        let ctx = crate::Context::new(client);

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(CTFInstanceStatus {
            endpoints: vec![CTFInstanceStatusEndpoint {
                name: "pwn".to_string(),
                type_: "tcp".to_string(),
                target: k8s_common::crd::EndpointTarget {
                    host: "chal.domain.com".to_string(),
                    port: 30005,
                },
            }],
            ..Default::default()
        });

        let err = Error::TemplateBuildError("Failed to patch JSON".to_string());
        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());
    }
}

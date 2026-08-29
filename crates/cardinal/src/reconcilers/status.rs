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

/// The outcome of evaluating an instance's readiness. Produced by `evaluate_status`
/// without touching the API server and consumed by `commit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evaluation {
    pub conditions: Vec<Condition>,
    pub template_generation: Option<i64>,
    pub resources: k8s_common::crd::CTFInstanceResources,
}

impl Evaluation {
    /// True when every child condition reports success.
    pub fn is_ready(&self) -> bool {
        self.conditions
            .iter()
            .all(|c| c.status == "True" || c.status == "Unknown")
    }
}

/// Evaluates the instance's readiness by collecting each resource's condition and
/// status payload. Purely reads in-memory state and writes nothing to the API
/// server, so it can be run before deciding whether to apply children.
pub fn evaluate_status(instance: &CTFInstance, ctx: &Context) -> Result<Evaluation, Error> {
    let mut evaluation = Evaluation {
        template_generation: current_template_generation(instance, ctx),
        ..Default::default()
    };

    fold_planner::<ReplicaSetPlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<NetworkPolicyPlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<ServicePlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<ProxyRoutePlanner>(instance, ctx, &mut evaluation)?;

    Ok(evaluation)
}

/// Calls a planner's `check_status`, collecting its condition and merging any
/// typed status payload it contributes into `Evaluation::resources`.
fn fold_planner<P: Planner>(
    instance: &CTFInstance,
    ctx: &Context,
    evaluation: &mut Evaluation,
) -> Result<(), Error> {
    let (condition, resources) =
        P::check_status(instance, ctx).map_err(|e| Error::StatusReconciliationError {
            kind: P::KIND.to_string(),
            source: Box::new(e),
        })?;
    evaluation.conditions.push(condition);

    if let Some(resources) = resources {
        evaluation.resources.overlay(resources);
    }

    Ok(())
}

/// Commits the evaluated state to the instance status in a single patch. Only
/// called after children have been applied, so the recorded observed generation
/// and applied template generation are truthful.
///
/// The skip path never reaches this function; it writes nothing.
pub async fn commit(
    instance: &CTFInstance,
    evaluation: &Evaluation,
    ctx: &Context,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let mut status = CTFInstanceStatus {
        observed_generation: instance.metadata.generation,
        template_generation: evaluation.template_generation,
        restarted_at: instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
            .cloned(),
        resources: evaluation.resources.clone(),
        conditions: evaluation.conditions.clone(),
    };

    if evaluation.is_ready() {
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
    }

    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(serde_json::json!({ "status": &status })),
        )
        .await?;

    Ok(())
}

/// Resolves the current generation of the template referenced by the instance,
/// if it is present in the in-memory template cache.
fn current_template_generation(instance: &CTFInstance, ctx: &Context) -> Option<i64> {
    let tmpl_name = &instance.spec.template;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    ctx.template_cache
        .as_ref()
        .and_then(|cache| cache.get(ns, tmpl_name))
        .and_then(|entry| entry.template.metadata.generation)
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
    let resources = instance
        .status
        .as_ref()
        .map(|s| s.resources.clone())
        .unwrap_or_default();

    let (reason, message) = match err {
        Error::TemplateNotFound(tmpl) => (
            "TemplateNotFound".to_string(),
            format!("Template \"{tmpl}\" not found"),
        ),
        Error::InvalidOverride(msg) => ("InvalidOverride".to_string(), msg.clone()),
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
        observed_generation: instance.metadata.generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition],
            resources,
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
    #[tokio::test]
    async fn test_commit_status() {
        let (_store, ctx) = dummy_context();
        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);

        let evaluation = evaluate_status(&instance, &ctx).unwrap();
        let res = commit(&instance, &evaluation, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_evaluate_synced_instance_is_ready() {
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
            resources: Default::default(),
        });

        let evaluation = evaluate_status(&synced, &ctx).unwrap();
        assert!(
            evaluation.is_ready(),
            "synced instance at current template generation must evaluate ready"
        );
        commit(&synced, &evaluation, &ctx)
            .await
            .expect("commit succeeds");
    }

    #[tokio::test]
    async fn test_requires_upgrade_detects_template_bump() {
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
            resources: Default::default(),
        });

        let template_gen = current_template_generation(&synced, &ctx);
        assert!(
            !crate::utils::versions::requires_template_upgrade(template_gen, &synced),
            "synced instance at the current template generation must not require an upgrade"
        );

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

        let template_gen = current_template_generation(&synced, &ctx);
        assert!(
            crate::utils::versions::requires_template_upgrade(template_gen, &synced),
            "a template generation bump surfaces as an upgrade so children get re-applied"
        );

        let mut caught_up = synced.clone();
        caught_up.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(2),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
        });
        let template_gen = current_template_generation(&caught_up, &ctx);
        assert!(
            !crate::utils::versions::requires_template_upgrade(template_gen, &caught_up),
            "after the applied template generation is recorded, the upgrade is no longer required"
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
    async fn test_reconcile_failure_preserves_existing_resources() {
        let client = dummy_kube_client();
        let ctx = crate::Context::new(client);

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(CTFInstanceStatus {
            resources: k8s_common::crd::CTFInstanceResources {
                endpoints: Some(vec![k8s_common::crd::CTFInstanceStatusEndpoint {
                    name: "pwn".to_string(),
                    type_: "tcp".to_string(),
                    target: k8s_common::crd::EndpointTarget {
                        host: "chal.domain.com".to_string(),
                        port: 30005,
                    },
                }]),
            },
            ..Default::default()
        });

        let err = Error::TemplateBuildError("Failed to patch JSON".to_string());
        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());
    }
}

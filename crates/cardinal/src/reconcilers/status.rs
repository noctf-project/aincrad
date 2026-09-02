use std::collections::BTreeMap;

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
    pub children: BTreeMap<String, Vec<String>>,
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

    if let Some(names) = P::cached_names(instance, ctx) {
        evaluation.children.insert(P::KIND.to_string(), names);
    }

    Ok(())
}

/// Returns true when the instance's status has observed the current spec
/// generation and restart annotation.
pub fn is_observed(instance: &CTFInstance) -> bool {
    match (
        instance.status.as_ref().and_then(|s| s.observed_generation),
        instance.metadata.generation,
    ) {
        (Some(observed), Some(current)) if observed < current => return false,
        (None, Some(_)) => return false,
        _ => {}
    }

    let status_restarted_at = instance
        .status
        .as_ref()
        .and_then(|s| s.restarted_at.as_deref());
    let annotation_restarted_at = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
        .map(|s| s.as_str());

    status_restarted_at == annotation_restarted_at
}

/// Commits the evaluated state to the instance status in a single patch. Only
/// called after children have been applied, so the recorded observed generation
/// and applied template generation are truthful.
pub async fn commit(
    instance: &CTFInstance,
    evaluation: &Evaluation,
    ctx: &Context,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    // Preserve existing children if already observed to avoid shrinking expected child list on child deletions
    let children = if is_observed(instance)
        && let Some(existing) = instance.status.as_ref().map(|s| &s.children)
        && !existing.is_empty()
    {
        let mut merged = existing.clone();
        for (kind, names) in &evaluation.children {
            if !names.is_empty() {
                merged.insert(kind.clone(), names.clone());
            }
        }
        merged
    } else {
        evaluation.children.clone()
    };

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
        children,
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

    if let Some(existing) = instance.status.as_ref() {
        let conditions_unchanged = existing.conditions.len() == status.conditions.len()
            && status.conditions.iter().all(|c| {
                existing.conditions.iter().any(|old| {
                    old.type_ == c.type_
                        && old.status == c.status
                        && old.reason == c.reason
                        && old.message == c.message
                })
            });

        if conditions_unchanged
            && existing.observed_generation == status.observed_generation
            && existing.template_generation == status.template_generation
            && existing.restarted_at == status.restarted_at
            && existing.resources == status.resources
            && existing.children == status.children
        {
            return Ok(());
        }

        // Preserve last_transition_time for conditions that did not transition
        for condition in &mut status.conditions {
            if let Some(old) = existing
                .conditions
                .iter()
                .find(|c| c.type_ == condition.type_)
                && old.status == condition.status
                && old.reason == condition.reason
                && old.message == condition.message
            {
                condition.last_transition_time = old.last_transition_time.clone();
            }
        }
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

    ctx.caches
        .templates
        .get(ns, tmpl_name)
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
            ..Default::default()
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
    use crate::{
        cache::ResourceKey,
        test_utils::tests::{
            dummy_context, dummy_context_with_routes, dummy_instance, dummy_kube_client,
        },
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
    async fn test_commit_updates_endpoints_then_skips_when_unchanged() {
        use crate::test_utils::tests::recording_kube_client;
        use k8s_common::crd::{CTFInstanceStatusEndpoint, EndpointTarget};

        let (client, log) = recording_kube_client();
        let (_store, ctx) = crate::test_utils::tests::dummy_ctx(client, vec![]);
        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);

        // Pass 1: initial status with no endpoints
        let evaluation_1 = evaluate_status(&instance, &ctx).unwrap();
        commit(&instance, &evaluation_1, &ctx).await.unwrap();
        let patch_count_1 = log
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains("PATCH"))
            .count();
        assert_eq!(patch_count_1, 1, "pass 1 must issue a patch");

        // Simulate Pass 1 committed status on instance
        instance.status = Some(CTFInstanceStatus {
            observed_generation: instance.metadata.generation,
            template_generation: evaluation_1.template_generation,
            restarted_at: None,
            resources: evaluation_1.resources.clone(),
            children: evaluation_1.children.clone(),
            conditions: evaluation_1.conditions.clone(),
        });

        // Pass 2: evaluation now discovers an endpoint
        let mut evaluation_2 = evaluation_1.clone();
        evaluation_2.resources.endpoints = Some(vec![CTFInstanceStatusEndpoint {
            name: "chal".to_string(),
            type_: "tcp".to_string(),
            target: EndpointTarget {
                host: "chal.domain.com".to_string(),
                port: 30005,
            },
        }]);
        evaluation_2
            .children
            .insert("CTFProxyRoute".to_string(), vec!["p30005".to_string()]);

        commit(&instance, &evaluation_2, &ctx).await.unwrap();
        let patch_count_2 = log
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains("PATCH"))
            .count();
        assert_eq!(
            patch_count_2, 2,
            "pass 2 must issue a patch because endpoints appeared"
        );

        // Simulate Pass 2 committed status on instance
        instance.status = Some(CTFInstanceStatus {
            observed_generation: instance.metadata.generation,
            template_generation: evaluation_2.template_generation,
            restarted_at: None,
            resources: evaluation_2.resources.clone(),
            children: evaluation_2.children.clone(),
            conditions: evaluation_2.conditions.clone(),
        });

        // Pass 3: identical status evaluation
        commit(&instance, &evaluation_2, &ctx).await.unwrap();
        let patch_count_3 = log
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains("PATCH"))
            .count();
        assert_eq!(
            patch_count_3, 2,
            "pass 3 must skip patch because status is identical"
        );
    }

    #[tokio::test]
    async fn test_evaluate_synced_instance_is_ready() {
        use k8s_common::crd::{RouteBackend, RouteSpec, RouteSpecTCP};

        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route]);

        let mut rs = k8s_openapi::api::apps::v1::ReplicaSet::default();
        rs.metadata.name = Some("chal-1-web".to_string());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs.status = Some(k8s_openapi::api::apps::v1::ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches
            .replica_sets
            .handle(&kube::runtime::watcher::Event::Apply(rs));

        let mut pr = k8s_common::crd::CTFProxyRoute::new("p30005", Default::default());
        pr.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "chal",
        });
        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(pr));

        let mut synced = dummy_instance("chal-1", None);
        synced.spec.sync = true;
        synced.metadata.generation = Some(1);
        synced.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: None,
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });

        let resolved = crate::reconcilers::template::reconcile(&synced, &ctx)
            .await
            .unwrap();
        let _ = ProxyRoutePlanner::plan(&synced, &resolved, &ctx).unwrap();

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
        use k8s_common::crd::{RouteBackend, RouteSpec, RouteSpecTCP};

        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
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
            ..Default::default()
        });

        let template_meta = ctx
            .caches
            .templates
            .get("default", "whoami-template")
            .unwrap()
            .template
            .metadata
            .clone();
        assert!(
            !crate::utils::versions::requires_template_upgrade(&template_meta, &synced),
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
        ctx.caches.templates.update(&bump_tmpl);

        let template_meta = ctx
            .caches
            .templates
            .get("default", "whoami-template")
            .unwrap()
            .template
            .metadata
            .clone();
        assert!(
            crate::utils::versions::requires_template_upgrade(&template_meta, &synced),
            "a template generation bump surfaces as an upgrade so children get re-applied"
        );

        let mut caught_up = synced.clone();
        caught_up.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(2),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });
        assert!(
            !crate::utils::versions::requires_template_upgrade(&template_meta, &caught_up),
            "after the applied template generation is recorded, the upgrade is no longer required"
        );
    }

    #[tokio::test]
    async fn test_reconcile_failure() {
        let client = dummy_kube_client();
        let ctx = crate::Context::new_stub(client);
        let instance = dummy_instance("chal-1", None);
        let err = Error::TemplateNotFound("missing".to_string());

        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());

        let route_err = Error::RouteAllocationError(crate::routing::RouteError::Port(
            crate::routing::PortError::Occupied(
                20001,
                ResourceKey::new("default", "other-chal", "pwn"),
            ),
        ));
        let res_route = reconcile_failure(&instance, &ctx, &route_err).await;
        assert!(res_route.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_failure_preserves_existing_resources() {
        let client = dummy_kube_client();
        let ctx = Context::new_stub(client);

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

    #[tokio::test]
    async fn test_evaluate_status_populates_children() {
        use k8s_openapi::api::apps::v1::{ReplicaSet, ReplicaSetStatus};
        use k8s_openapi::api::core::v1::Service;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);

        // Seed ReplicaSet
        let mut rs = ReplicaSet::default();
        rs.metadata.name = Some("chal-1-web".to_string());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs.status = Some(ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs));

        // Seed Service
        let mut svc = Service::default();
        svc.metadata.name = Some("chal-1-web".to_string());
        svc.metadata.namespace = Some("default".to_string());
        svc.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        ctx.caches.services.handle(&Event::Apply(svc));

        let evaluation = evaluate_status(&instance, &ctx).unwrap();
        assert_eq!(
            evaluation.children.get("ReplicaSet"),
            Some(&vec!["chal-1-web".to_string()])
        );
        assert_eq!(
            evaluation.children.get("Service"),
            Some(&vec!["chal-1-web".to_string()])
        );
    }
}

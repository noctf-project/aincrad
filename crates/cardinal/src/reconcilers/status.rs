use std::collections::BTreeMap;

use k8s_common::{
    crd::{EndpointTarget, Instance, InstanceStatus, InstanceStatusEndpoint, RouteTarget},
    labels::RESTARTED_AT_ANNOTATION,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error,
    cache::ResourceKey,
    planners::{
        NetworkPolicyPlanner, Planner, ReplicaSetPlanner, ServicePlanner, TLSRoutePlanner,
        apply_condition, build_merged_route_spec,
    },
    reconcilers::template::ResolvedTemplate,
    routing::{default_tls_prefix, derive_hostname, format_tls_host},
};

/// The outcome of evaluating an instance's readiness. Produced by `evaluate_status`
/// without touching the API server and consumed by `commit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evaluation {
    pub conditions: Vec<Condition>,
    pub template_generation: Option<i64>,
    pub resources: k8s_common::crd::InstanceResources,
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
pub fn evaluate_status(instance: &Instance, ctx: &Context) -> Result<Evaluation, Error> {
    let mut evaluation = Evaluation {
        template_generation: current_template_generation(instance, ctx),
        ..Default::default()
    };

    fold_planner::<ReplicaSetPlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<NetworkPolicyPlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<ServicePlanner>(instance, ctx, &mut evaluation)?;
    fold_planner::<TLSRoutePlanner>(instance, ctx, &mut evaluation)?;

    Ok(evaluation)
}

/// Calls a planner's `check_status`, collecting its condition and merging any
/// typed status payload it contributes into `Evaluation::resources`.
fn fold_planner<P: Planner>(
    instance: &Instance,
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

/// Generates the endpoints for a Instance from route specs and active port allocations.
pub fn generate_endpoints(
    instance: &Instance,
    template: &ResolvedTemplate,
    ctx: &Context,
) -> Vec<InstanceStatusEndpoint> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let mut endpoints = Vec::new();

    for route_tmpl in &template.spec.routes {
        let route_override = instance
            .spec
            .routes
            .iter()
            .find(|r| r.name == route_tmpl.name);
        let merged_spec = build_merged_route_spec(route_tmpl, route_override);

        match merged_spec.target() {
            Some(RouteTarget::Port(port_opt, proto)) => {
                let port = if let Some(p) = port_opt
                    && p != 0
                {
                    p
                } else if let Some(port_map) = ctx.port_map.as_deref() {
                    let key = ResourceKey::new(ns, name, &route_tmpl.name);
                    port_map.get_port(&key).map(|p| p.number()).unwrap_or(0)
                } else {
                    0
                };

                if port != 0 {
                    let host = ctx.hostname_suffix().to_string();
                    endpoints.push(InstanceStatusEndpoint {
                        name: route_tmpl.name.clone(),
                        type_: proto.as_str().to_lowercase(),
                        target: EndpointTarget { host, port },
                    });
                }
            }
            Some(RouteTarget::Tls(tls)) => {
                let route_key = ResourceKey::new(ns, name, &route_tmpl.name);
                let template_name = template.metadata.name.as_deref().unwrap_or("unknown");
                let default_prefix = default_tls_prefix(template_name, &route_tmpl.name);
                let prefix = tls.prefix.as_deref().unwrap_or(&default_prefix);
                let hostname = derive_hostname(ctx.route_seed(), &route_key, Some(prefix));
                let fqdn = format_tls_host(ctx.hostname_suffix(), &hostname);
                endpoints.push(InstanceStatusEndpoint {
                    name: route_tmpl.name.clone(),
                    type_: "tls".to_string(),
                    target: EndpointTarget {
                        host: fqdn,
                        port: ctx.tls_port(),
                    },
                });
            }
            None => {}
        }
    }

    endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
    endpoints
}

/// Returns true when the instance's status has observed the current spec
/// generation and restart annotation.
pub fn is_observed(instance: &Instance) -> bool {
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
        .and_then(|a| a.get(RESTARTED_AT_ANNOTATION))
        .map(|s| s.as_str());

    status_restarted_at == annotation_restarted_at
}

/// Commits the evaluated state to the instance status in a single patch. Only
/// called after children have been applied, so the recorded observed generation
/// and applied template generation are truthful.
pub async fn commit(
    instance: &Instance,
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

    let mut status = InstanceStatus {
        observed_generation: instance.metadata.generation,
        template_generation: evaluation.template_generation,
        restarted_at: instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(RESTARTED_AT_ANNOTATION))
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
                message: "Instance reconciled successfully".to_string(),
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

    let instances: Api<Instance> = Api::namespaced(ctx.client.clone(), ns);
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
fn current_template_generation(instance: &Instance, ctx: &Context) -> Option<i64> {
    let tmpl_name = &instance.spec.template;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    ctx.caches
        .templates
        .get(ns, tmpl_name)
        .and_then(|entry| entry.template.metadata.generation)
}

/// Updates Instance status conditions to indicate reconciliation failure.
#[instrument(skip(ctx, instance, err))]
pub async fn reconcile_failure(
    instance: &Instance,
    ctx: &Context,
    err: &Error,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<Instance> = Api::namespaced(ctx.client.clone(), ns);

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
    let children = instance
        .status
        .as_ref()
        .map(|s| s.children.clone())
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
        "status": InstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition],
            resources,
            children,
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
    use k8s_common::labels::{INSTANCE_LABEL, NAMESPACE_LABEL, RESOURCE_LABEL};

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
        use k8s_common::crd::{EndpointTarget, InstanceStatusEndpoint};

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
        instance.status = Some(InstanceStatus {
            observed_generation: instance.metadata.generation,
            template_generation: evaluation_1.template_generation,
            restarted_at: None,
            resources: evaluation_1.resources.clone(),
            children: evaluation_1.children.clone(),
            conditions: evaluation_1.conditions.clone(),
        });

        // Pass 2: evaluation now discovers an endpoint
        let mut evaluation_2 = evaluation_1.clone();
        evaluation_2.resources.endpoints = Some(vec![InstanceStatusEndpoint {
            name: "chal".to_string(),
            type_: "tcp".to_string(),
            target: EndpointTarget {
                host: "chal.domain.com".to_string(),
                port: 30005,
            },
        }]);
        evaluation_2
            .children
            .insert("Service".to_string(), vec!["chal-tcp".to_string()]);

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
        instance.status = Some(InstanceStatus {
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
        use k8s_common::crd::{RouteBackend, RouteSpec};

        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
                protocol: None,
            },
            port: Some(0),
            ..Default::default()
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route]);

        let mut rs = k8s_openapi::api::apps::v1::ReplicaSet::default();
        rs.metadata.name = Some("chal-1-web".to_string());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            NAMESPACE_LABEL => "default",
            INSTANCE_LABEL => "chal-1",
            RESOURCE_LABEL => "web",
        });
        rs.status = Some(k8s_openapi::api::apps::v1::ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches
            .replica_sets
            .handle(&kube::runtime::watcher::Event::Apply(rs));

        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);
        instance.status = Some(InstanceStatus {
            observed_generation: Some(1),
            template_generation: None,
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });

        let _resolved = crate::reconcilers::template::reconcile(&instance, &ctx)
            .await
            .unwrap();

        let evaluation = evaluate_status(&instance, &ctx).unwrap();
        assert!(
            evaluation.is_ready(),
            "instance at current template generation must evaluate ready"
        );
        commit(&instance, &evaluation, &ctx)
            .await
            .expect("commit succeeds");
    }

    #[tokio::test]
    async fn test_requires_upgrade_detects_template_bump() {
        use k8s_common::crd::{RouteBackend, RouteSpec};

        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
                protocol: None,
            },
            port: Some(0),
            ..Default::default()
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route.clone()]);

        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);
        instance.status = Some(InstanceStatus {
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
            !crate::utils::versions::requires_template_upgrade(&template_meta, &instance),
            "instance without floor must not require an upgrade"
        );

        let bump_tmpl = k8s_common::crd::Template {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(2),
                annotations: Some(
                    [(
                        k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                        "2".to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            spec: k8s_common::crd::TemplateSpec {
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
            crate::utils::versions::requires_template_upgrade(&template_meta, &instance),
            "a template minTemplateGeneration floor surfaces as an upgrade so children get re-applied"
        );

        let mut caught_up = instance.clone();
        caught_up.status = Some(InstanceStatus {
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
                crate::routing::Port::Tcp(20001),
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
        instance.status = Some(InstanceStatus {
            resources: k8s_common::crd::InstanceResources {
                endpoints: Some(vec![k8s_common::crd::InstanceStatusEndpoint {
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
            NAMESPACE_LABEL => "default",
            INSTANCE_LABEL => "chal-1",
            RESOURCE_LABEL => "web",
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
            NAMESPACE_LABEL => "default",
            INSTANCE_LABEL => "chal-1",
            RESOURCE_LABEL => "web",
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

    #[tokio::test]
    async fn test_generate_endpoints() {
        use crate::test_utils::tests::dummy_resolved_template;
        use k8s_common::crd::{RouteBackend, RouteSpec, RouteSpecTLS};

        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);

        template.spec.routes = vec![
            RouteSpec {
                name: "web".to_string(),
                backend: RouteBackend {
                    service: "web".to_string(),
                    port: 80,
                    protocol: None,
                },
                tls: Some(RouteSpecTLS {
                    prefix: Some("whoami".to_string()),
                }),
                port: None,
            },
            RouteSpec {
                name: "pwn".to_string(),
                backend: RouteBackend {
                    service: "web".to_string(),
                    port: 1337,
                    protocol: None,
                },
                tls: None,
                port: Some(0),
            },
        ];

        let key = ResourceKey::new("default", "chal-1", "pwn");
        ctx.port_map
            .as_ref()
            .unwrap()
            .bind(crate::routing::Port::Tcp(30005), key);

        let endpoints = generate_endpoints(&instance, &template, &ctx);
        assert_eq!(endpoints.len(), 2);

        assert_eq!(endpoints[0].name, "pwn");
        assert_eq!(endpoints[0].type_, "tcp");
        assert_eq!(endpoints[0].target.port, 30005);
        assert_eq!(endpoints[0].target.host, "c.noctf.dev");

        assert_eq!(endpoints[1].name, "web");
        assert_eq!(endpoints[1].type_, "tls");
        assert_eq!(endpoints[1].target.port, 4433);
        assert!(endpoints[1].target.host.contains("whoami"));
    }
}

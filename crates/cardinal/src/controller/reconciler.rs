use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_common::crd::{CTFInstance, CTFRoute, CTFTemplate};
use kube::{
    Api, Client,
    runtime::{
        Predicate, WatchStreamExt,
        controller::{Action, Controller},
        predicates,
        reflector::{ObjectRef, reflector, store},
        watcher::{Config, Event, watcher},
    },
};
use tracing::{error, info, instrument, warn};

use crate::{
    Context, Error, reconcilers,
    utils::ttl::{calculate_remaining_ttl, is_expired, parse_expires_at},
};

const EXPIRES_REQUEUE_BUFFER: Duration = Duration::from_secs(5);

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    match reconcile_inner(&instance, &ctx).await {
        Ok(action) => Ok(action),
        Err(err) => {
            let _ = reconcilers::status::reconcile_failure(&instance, &ctx, &err).await;
            Err(err)
        }
    }
}

async fn reconcile_inner(instance: &CTFInstance, ctx: &Context) -> Result<Action, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    info!(name, ns, "Reconciling CTFInstance");

    // Skip reconciliation if instance is marked for deletion
    if instance.metadata.deletion_timestamp.is_some() {
        info!(
            name,
            ns, "CTFInstance marked for deletion, skipping reconciliation"
        );
        return Ok(Action::await_change());
    }

    let expires_at = parse_expires_at(instance);

    // Check if instance has expired
    if is_expired(expires_at) {
        info!(name, ns, "CTFInstance has expired, deleting resource...");
        let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
        instances.delete(name, &Default::default()).await?;
        return Ok(Action::await_change());
    }

    // Check if instance generation and restartedAt annotation have already been observed
    let observed_gen = instance.status.as_ref().and_then(|s| s.observed_generation);
    let observed_tmpl_gen = instance.status.as_ref().and_then(|s| s.template_generation);
    let observed_restarted_at = instance
        .status
        .as_ref()
        .and_then(|s| s.restarted_at.as_deref());
    let instance_restarted_at = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
        .map(|s| s.as_str())
        .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok());

    let is_instance_gen_current = instance.metadata.generation.is_some()
        && instance.metadata.generation == observed_gen
        && instance_restarted_at == observed_restarted_at;

    let raw_min_tmpl_gen = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION));

    // Fast-path skip: if instance spec generation is current, restartedAt matches,
    // minTemplateGeneration is not set, sync is false, and instance has already been deployed.
    if is_instance_gen_current
        && raw_min_tmpl_gen.is_none()
        && !instance.spec.sync
        && observed_tmpl_gen.is_some()
    {
        let _ = reconcilers::status::reconcile_child_status(instance, ctx).await?;
        info!(
            name,
            ns, "CTFInstance already reconciled and not synced, skipping template resolution"
        );
        if let Some(remaining) = calculate_remaining_ttl(expires_at) {
            return Ok(Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER));
        }
        return Ok(Action::await_change());
    }

    // Resolve CTFTemplate referenced by `instance.spec.template`.
    let template = reconcilers::template::reconcile(instance, ctx).await?;

    // Rewrite invalid minTemplateGeneration annotation (non-numeric or <= 0)
    let min_tmpl_gen_annotation = match raw_min_tmpl_gen {
        Some(raw_val) => match raw_val.parse::<i64>() {
            Ok(parsed_gen) if parsed_gen > 0 => Some(parsed_gen),
            _ => {
                let valid_gen = template.metadata.generation.unwrap_or(1);
                info!(
                    name,
                    ns, raw_val, valid_gen, "Rewriting invalid minTemplateGeneration annotation"
                );
                return patch_min_template_annotation(ctx, name, ns, valid_gen).await;
            }
        },
        None => None,
    };

    // Check if requested minTemplateGeneration annotation exceeds the template's current generation
    if let (Some(req_gen), Some(tmpl_gen)) = (min_tmpl_gen_annotation, template.metadata.generation)
        && req_gen > tmpl_gen
    {
        info!(
            name,
            ns, req_gen, tmpl_gen, "Capping minTemplateGeneration annotation"
        );
        return patch_min_template_annotation(ctx, name, ns, tmpl_gen).await;
    }

    let target_tmpl_gen = min_tmpl_gen_annotation.or({
        if instance.spec.sync {
            template.metadata.generation
        } else {
            None
        }
    });

    let is_tmpl_gen_satisfied = observed_tmpl_gen >= target_tmpl_gen;

    if is_instance_gen_current && is_tmpl_gen_satisfied {
        let _ = reconcilers::status::reconcile_child_status(instance, ctx).await?;
        info!(name, ns, "CTFInstance already reconciled, skipping");
        if let Some(remaining) = calculate_remaining_ttl(expires_at) {
            return Ok(Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER));
        }
        return Ok(Action::await_change());
    }

    reconcile_children(instance, &template, ctx).await?;

    // Success! Update status conditions (Ready = True, RoutesReady) & observed generations
    reconcilers::status::reconcile(instance, ctx, template.metadata.generation).await?;

    if let Some(remaining) = calculate_remaining_ttl(expires_at) {
        // We want to make sure the object really expires to save requeuing
        return Ok(Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER));
    }

    Ok(Action::await_change())
}

/// Helper function to patch minTemplateGeneration annotation on a CTFInstance and requeue reconciliation.
async fn patch_min_template_annotation(
    ctx: &Context,
    name: &str,
    ns: &str,
    target_gen: i64,
) -> Result<Action, Error> {
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION: target_gen.to_string()
            }
        }
    });
    instances
        .patch(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(patch),
        )
        .await?;
    Ok(Action::requeue(Duration::from_millis(100)))
}

/// Reconciles all child resources (workloads, network policies, services, routes) for a CTFInstance.
async fn reconcile_children(
    instance: &CTFInstance,
    template: &reconcilers::template::ResolvedTemplate,
    ctx: &Context,
) -> Result<(), Error> {
    use crate::planners::{NetworkPolicyPlanner, ReplicaSetPlanner, RoutePlanner, ServicePlanner};
    use crate::reconcilers::helper::apply_planner;

    apply_planner::<ReplicaSetPlanner>(ctx.client.clone(), instance, template).await?;
    apply_planner::<NetworkPolicyPlanner>(ctx.client.clone(), instance, template).await?;
    apply_planner::<ServicePlanner>(ctx.client.clone(), instance, template).await?;
    apply_planner::<RoutePlanner>(ctx.client.clone(), instance, template).await?;
    Ok(())
}

/// Error policy handler invoked when reconciliation returns an error.
pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    error!(name, %error, "Reconciliation failed");

    match error {
        Error::TemplateBuildError(_) | Error::TemplateNotFound(_) | Error::KubeCommon(_) => {
            Action::await_change()
        }
        Error::Kube(e) => match e {
            kube::Error::Api(status) if status.code == 409 => {
                Action::requeue(Duration::from_millis(200))
            }
            kube::Error::HyperError(_) | kube::Error::HttpError(_) => {
                Action::requeue(Duration::from_secs(2))
            }
            kube::Error::Api(status) if status.code == 429 || status.code >= 500 => {
                Action::requeue(Duration::from_secs(10))
            }
            // Other API errors (400, 403, 422) require manifest or permission fixes
            kube::Error::Api(_) => Action::await_change(),
            _ => Action::requeue(Duration::from_secs(30)),
        },
        _ => Action::requeue(Duration::from_secs(60)),
    }
}

/// Maps a `CTFTemplate` update event to a vector of `ObjectRef<CTFInstance>` for all instances
/// in the same namespace referencing the template that have `spec.sync == true`.
pub fn find_synced_instances(
    template: &CTFTemplate,
    instances: &[Arc<CTFInstance>],
) -> Vec<ObjectRef<CTFInstance>> {
    let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
    let tmpl_ns = template.metadata.namespace.as_deref().unwrap_or("default");

    instances
        .iter()
        .filter(|inst| {
            let inst_ns = inst.metadata.namespace.as_deref().unwrap_or("default");
            inst_ns == tmpl_ns && inst.spec.template == tmpl_name && inst.spec.sync
        })
        .map(|inst| ObjectRef::from_obj(&**inst))
        .collect()
}

/// Maps a `CTFRoute` update event to the owning `CTFInstance` ObjectRef.
pub fn find_instance_for_route(route: &CTFRoute) -> Option<ObjectRef<CTFInstance>> {
    let ns = route.metadata.namespace.as_deref().unwrap_or("default");

    if let Some(instance_name) = route
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(crate::utils::labels::INSTANCE_LABEL))
    {
        return Some(ObjectRef::new(instance_name).within(ns));
    }

    if let Some(owner) = route
        .metadata
        .owner_references
        .as_ref()
        .and_then(|refs| refs.iter().find(|r| r.kind == "CTFInstance"))
    {
        return Some(ObjectRef::new(&owner.name).within(ns));
    }

    None
}

/// Handles watcher events for `CTFInstance` to update or clear the in-memory index.
pub fn handle_instance_watcher_event(
    event: &Event<CTFInstance>,
    cache: &crate::cache::InstanceCache,
) {
    match event {
        Event::Apply(inst) | Event::InitApply(inst) => {
            cache.update(inst);
        }
        Event::Delete(inst) => {
            cache.remove(inst);
        }
        Event::Init => {
            cache.clear();
            info!("Cleared instance index on watcher init");
        }
        Event::InitDone => {}
    }
}

/// Handles watcher events for `CTFTemplate` to update or clear the in-memory cache.
pub fn handle_template_watcher_event(
    event: &Event<CTFTemplate>,
    cache: &crate::cache::TemplateCache,
) {
    match event {
        Event::Apply(t) | Event::InitApply(t) => {
            cache.update(t);
        }
        Event::Delete(t) => {
            cache.remove(t);
        }
        Event::Init => {
            cache.clear();
            info!("Cleared CTFTemplate cache on watcher init");
        }
        Event::InitDone => {}
    }
}

/// Handles watcher events for `CTFRoute` to update or clear the in-memory index.
pub fn handle_route_watcher_event(event: &Event<CTFRoute>, cache: &crate::cache::RouteCache) {
    match event {
        Event::Apply(r) | Event::InitApply(r) => {
            cache.update(r);
        }
        Event::Delete(r) => {
            cache.remove(r);
        }
        Event::Init => {
            cache.clear();
            info!("Cleared CTFRoute index on watcher init");
        }
        Event::InitDone => {}
    }
}

/// Spawns and runs the `CTFInstance` controller loop.
pub async fn run(client: Client) {
    let instances = Api::<CTFInstance>::all(client.clone());
    let templates = Api::<CTFTemplate>::all(client.clone());
    let routes = Api::<CTFRoute>::all(client.clone());

    // Initialize in-memory CTFTemplate reflector store cache
    let (template_store, template_writer) = store();

    // Initialize in-memory CTFRoute reflector store cache
    let (route_store, route_writer) = store();

    let context = Arc::new(Context::with_stores(client, template_store, route_store));
    let template_cache = context.template_cache.clone().unwrap();
    let template_cache_task = template_cache.clone();

    let route_cache = context.route_cache.clone().unwrap();
    let route_cache_task = route_cache.clone();

    // Template watch stream updates template cache before populating the template store
    let template_watcher_stream = watcher(templates.clone(), Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_template_watcher_event(event, &template_cache_task);
            }
        });

    let template_reflector = reflector(template_writer, template_watcher_stream);
    let template_stream = template_reflector
        .touched_objects()
        .predicate_filter(predicates::generation, Default::default());

    // CTFRoute watch stream updates route cache index before populating the reflector store
    let route_watcher_stream = watcher(routes.clone(), Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_route_watcher_event(event, &route_cache_task);
            }
        });
    let route_reflector = reflector(route_writer, route_watcher_stream);
    let route_stream = route_reflector.touched_objects();

    // Initialize in-memory CTFInstance reflector store cache for watches mapping
    let (instance_store, instance_writer) = store();

    use crate::cache::InstanceCache;
    let instance_cache = InstanceCache::new(instance_store.clone());
    let instance_cache_task = instance_cache.clone();

    // Instance watch stream updates custom index before populating the reflector store
    let instance_watcher_stream = watcher(instances, Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_instance_watcher_event(event, &instance_cache_task);
            }
        });

    let instance_reflector = reflector(instance_writer, instance_watcher_stream);
    let predicate = predicates::generation.combine(predicates::annotations);
    let controller_instance_stream = instance_reflector
        .touched_objects()
        .predicate_filter(predicate, Default::default());

    info!("Starting CTFInstance controller with template & route caching");

    Controller::for_stream(controller_instance_stream, instance_store)
        .watches_stream(template_stream, move |template| {
            let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
            info!(
                template_name = tmpl_name,
                "CTFTemplate updated, evaluating synced CTFInstances to retrigger"
            );
            instance_cache.find_synced_instances(&template)
        })
        .watches_stream(route_stream, |route| find_instance_for_route(&route))
        .run(reconcile, error_policy, context)
        .for_each(|res| async {
            match res {
                Ok((object, _action)) => {
                    info!(name = %object.name, "Successfully reconciled CTFInstance");
                }
                Err(err) => {
                    warn!(%err, "Controller error occurred");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::InstanceCache;
    use crate::test_utils::tests::dummy_kube_client;
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::crd::CTFInstanceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn dummy_test_context() -> Arc<Context> {
        let client = dummy_kube_client();
        let (template_store, _) = kube::runtime::reflector::store();
        let (route_store, _) = kube::runtime::reflector::store();
        let ctx = Context::with_stores(client, template_store, route_store);

        let tmpl = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFTemplateSpec {
                pods: vec![k8s_common::crd::CTFTemplateSpecPod {
                    name: "web".into(),
                    allow_internet: false,
                    replicas: 1,
                    patch: None,
                    spec: k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "web".into(),
                            image: Some("nginx:latest".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                }],
                ..Default::default()
            },
            status: None,
        };
        if let Some(cache) = &ctx.template_cache {
            cache.update(&tmpl);
        }
        Arc::new(ctx)
    }

    #[tokio::test]
    async fn test_reconcile_no_expiration() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_future_expiration() {
        let ctx = dummy_test_context();
        let future_time = Utc::now() + ChronoDuration::seconds(120);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::EXPIRES_AT_ANNOTATION.to_string(),
            future_time.to_rfc3339(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_past_expiration() {
        let ctx = dummy_test_context();
        let past_time = Utc::now() - ChronoDuration::seconds(60);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::EXPIRES_AT_ANNOTATION.to_string(),
            past_time.to_rfc3339(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_deletion_timestamp() {
        let ctx = dummy_test_context();
        let now = Utc::now();

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                deletion_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(now.timestamp()).unwrap(),
                )),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_observed_generation_skips() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_observed_generation_future_expiration_requeues() {
        let ctx = dummy_test_context();
        let future_time = Utc::now() + ChronoDuration::seconds(120);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::EXPIRES_AT_ANNOTATION.to_string(),
            future_time.to_rfc3339(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_unobserved_generation_reconciles() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_min_template_generation_exceeds_caps_and_requeues() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
            "99".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Should return Action::requeue after capping annotation to current template generation (1)
        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn test_reconcile_invalid_min_template_generation_rewrites_and_requeues() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
            "invalid_non_numeric".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Should rewrite the annotation to valid template generation (1) and return Action::requeue
        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn test_reconcile_negative_min_template_generation_rewrites_and_requeues() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
            "-5".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Should rewrite the negative annotation to valid template generation (1) and return Action::requeue
        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn test_reconcile_min_template_generation_satisfied_skips() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
            "1".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_restarted_at_annotation_change_reconciles() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::RESTARTED_AT_ANNOTATION.to_string(),
            "2026-08-27T20:30:00Z".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                restarted_at: Some("2026-08-27T10:00:00Z".into()),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Should NOT skip reconciliation because restarted_at annotation does not match status.restarted_at
        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_restarted_at_annotation_matching_skips() {
        let ctx = dummy_test_context();
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::RESTARTED_AT_ANNOTATION.to_string(),
            "2026-08-27T20:30:00Z".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                restarted_at: Some("2026-08-27T20:30:00Z".into()),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Should skip reconciliation because both generation and restarted_at match status
        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_synced_template_generation_change_reconciles() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(0), // template default generation is 1, so 0 triggers reconcile
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_synced_template_generation_match_skips() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1), // matches template default generation 1
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_failure_records_status() {
        use crate::test_utils::tests::error_kube_client;
        let client = error_kube_client(500);
        let (template_store, _) = kube::runtime::reflector::store();
        let (route_store, _) = kube::runtime::reflector::store();
        let ctx = Context::with_stores(client, template_store, route_store);

        let tmpl = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFTemplateSpec {
                pods: vec![k8s_common::crd::CTFTemplateSpecPod {
                    name: "web".into(),
                    allow_internet: false,
                    replicas: 1,
                    patch: None,
                    spec: k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "web".into(),
                            image: Some("nginx:latest".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                }],
                ..Default::default()
            },
            status: None,
        };
        if let Some(cache) = &ctx.template_cache {
            cache.update(&tmpl);
        }
        let ctx = Arc::new(ctx);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let res = reconcile(instance, ctx).await;
        assert!(matches!(res, Err(Error::Kube(_))));
    }

    #[tokio::test]
    async fn test_error_policy() {
        let ctx = dummy_test_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let err_build = Error::TemplateBuildError("invalid json patch".into());
        let action_build = error_policy(instance.clone(), &err_build, ctx.clone());
        assert_eq!(action_build, Action::await_change());

        let err_not_found = Error::TemplateNotFound("whoami-template".into());
        let action_not_found = error_policy(instance.clone(), &err_not_found, ctx.clone());
        assert_eq!(action_not_found, Action::await_change());

        let err_transient = Error::Custom("failed to connect".into());
        let action_transient = error_policy(instance, &err_transient, ctx);
        assert_eq!(action_transient, Action::requeue(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_find_synced_instances() {
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let inst_sync_true = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let inst_sync_false = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-2".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: false,
                ..Default::default()
            },
            status: None,
        });

        let inst_other_tmpl = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-3".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "other-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let inst_other_ns = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-4".into()),
                namespace: Some("other-ns".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let instances = vec![
            inst_sync_true,
            inst_sync_false,
            inst_other_tmpl,
            inst_other_ns,
        ];
        let matched = find_synced_instances(&tmpl, &instances);

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "inst-1");
        assert_eq!(matched[0].namespace.as_deref(), Some("default"));
    }

    #[tokio::test]
    async fn test_handle_instance_watcher_event() {
        let (store, _writer) = kube::runtime::reflector::store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        handle_instance_watcher_event(&Event::Apply(inst.clone()), &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);

        handle_instance_watcher_event(&Event::Delete(inst), &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);

        handle_instance_watcher_event(&Event::Init, &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);
    }

    #[tokio::test]
    async fn test_handle_template_watcher_event() {
        let (store, _writer) = kube::runtime::reflector::store();
        let cache = crate::cache::TemplateCache::new(store);
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        // Test Apply event updates cache
        handle_template_watcher_event(&Event::Apply(tmpl.clone()), &cache);
        assert!(cache.get("default", "whoami-template").is_some());

        // Test Delete event removes from cache
        handle_template_watcher_event(&Event::Delete(tmpl.clone()), &cache);
        assert!(cache.get("default", "whoami-template").is_none());

        // Test Init event clears cache
        handle_template_watcher_event(&Event::Apply(tmpl), &cache);
        handle_template_watcher_event(&Event::Init, &cache);
        assert!(cache.get("default", "whoami-template").is_none());
    }

    #[tokio::test]
    async fn test_reconcile_expires_at_fast_path_skips_template_resolution() {
        // Create a context where template is intentionally NOT in cache.
        // If template resolution was attempted, it would fail with Error::TemplateNotFound.
        let client = dummy_kube_client();
        let (template_store, _) = kube::runtime::reflector::store();
        let (route_store, _) = kube::runtime::reflector::store();
        let ctx = Arc::new(Context::with_stores(client, template_store, route_store));

        let future_time = Utc::now() + ChronoDuration::seconds(300);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::EXPIRES_AT_ANNOTATION.to_string(),
            future_time.to_rfc3339(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "missing-template".into(),
                sync: false,
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![],
                endpoints: vec![],
                ..Default::default()
            }),
        });

        // Fast-path skip must succeed and return Action::requeue without querying or failing on missing template
        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_restarted_at_overrides_fast_path_and_reconciles() {
        let ctx = dummy_test_context();
        let future_time = Utc::now() + ChronoDuration::seconds(300);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(
            crate::utils::labels::EXPIRES_AT_ANNOTATION.to_string(),
            future_time.to_rfc3339(),
        );
        // New restartedAt annotation differs from status.restarted_at
        annotations.insert(
            crate::utils::labels::RESTARTED_AT_ANNOTATION.to_string(),
            "2026-08-28T08:00:00Z".to_string(),
        );

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: false,
                ..Default::default()
            },
            status: Some(k8s_common::crd::CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                restarted_at: Some("2026-08-28T07:00:00Z".to_string()),
                conditions: vec![],
                endpoints: vec![],
            }),
        });

        // Must bypass fast-path skip and successfully reconcile
        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }
}

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

use crate::{Context, Error, reconcilers, utils::ttl::calculate_remaining_ttl};

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

    // Check if instance has expired
    if crate::utils::ttl::is_expired(instance.spec.expires_at) {
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
        if let Some(remaining) = calculate_remaining_ttl(instance.spec.expires_at) {
            return Ok(Action::requeue(remaining + Duration::from_secs(10)));
        }
        return Ok(Action::await_change());
    }

    reconcile_children(instance, &template, ctx).await?;

    // Success! Update status conditions (Ready = True, RoutesReady) & observed generations
    reconcilers::status::reconcile(instance, ctx, template.metadata.generation).await?;

    if let Some(remaining) = calculate_remaining_ttl(instance.spec.expires_at) {
        // We want to make sure the object really expires to save requeuing
        return Ok(Action::requeue(remaining + Duration::from_secs(10)));
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

    let backoff_secs = match error {
        Error::TemplateBuildError(_) => 120_000,
        Error::TemplateNotFound(_) => 120_000,
        Error::Kube(e) => match e {
            kube::Error::Api(status) if status.code == 429 || status.code >= 500 => 5_000,
            kube::Error::Api(status) if status.code == 409 => 200,
            kube::Error::HyperError(_) | kube::Error::HttpError(_) => 2_000,
            _ => 120_000,
        },
        _ => 15_000,
    };

    Action::requeue(Duration::from_millis(backoff_secs))
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

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
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

/// Handles watcher events for `CTFTemplate` to evict updated or deleted entries from the patcher cache.
pub fn handle_template_watcher_event(
    event: &Result<Event<CTFTemplate>, kube::runtime::watcher::Error>,
    cache: &crate::cache::TemplateCache,
) {
    match event {
        Ok(Event::Apply(t)) | Ok(Event::Delete(t)) | Ok(Event::InitApply(t)) => {
            let name = t.metadata.name.as_deref().unwrap_or_default();
            let ns = t.metadata.namespace.as_deref().unwrap_or("default");
            let cache_key = crate::cache::TemplateKey {
                namespace: ns.to_string(),
                name: name.to_string(),
            };
            cache.remove(&cache_key);
        }
        Ok(Event::Init) => {
            cache.clear();
            info!("Cleared all entries from CTFTemplate patcher cache on watcher init");
        }
        Ok(Event::InitDone) => {}
        Err(err) => {
            error!(%err, "CTFTemplate watcher error");
        }
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

/// Spawns a background task to process a reflector stream.
fn spawn_reflector_watcher<S, K>(stream: S, kind: &'static str) -> AbortOnDrop
where
    S: futures::Stream<Item = Result<K, kube::runtime::watcher::Error>> + Send + 'static,
    K: Send + Sync + 'static,
{
    let task = tokio::spawn(async move {
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(err) = res {
                error!(kind, %err, "Reflector watcher error");
            }
        }
    });
    AbortOnDrop(task)
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
    let template_cache_watcher = context.template_cache.clone();

    let route_cache = context.route_cache.clone().unwrap();
    let route_cache_task = route_cache.clone();

    // Template watch stream handles evictions before populating the template store
    let template_watcher_stream = watcher(templates.clone(), Config::default())
        .default_backoff()
        .inspect(move |res| {
            handle_template_watcher_event(res, &template_cache_watcher);
        });

    let template_reflector = reflector(template_writer, template_watcher_stream);
    let _tmpl_store_guard =
        spawn_reflector_watcher(template_reflector.touched_objects(), "CTFTemplate");

    // CTFRoute watch stream updates route cache index before populating the reflector store
    let route_watcher_stream = watcher(routes.clone(), Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_route_watcher_event(event, &route_cache_task);
            }
        });
    let route_reflector = reflector(route_writer, route_watcher_stream);
    let _route_store_guard = spawn_reflector_watcher(route_reflector.touched_objects(), "CTFRoute");

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
        .watches(templates, Config::default(), move |template| {
            let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
            info!(
                template_name = tmpl_name,
                "CTFTemplate updated, evaluating synced CTFInstances to retrigger"
            );
            instance_cache.find_synced_instances(&template)
        })
        .watches(routes, Config::default(), |route| {
            find_instance_for_route(&route)
        })
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

    #[tokio::test]
    async fn test_reconcile_no_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: None,
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_future_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let future_time = Utc::now() + ChronoDuration::seconds(120);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: Some(future_time),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_past_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let past_time = Utc::now() - ChronoDuration::seconds(60);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: Some(past_time),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_deletion_timestamp() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let future_time = Utc::now() + ChronoDuration::seconds(120);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: Some(future_time),
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        let ctx = Arc::new(Context::new(client));
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
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
        assert_eq!(action_build, Action::requeue(Duration::from_secs(120)));

        let err_transient = Error::Custom("failed to connect".into());
        let action_transient = error_policy(instance, &err_transient, ctx);
        assert_eq!(action_transient, Action::requeue(Duration::from_secs(15)));
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
        let cache = crate::cache::TemplateCache::new();
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let key = crate::cache::TemplateKey {
            namespace: "default".into(),
            name: "whoami-template".into(),
        };

        // Populate cache
        cache.get_or_compile(&key, 1, &[]).unwrap();

        // Test Apply event evicts entry
        handle_template_watcher_event(&Ok(Event::Apply(tmpl.clone())), &cache);

        // Test Init event clears cache
        cache.get_or_compile(&key, 1, &[]).unwrap();
        handle_template_watcher_event(&Ok(Event::Init), &cache);
    }
}

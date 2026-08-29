use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_common::crd::{CTFInstance, CTFProxyRoute, CTFTemplate};
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

    // Ensure routes finalizer is attached to manage cross-namespace cleanup
    if instance.metadata.deletion_timestamp.is_none() {
        reconcilers::helper::ensure_finalizer(ctx.client.clone(), instance).await?;
    }

    // Handle finalizer cleanup if instance is marked for deletion
    if instance.metadata.deletion_timestamp.is_some() {
        info!(
            name,
            ns, "CTFInstance marked for deletion, cleaning up cross-namespace routes..."
        );
        reconcilers::helper::cleanup_instance_routes(
            ctx.client.clone(),
            &ctx.system_namespace,
            instance,
            ctx.route_allocator.as_deref(),
        )
        .await?;
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

    // This evaluates all child conditions (Template, ReplicaSet, NetworkPolicy, Service, CTFProxyRoute)
    // and writes them to the instance status. Only when all are True and nothing has changed
    // since the last ready pass can we skip the child reconciliation entirely.
    let ready = reconcilers::status::reconcile(instance, ctx).await?;
    if matches!(ready, reconcilers::status::Readiness::Ready) && is_observed(instance) {
        info!(name, ns, "Instance ready, skipping reconciliation");
        if let Some(remaining) = calculate_remaining_ttl(expires_at) {
            return Ok(Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER));
        }
        return Ok(Action::await_change());
    }

    info!(name, ns, "Instance not ready, reconciling children");

    // Resolve CTFTemplate referenced by `instance.spec.template`.
    let template = reconcilers::template::reconcile(instance, ctx).await?;

    // Rewrite invalid minTemplateGeneration annotation (non-numeric or <= 0)
    let raw_min_tmpl_gen = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION));

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

    reconcile_children(instance, &template, ctx).await?;

    // A synced instance only reports Ready once status.template_generation catches
    // up with the template, and that field is written in status::reconcile's Ready
    // branch. Record the generation actually applied here so a template bump can
    // transition back to Ready instead of deadlocking in TemplateOutOfSync.
    if instance.spec.sync
        && let Some(applied_gen) = template.metadata.generation
        && instance.status.as_ref().and_then(|s| s.template_generation) != Some(applied_gen)
    {
        reconcilers::helper::PartialStatusTemplateGeneration {
            template_generation: applied_gen,
        }
        .apply(ctx.client.clone(), name, ns)
        .await?;
    }

    if let Some(remaining) = calculate_remaining_ttl(expires_at) {
        return Ok(Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER));
    }

    Ok(Action::await_change())
}

/// Returns true when the instance's status has observed the current spec generation
/// and restart annotation, meaning this reconcile pass found nothing new to apply.
fn is_observed(instance: &CTFInstance) -> bool {
    match (
        instance.status.as_ref().and_then(|s| s.observed_generation),
        instance.metadata.generation,
    ) {
        (Some(observed), Some(current)) if observed < current => return false,
        (None, Some(_)) => return false,
        _ => {}
    }

    // restartedAt doesn't bump metadata.generation, so it must be checked
    // separately or restart requests would be swallowed by the Ready gate.
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

/// Reconciles all child resources (workloads, network policies, services, proxy routes) for a CTFInstance.
async fn reconcile_children(
    instance: &CTFInstance,
    template: &reconcilers::template::ResolvedTemplate,
    ctx: &Context,
) -> Result<(), Error> {
    use crate::planners::{
        NetworkPolicyPlanner, ProxyRoutePlanner, ReplicaSetPlanner, ServicePlanner,
    };
    use crate::reconcilers::helper::{apply_planner, apply_proxy_routes};

    apply_planner::<ReplicaSetPlanner>(ctx.client.clone(), instance, template, ctx).await?;
    apply_planner::<NetworkPolicyPlanner>(ctx.client.clone(), instance, template, ctx).await?;
    apply_planner::<ServicePlanner>(ctx.client.clone(), instance, template, ctx).await?;

    if let Some(allocator) = &ctx.route_allocator {
        use crate::planners::Planner;
        let routes = ProxyRoutePlanner::plan(instance, template, ctx)?;
        apply_proxy_routes(
            ctx.client.clone(),
            &ctx.system_namespace,
            instance,
            routes,
            allocator,
        )
        .await?;
    }

    Ok(())
}

pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    error!(name, %error, "Reconciliation failed");

    match error {
        Error::RouteAllocationError(_) => Action::requeue(Duration::from_secs(30)),
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

/// Predicate for streaming CTFInstances into the controller. Includes deletion
/// state so finalizer cleanup reconciles (deletionTimestamp changes) are delivered
/// even when generation and annotations are untouched.
fn instance_predicate() -> impl Predicate<CTFInstance> {
    predicates::generation
        .combine(predicates::annotations)
        .combine(|obj: &CTFInstance| Some(u64::from(obj.metadata.deletion_timestamp.is_some())))
}

/// Handles instance watcher `InitDone` event by pruning unreferenced proxy routes in the cluster.
pub async fn handle_instance_watcher_init_done(
    client: Client,
    system_ns: &str,
    store: &store::Store<CTFInstance>,
    allocator: &crate::routing::RouteAllocator,
) -> Result<(), Error> {
    let live_instances: std::collections::HashSet<(String, String)> = store
        .state()
        .into_iter()
        .filter(|inst| inst.metadata.deletion_timestamp.is_none())
        .map(|inst| {
            let ns = inst.metadata.namespace.as_deref().unwrap_or("default");
            let name = inst.metadata.name.as_deref().unwrap_or("unknown");
            (ns.to_string(), name.to_string())
        })
        .collect();

    info!(
        live_count = live_instances.len(),
        "CTFInstance init done; checking and pruning dangling proxy routes..."
    );
    crate::reconcilers::helper::prune_unreferenced_proxy_routes(
        client,
        system_ns,
        &live_instances,
        allocator,
    )
    .await?;

    Ok(())
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

/// Spawns and runs the `CTFInstance` controller loop.
pub async fn run(
    client: Client,
    allocator: Arc<crate::routing::RouteAllocator>,
    system_namespace: String,
    cluster_domain: String,
) -> Result<(), Error> {
    let instances = Api::<CTFInstance>::all(client.clone());
    let templates = Api::<CTFTemplate>::all(client.clone());
    let proxy_routes = Api::<CTFProxyRoute>::namespaced(client.clone(), &system_namespace);

    // Bootstrap active port allocations directly from existing CTFProxyRoutes in system namespace
    match proxy_routes.list(&Default::default()).await {
        Ok(routes) => {
            use k8s_common::crd::ProxyRouteKey;
            use kube::Resource;

            allocator.clear();
            let mut count = 0;
            for route in routes {
                if let Some(name) = route.meta().name.as_deref()
                    && let Ok(ProxyRouteKey::Tcp(port)) = name.parse::<ProxyRouteKey>()
                    && let Some(labels) = route.metadata.labels.as_ref()
                {
                    let instance_name = labels.get(crate::utils::labels::INSTANCE_LABEL);
                    let instance_ns = labels
                        .get(crate::utils::labels::INSTANCE_NAMESPACE_LABEL)
                        .map(|s| s.as_str())
                        .unwrap_or("default");
                    let pod_name = labels.get(crate::utils::labels::POD_LABEL);

                    if let (Some(inst), Some(pod)) = (instance_name, pod_name) {
                        let route_key = crate::routing::RouteKey::new(instance_ns, inst, pod);
                        allocator.sync(&route_key, port);
                        count += 1;
                    }
                }
            }
            info!(
                count,
                system_namespace = %system_namespace,
                "Bootstrapped active ports from cluster CTFProxyRoutes"
            );
        }
        Err(e) => {
            error!("fatal controller error: {e}");
            return Err(e.into());
        }
    }

    // Initialize in-memory CTFTemplate reflector store cache
    let (template_store, template_writer) = store();

    let context = Arc::new(Context::with_allocator(
        client.clone(),
        template_store,
        allocator.clone(),
        system_namespace.clone(),
        cluster_domain,
    ));
    let template_cache = context.template_cache.clone().unwrap();
    let template_cache_task = template_cache.clone();

    // Used to gate instance events on the initial CTFTemplate sync. A watch
    // channel (rather than flag + Notify) because notify_waiters() loses the
    // wakeup if it fires before a waiter registers: a watch stores the value.
    let (template_ready_tx, template_ready_rx) = tokio::sync::watch::channel(false);
    let template_ready_tx_task = template_ready_tx.clone();

    // Template watch stream updates template cache before populating the template store
    let template_watcher_stream = watcher(templates.clone(), Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_template_watcher_event(event, &template_cache_task);
                if let Event::InitDone = event {
                    info!("CTFTemplate initial sync complete");
                    let _ = template_ready_tx_task.send(true);
                }
            }
        });

    let template_reflector = reflector(template_writer, template_watcher_stream);
    let template_stream = template_reflector
        .touched_objects()
        .predicate_filter(predicates::generation, Default::default());

    // Initialize in-memory CTFInstance reflector store cache for watches mapping
    let (instance_store, instance_writer) = store();

    use crate::cache::InstanceCache;
    let instance_cache = InstanceCache::new(instance_store.clone());
    let instance_cache_task = instance_cache.clone();

    let client_init_done = client.clone();
    let system_ns_init_done = system_namespace.clone();
    let allocator_init_done = allocator.clone();
    let instance_store_init_done = instance_store.clone();

    let instance_template_rx = template_ready_rx.clone();

    let (fatal_tx, mut fatal_rx) = tokio::sync::broadcast::channel::<String>(1);

    let instance_watcher_stream = watcher(instances, Config::default())
        .default_backoff()
        .then(move |res| {
            let client = client_init_done.clone();
            let system_ns = system_ns_init_done.clone();
            let allocator = allocator_init_done.clone();
            let store = instance_store_init_done.clone();
            let cache = instance_cache_task.clone();
            let fatal_tx = fatal_tx.clone();
            let mut template_rx = instance_template_rx.clone();

            async move {
                // Race-free wait for the initial CTFTemplate sync: watch stores
                // the latest value, so a send racing this check cannot be lost.
                while !*template_rx.borrow() {
                    if template_rx.changed().await.is_err() {
                        break;
                    }
                }

                if let Ok(ref event) = res {
                    handle_instance_watcher_event(event, &cache);
                    if let Event::InitDone = event
                        && let Err(e) = handle_instance_watcher_init_done(
                            client, &system_ns, &store, &allocator,
                        )
                        .await
                    {
                        error!("fatal controller error: {e}");
                        let _ = fatal_tx.send(e.to_string());
                    }
                }
                res
            }
        });

    let instance_reflector = reflector(instance_writer, instance_watcher_stream);
    let controller_instance_stream = instance_reflector
        .touched_objects()
        .predicate_filter(instance_predicate(), Default::default());

    info!("Starting CTFInstance controller with Template tracking");

    tokio::select! {
        Ok(err_msg) = fatal_rx.recv() => {
            Err(Error::Custom(err_msg))
        }
        _ = Controller::for_stream(controller_instance_stream, instance_store)
            .watches_stream(template_stream, move |template| {
                let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
                info!(
                    template_name = tmpl_name,
                    "CTFTemplate updated, evaluating synced CTFInstances to retrigger"
                );
                instance_cache.find_synced_instances(&template)
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
            }) => {
                Ok(())
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{PortsStore, RouteAllocator};
    use crate::test_utils::tests::{
        dummy_context, dummy_ctx, dummy_instance, dummy_kube_client, recording_kube_client,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use futures::StreamExt;
    use k8s_common::PortRange;
    use k8s_common::crd::{
        CTFInstanceSpec, CTFInstanceStatus, CTFTemplateSpecRoute, RouteBackend, RouteSpec,
        RouteSpecTCP,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::WatchStreamExt;
    use kube::runtime::watcher::Error as WatcherError;

    #[tokio::test]
    async fn test_template_ready_wait_delivers_concurrent_send() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);

        let task = tokio::spawn(async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("template ready wait must not deadlock when send races the check")
            .unwrap();
    }

    #[tokio::test]
    async fn test_template_ready_wait_returns_immediately_when_already_ready() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        tx.send(true).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("template ready wait must return immediately when already ready");
    }

    #[tokio::test]
    async fn test_reconcile_no_expiration() {
        let (_store, ctx) = dummy_context();
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
        let (_store, ctx) = dummy_context();
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
        let (_store, ctx) = dummy_context();
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
        let (_store, ctx) = dummy_context();
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
    async fn test_deletion_timestamp_instances_are_delivered_to_controller() {
        let mut inst = dummy_instance("chal-1", None);
        inst.metadata.uid = Some("uid-1".to_string());
        inst.metadata.generation = Some(1);
        inst.metadata.resource_version = Some("1".to_string());
        inst.metadata.finalizers = Some(vec![crate::utils::labels::ROUTES_FINALIZER.to_string()]);

        let mut dying = inst.clone();
        dying.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        dying.metadata.resource_version = Some("2".to_string());

        let events: Vec<Result<CTFInstance, WatcherError>> = vec![Ok(inst), Ok(dying)];
        let filtered = futures::stream::iter(events)
            .predicate_filter(instance_predicate(), Default::default());

        let items: Vec<CTFInstance> = filtered.map(|r| r.unwrap()).collect().await;
        assert_eq!(
            items.len(),
            2,
            "finalizer cleanup reconcile for the deleted instance must be delivered"
        );
        assert!(
            items
                .iter()
                .any(|i| i.metadata.deletion_timestamp.is_some()),
            "deleted instance must reach the reconcile loop"
        );
    }

    #[tokio::test]
    async fn test_spec_change_after_ready_reapplies_children() {
        let (client, log) = recording_kube_client();
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
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route]);

        let count_rs_patches = |log: &std::sync::Mutex<Vec<String>>| {
            log.lock()
                .unwrap()
                .iter()
                .filter(|s| s.starts_with("PATCH") && s.contains("/replicasets"))
                .count()
        };

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });

        reconcile(instance.clone(), ctx.clone()).await.unwrap();
        assert_eq!(
            count_rs_patches(&log),
            0,
            "ready + observed instance must not re-apply children"
        );

        log.lock().unwrap().clear();
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(2);
        inst.spec
            .params
            .push(k8s_common::crd::CTFInstanceSpecParam {
                name: "FLAG".into(),
                value: k8s_common::crd::PatchValue::Value("CTF{rotated}".into()),
            });

        reconcile(instance, ctx).await.unwrap();
        assert!(
            count_rs_patches(&log) > 0,
            "children must be re-applied after the spec generation changes"
        );
    }

    #[tokio::test]
    async fn test_restart_annotation_after_ready_reapplies_children() {
        let (client, log) = recording_kube_client();
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
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route]);

        let count_rs_patches = |log: &std::sync::Mutex<Vec<String>>| {
            log.lock()
                .unwrap()
                .iter()
                .filter(|s| s.starts_with("PATCH") && s.contains("/replicasets"))
                .count()
        };

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });

        reconcile(instance.clone(), ctx.clone()).await.unwrap();
        log.lock().unwrap().clear();

        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                crate::utils::labels::RESTARTED_AT_ANNOTATION.to_string(),
                "2026-08-29T12:00:00Z".to_string(),
            );

        reconcile(instance, ctx).await.unwrap();
        assert!(
            count_rs_patches(&log) > 0,
            "children must be re-applied when restartedAt changes without a generation bump"
        );
    }

    #[tokio::test]
    async fn test_synced_instance_stamps_template_generation_after_apply() {
        let (client, log) = recording_kube_client();
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
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route.clone()]);

        let tmpl = k8s_common::crd::CTFTemplate {
            metadata: ObjectMeta {
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
        ctx.template_cache.as_ref().unwrap().update(&tmpl);

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.spec.sync = true;
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            endpoints: vec![],
        });

        reconcile(instance, ctx).await.unwrap();

        let stamped = log
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("PATCH") && s.contains("/status"));
        assert!(
            stamped,
            "reconcile must stamp templateGeneration after applying a bumped template \
             so the instance can return to Ready"
        );
    }

    #[tokio::test]
    async fn test_reconcile_observed_generation_skips() {
        let (_store, ctx) = dummy_context();
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
            status: Some(CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![Condition {
                    type_: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "Reconciled".to_string(),
                    message: "CTFInstance reconciled successfully".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ),
                    observed_generation: Some(1),
                }],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_handle_instance_watcher_init_done_success() {
        let client = dummy_kube_client();
        let (instance_store, mut instance_writer) = store();
        let mut inst = dummy_instance("chal-1", None);
        inst.metadata.namespace = Some("team-1".into());
        instance_writer.apply_watcher_event(&Event::Apply(inst));

        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports, "seed", "c.sk8.dog", 4433);

        let res = handle_instance_watcher_init_done(
            client,
            "aincrad-system",
            &instance_store,
            &allocator,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_handle_instance_watcher_init_done_failure() {
        use tower::service_fn;
        let mock_service = service_fn(|_req: axum::http::Request<kube::client::Body>| async move {
            Ok::<_, std::convert::Infallible>(
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from("Internal Server Error"))
                    .unwrap(),
            )
        });
        let client = kube::Client::new(mock_service, "default");
        let (instance_store, _) = store();

        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports, "seed", "c.sk8.dog", 4433);

        let res = handle_instance_watcher_init_done(
            client,
            "aincrad-system",
            &instance_store,
            &allocator,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_controller_run_fatal_list_error() {
        use tower::service_fn;
        let mock_service = service_fn(|_req: axum::http::Request<kube::client::Body>| async move {
            Ok::<_, std::convert::Infallible>(
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from("Internal Server Error"))
                    .unwrap(),
            )
        });
        let client = kube::Client::new(mock_service, "default");

        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = Arc::new(RouteAllocator::new(ports, "seed", "c.sk8.dog", 4433));

        let res = run(
            client,
            allocator,
            "aincrad-system".into(),
            "cluster.local".into(),
        )
        .await;
        assert!(res.is_err());
    }
}

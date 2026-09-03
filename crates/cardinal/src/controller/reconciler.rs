use std::{sync::Arc, time::Duration};

use futures::{Stream, StreamExt};
use k8s_common::{
    crd::{CTFInstance, CTFProxyRoute, CTFTemplate, ProxyRouteKey, TLSRoute},
    labels::{INSTANCE_LABEL, NAMESPACE_LABEL, RESOURCE_LABEL},
};
use k8s_openapi::api::{apps::v1::ReplicaSet, core::v1::Service};
use kube::{
    Api, Client,
    runtime::{
        Predicate, WatchStreamExt,
        controller::{Action, Controller},
        predicates,
        reflector::{ObjectRef, reflector, store},
        watcher::{Config, Error as WatcherError, Event, watcher},
    },
};
use tracing::{error, info, instrument, warn};

use crate::{
    Context, Error,
    cache::{Caches, ReadyGate, ResourceKey},
    cli::Opts,
    reconcilers,
    routing::PortMap,
};

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    match crate::controller::phases::run(&instance, &ctx).await {
        Ok(action) => Ok(action),
        Err(err) => {
            let _ = reconcilers::status::reconcile_failure(&instance, &ctx, &err).await;
            Err(err)
        }
    }
}

pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");

    if let Error::Kube(kube::Error::Api(status)) = error
        && status.code == 404
    {
        tracing::debug!(name, "Instance already deleted from cluster");
        return Action::await_change();
    }

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

/// Handles instance watcher `InitDone` event by pruning unreferenced proxy routes
/// from the live proxy-route cache.
pub async fn handle_instance_watcher_init_done(
    client: Client,
    system_ns: &str,
    cache: &crate::cache::InstanceCache,
    proxy_routes: &crate::cache::ResourceCache<CTFProxyRoute>,
    managed_namespace: Option<&str>,
) -> Result<(), Error> {
    let live_instances: std::collections::HashSet<(String, String)> =
        cache.live_instances().into_iter().collect();

    info!(
        live_count = live_instances.len(),
        managed_namespace = ?managed_namespace,
        "CTFInstance init done; checking and pruning dangling proxy routes..."
    );
    crate::reconcilers::helper::prune_unreferenced_proxy_routes(
        client,
        system_ns,
        proxy_routes,
        &live_instances,
        managed_namespace,
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
            cache.mark_unready();
            info!("Cleared CTFTemplate cache on watcher init");
        }
        Event::InitDone => {
            cache.mark_ready();
            info!("CTFTemplate initial sync complete");
        }
    }
}

/// Maps a `CTFProxyRoute` event to the `CTFInstance` it belongs to via labels.
fn proxy_route_owner(
    route: &CTFProxyRoute,
    filter_ns: Option<&str>,
) -> Vec<ObjectRef<CTFInstance>> {
    let Some(instance) = route
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(INSTANCE_LABEL))
    else {
        return Vec::new();
    };
    let ns = route
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(NAMESPACE_LABEL))
        .map(String::as_str)
        .unwrap_or("default");
    if let Some(target_ns) = filter_ns
        && ns != target_ns
    {
        return Vec::new();
    }
    vec![ObjectRef::new(instance).within(ns)]
}

/// Helper handling port map synchronization on proxy route watcher events.
fn handle_proxy_route_port_map_event(
    event: &Event<CTFProxyRoute>,
    port_map: &PortMap,
    _managed_namespace: Option<&str>,
) {
    match event {
        Event::Apply(route) | Event::InitApply(route) => {
            if let Ok(ProxyRouteKey::Tcp(port)) = route.route_key() {
                // Static or unlabeled routes occupy a port without an instance owner.
                let key = proxy_route_key(route).unwrap_or_else(|| ResourceKey::new("", "", ""));
                port_map.bind(port, key);
            }
        }
        Event::Delete(route) => {
            if let Ok(ProxyRouteKey::Tcp(port)) = route.route_key() {
                port_map.unbind(port);
            }
        }
        Event::Init => {
            port_map.clear();
        }
        Event::InitDone => {}
    }
}

pub async fn run(client: Client, opts: Opts) -> Result<(), Error> {
    let Opts {
        system_namespace,
        reserved_ports,
        auto_ports,
        route_seed,
        hostname_suffix,
        tls_port,
        cluster_domain,
        managed_namespaces,
        image_aliases: image_alias,
    } = opts;
    let system_namespace =
        system_namespace.unwrap_or_else(|| client.default_namespace().to_string());

    let port_map = Arc::new(PortMap::new(reserved_ports, auto_ports));

    let image_alias_map = image_alias
        .into_iter()
        .flatten()
        .collect::<std::collections::BTreeMap<String, String>>();

    if managed_namespaces.is_empty() {
        let context = Arc::new(Context {
            client: client.clone(),
            caches: Caches::default(),
            port_map: Some(port_map.clone()),
            route_seed,
            hostname_suffix,
            tls_port,
            system_namespace: system_namespace.clone(),
            cluster_domain,
            image_aliases: image_alias_map,
        });

        let proxy_routes = Api::<CTFProxyRoute>::namespaced(client, &system_namespace);
        let proxy_route_cache = context.caches.proxy_routes.clone();
        let port_map_stream = port_map.clone();
        let proxy_route_stream = proxy_route_cache.watcher_stream(proxy_routes, move |event| {
            handle_proxy_route_port_map_event(event, &port_map_stream, None);
        });

        run_controller(None, context, proxy_route_stream).await
    } else {
        let mut tasks = Vec::new();
        for ns in managed_namespaces {
            let context = Arc::new(Context {
                client: client.clone(),
                caches: Caches::default(),
                port_map: Some(port_map.clone()),
                route_seed: route_seed.clone(),
                hostname_suffix: hostname_suffix.clone(),
                tls_port,
                system_namespace: system_namespace.clone(),
                cluster_domain: cluster_domain.clone(),
                image_aliases: image_alias_map.clone(),
            });

            let proxy_routes = Api::<CTFProxyRoute>::namespaced(client.clone(), &system_namespace);
            let proxy_route_cache = context.caches.proxy_routes.clone();
            let port_map_stream = port_map.clone();
            let ns_clone = ns.clone();
            let proxy_route_stream = proxy_route_cache.watcher_stream(proxy_routes, move |event| {
                handle_proxy_route_port_map_event(event, &port_map_stream, Some(&ns_clone));
            });

            tasks.push(tokio::spawn(async move {
                run_controller(Some(ns), context, proxy_route_stream).await
            }));
        }

        let (res, _idx, _remaining) = futures::future::select_all(tasks).await;
        match res {
            Ok(controller_res) => controller_res,
            Err(join_err) => Err(Error::Custom(join_err.to_string())),
        }
    }
}

/// Derives the allocator key for a proxy route from its labels.
fn proxy_route_key(route: &CTFProxyRoute) -> Option<ResourceKey> {
    let labels = route.metadata.labels.as_ref()?;
    let instance = labels.get(INSTANCE_LABEL)?;
    let instance_ns = labels
        .get(NAMESPACE_LABEL)
        .map(|s| s.as_str())
        .unwrap_or("default");
    let resource = labels.get(RESOURCE_LABEL)?;
    Some(ResourceKey::new(
        instance_ns,
        instance.as_str(),
        resource.as_str(),
    ))
}

/// Spawns and runs the `CTFInstance` controller loop.
pub async fn run_controller<S>(
    namespace: Option<String>,
    context: Arc<Context>,
    proxy_route_stream: S,
) -> Result<(), Error>
where
    S: Stream<Item = Result<CTFProxyRoute, WatcherError>> + Send + 'static,
{
    let client = &context.client;
    let (instances, templates, services, replica_sets, tls_routes) = if let Some(ref ns) = namespace {
        (
            Api::<CTFInstance>::namespaced(client.clone(), ns),
            Api::<CTFTemplate>::namespaced(client.clone(), ns),
            Api::<Service>::namespaced(client.clone(), ns),
            Api::<ReplicaSet>::namespaced(client.clone(), ns),
            Api::<TLSRoute>::namespaced(client.clone(), ns),
        )
    } else {
        (
            Api::<CTFInstance>::all(client.clone()),
            Api::<CTFTemplate>::all(client.clone()),
            Api::<Service>::all(client.clone()),
            Api::<ReplicaSet>::all(client.clone()),
            Api::<TLSRoute>::all(client.clone()),
        )
    };

    // Gates instance processing until every auxiliary cache completes its initial sync.
    let ready = ReadyGate::from_caches(&context.caches);

    let template_cache = context.caches.templates.clone();

    // Template watcher updates the cache before the stream drives the controller `watches_stream` trigger.
    let template_watcher_stream = watcher(templates, Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_template_watcher_event(event, &template_cache);
            }
        });

    let template_stream = template_watcher_stream.touched_objects().predicate_filter(
        predicates::generation.combine(predicates::annotations),
        Default::default(),
    );

    let services_cache = context.caches.services.clone();
    let service_stream = services_cache.watcher_stream(services, |_| {});

    let replica_sets_cache = context.caches.replica_sets.clone();
    let replica_set_stream = replica_sets_cache.watcher_stream(replica_sets, |_| {});

    let tls_routes_cache = context.caches.tls_routes.clone();
    let tls_route_stream = tls_routes_cache.watcher_stream(tls_routes, |_| {});

    let proxy_route_stream = proxy_route_stream;

    // Initialize in-memory CTFInstance reflector store cache for watches mapping
    let (instance_store, instance_writer) = store();

    let instance_cache = context.caches.instances.clone();
    let instance_cache_task = instance_cache.clone();

    let client_init_done = client.clone();
    let system_ns_init_done = context.system_namespace.clone();
    let proxy_routes_init_done = context.caches.proxy_routes.clone();

    let ready_task = ready.clone();
    let namespace_task = namespace.clone();

    let (fatal_tx, mut fatal_rx) = tokio::sync::broadcast::channel::<String>(1);

    let instance_watcher_stream = watcher(instances, Config::default())
        .default_backoff()
        .then(move |res| {
            let client = client_init_done.clone();
            let system_ns = system_ns_init_done.clone();
            let proxy_routes = proxy_routes_init_done.clone();
            let cache = instance_cache_task.clone();
            let fatal_tx = fatal_tx.clone();
            let ready = ready_task.clone();
            let managed_ns = namespace_task.clone();

            async move {
                // Hold instance events until every child cache has completed its initial sync.
                ready.wait().await;

                if let Ok(ref event) = res {
                    handle_instance_watcher_event(event, &cache);
                    if let Event::InitDone = event
                        && let Err(e) = handle_instance_watcher_init_done(
                            client,
                            &system_ns,
                            &cache,
                            &proxy_routes,
                            managed_ns.as_deref(),
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

    if let Some(ref ns) = namespace {
        info!(namespace = %ns, "Starting CTFInstance controller with Template tracking");
    } else {
        info!("Starting CTFInstance controller across all namespaces with Template tracking");
    }

    let proxy_route_ns = namespace.clone();

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
                instance_cache
                    .instances_to_sync(&template)
                    .into_iter()
                    .map(|inst| ObjectRef::from_obj(&*inst))
                    .collect::<Vec<_>>()
            })
            .watches_stream(proxy_route_stream, move |route| {
                proxy_route_owner(&route, proxy_route_ns.as_deref())
            })
            .owns_stream(service_stream)
            .owns_stream(replica_set_stream)
            .owns_stream(tls_route_stream)
            .run(reconcile, error_policy, context)
            .for_each(|res| async {
                match res {
                    Ok((object, _action)) => {
                        info!(name = %object.name, "Successfully reconciled CTFInstance");
                    }
                    Err(err) => {
                        let err_msg = err.to_string();
                        if err_msg.contains("not found") || err_msg.contains("NotFound") {
                            tracing::debug!(%err, "Object deleted before reconciliation completed");
                        } else {
                            warn!(%err, "Controller error occurred");
                        }
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
    use crate::test_utils::tests::{
        dummy_context, dummy_ctx, dummy_instance, dummy_kube_client, recording_kube_client,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::crd::{
        CTFInstanceSpec, CTFInstanceStatus, RouteBackend, RouteSpec, RouteSpecTCP,
    };
    use k8s_common::labels::{EXPIRES_AT_ANNOTATION, RESTARTED_AT_ANNOTATION, ROUTES_FINALIZER};
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
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), future_time.to_rfc3339());

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
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), past_time.to_rfc3339());

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
        inst.metadata.finalizers = Some(vec![ROUTES_FINALIZER.to_string()]);

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
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
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
            resources: Default::default(),
            ..Default::default()
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
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
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
            resources: Default::default(),
            ..Default::default()
        });

        reconcile(instance.clone(), ctx.clone()).await.unwrap();
        log.lock().unwrap().clear();

        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                RESTARTED_AT_ANNOTATION.to_string(),
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
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
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
        ctx.caches.templates.update(&tmpl);

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.spec.sync = true;
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
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
        use crate::cache::{InstanceCache, ResourceCache};

        let client = dummy_kube_client();
        let mut inst = dummy_instance("chal-1", None);
        inst.metadata.namespace = Some("team-1".into());
        let cache = InstanceCache::new();
        cache.update(&inst);

        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();

        let res = handle_instance_watcher_init_done(
            client,
            "aincrad-system",
            &cache,
            &proxy_routes,
            None,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_handle_instance_watcher_init_done_failure() {
        use crate::cache::{InstanceCache, ResourceCache};
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
        let cache = InstanceCache::new();

        // Seed an orphaned route so the prune hits the always-500 mock client.
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();
        let orphan = CTFProxyRoute {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("p30005".to_string()),
                labels: Some(crate::btreemap! {
                    NAMESPACE_LABEL => "team-1",
                    INSTANCE_LABEL => "dead-chal",
                    RESOURCE_LABEL => "pwn",
                }),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFProxyRouteSpec {
                backend: "10.0.0.1:80".to_string(),
                policy: Default::default(),
            },
        };
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(orphan));

        let res = handle_instance_watcher_init_done(
            client,
            "aincrad-system",
            &cache,
            &proxy_routes,
            None,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_instances_lock_when_route_allocator_reallocating() {
        use crate::cache::ReadyGate;
        use std::time::Duration;

        let (_store, ctx) = dummy_context();

        // Mark all auxiliary caches as initially ready
        ctx.caches.replica_sets.mark_ready();
        ctx.caches.services.mark_ready();
        ctx.caches.templates.mark_ready();
        ctx.caches.proxy_routes.mark_ready();
        ctx.caches.tls_routes.mark_ready();

        let gate = ReadyGate::from_caches(&ctx.caches);
        assert!(gate.is_ready(), "gate must be ready initially");

        // Port map receives Event::Init (e.g. reconnection / re-list)
        let port_map = ctx.port_map.as_ref().unwrap();
        handle_proxy_route_port_map_event(&Event::Init, port_map, None);
        // ProxyRoute watcher stream marks proxy_routes unready on Event::Init
        ctx.caches.proxy_routes.mark_unready();

        assert!(
            !gate.is_ready(),
            "gate must not be ready while port map is re-syncing"
        );

        // Spawn a task that waits on the gate (simulating instance reconcile stream)
        let gate_waiter = gate.clone();
        let (unlocked_tx, mut unlocked_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            gate_waiter.wait().await;
            let _ = unlocked_tx.send(()).await;
        });

        // Verify the gate remains locked while routes are being reloaded
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            unlocked_rx.try_recv().is_err(),
            "instance processing must be locked while port map is re-syncing"
        );

        // Re-stream routes during InitApply
        let route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("r30000".to_string()),
                namespace: Some("aincrad-system".to_string()),
                labels: Some(crate::btreemap! {
                    NAMESPACE_LABEL => "default",
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFProxyRouteSpec {
                backend: "web.default.svc.cluster.local:80".to_string(),
                policy: Default::default(),
            },
        };
        handle_proxy_route_port_map_event(&Event::InitApply(route.clone()), port_map, None);
        ctx.caches.proxy_routes.handle(&Event::InitApply(route));

        // Re-allocation finishes: Event::InitDone arrives
        handle_proxy_route_port_map_event(&Event::InitDone, port_map, None);
        ctx.caches.proxy_routes.mark_ready();

        // Verify gate is ready and waiter task unlocks
        assert!(gate.is_ready(), "gate must be ready after InitDone");
        let unlocked = tokio::time::timeout(Duration::from_secs(1), unlocked_rx.recv()).await;
        assert!(
            unlocked.is_ok(),
            "instance processing must resume once route allocator finishes"
        );
    }

    #[tokio::test]
    async fn test_handle_proxy_route_port_map_event_binds_unlabeled_static_route() {
        let (_store, ctx) = dummy_context();
        let port_map = ctx.port_map.as_ref().unwrap();

        let unlabeled_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p30005".to_string()),
                namespace: Some("aincrad-system".to_string()),
                labels: None,
                ..Default::default()
            },
            spec: k8s_common::crd::CTFProxyRouteSpec {
                backend: "static-service.default.svc.cluster.local:80".to_string(),
                policy: Default::default(),
            },
        };

        handle_proxy_route_port_map_event(&Event::Apply(unlabeled_route), port_map, None);

        let key = port_map.get_key(30005);
        assert!(
            key.is_some(),
            "unlabeled TCP route must be bound in port map"
        );
        let key = key.unwrap();
        assert_eq!(key.namespace, "");
        assert_eq!(key.instance, "");
        assert_eq!(key.resource, "");
    }
}

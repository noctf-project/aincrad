pub mod instance;
pub mod phases;
pub mod template;

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_common::{
    crd::{CTFInstance, CTFTemplate, TLSRoute},
    labels::{INSTANCE_LABEL, RESOURCE_LABEL},
};
use k8s_openapi::api::{apps::v1::ReplicaSet, core::v1::Service};
use kube::{
    Api, Client,
    runtime::{
        Predicate, WatchStreamExt,
        controller::Controller,
        predicates,
        reflector::{ObjectRef, reflector, store, store_shared},
        watcher::{Config, Event, watcher},
    },
};
use tracing::{info, warn};

use crate::{
    Context, Error,
    cache::{Caches, ReadyGate, ResourceKey},
    routing::{Port, PortMap},
};

pub use instance::{error_policy, reconcile};

pub const TIME_BASED_REQUEUE_BUFFER: Duration = Duration::from_secs(3);
pub const AVAILABILITY_LEAD_TIME: Duration = Duration::from_secs(30);

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

/// Helper handling port map synchronization on Service watcher events for LoadBalancer services.
pub fn handle_service_port_map_event(event: &Event<Service>, port_map: &PortMap) {
    match event {
        Event::Apply(svc) | Event::InitApply(svc) => {
            if svc
                .spec
                .as_ref()
                .and_then(|s| s.load_balancer_class.as_deref())
                != Some(crate::utils::CARDINAL_LB_CLASS)
            {
                return;
            }
            let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
            let instance_name = svc
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(INSTANCE_LABEL))
                .map(String::as_str)
                .unwrap_or("");
            let pod_name = svc
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(RESOURCE_LABEL))
                .map(String::as_str)
                .unwrap_or("");

            if let Some(ports) = svc.spec.as_ref().and_then(|s| s.ports.as_ref()) {
                for p in ports {
                    if p.port > 0 {
                        let route_name = p.name.as_deref().unwrap_or(pod_name);
                        let key = ResourceKey::new(ns, instance_name, route_name);
                        let port = match p.protocol.as_deref() {
                            Some("UDP") => Port::Udp(p.port as u16),
                            _ => Port::Tcp(p.port as u16),
                        };
                        port_map.bind(port, key);
                    }
                }
            }
        }
        Event::Delete(svc) => {
            if svc
                .spec
                .as_ref()
                .and_then(|s| s.load_balancer_class.as_deref())
                != Some(crate::utils::CARDINAL_LB_CLASS)
            {
                return;
            }
            let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
            let instance_name = svc
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(INSTANCE_LABEL))
                .map(String::as_str)
                .unwrap_or("");
            let pod_name = svc
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(RESOURCE_LABEL))
                .map(String::as_str)
                .unwrap_or("");

            if let Some(ports) = svc.spec.as_ref().and_then(|s| s.ports.as_ref()) {
                for p in ports {
                    if p.port > 0 {
                        let route_name = p.name.as_deref().unwrap_or(pod_name);
                        let key = ResourceKey::new(ns, instance_name, route_name);
                        let port = match p.protocol.as_deref() {
                            Some("UDP") => Port::Udp(p.port as u16),
                            _ => Port::Tcp(p.port as u16),
                        };
                        port_map.unbind_key(port, &key);
                    }
                }
            }
        }
        Event::Init => {
            port_map.clear();
        }
        Event::InitDone => {}
    }
}

pub async fn run(client: Client, config: crate::config::CardinalConfig) -> Result<(), Error> {
    let port_map = Arc::new(PortMap::new(
        config.ports.reserved.clone(),
        config.ports.auto.clone(),
    ));

    // TODO: support more than 1 namespace
    let namespace = if config.namespaces.len() == 1 {
        Some(config.namespaces[0].clone())
    } else {
        None
    };

    let context = Arc::new(Context {
        client: client.clone(),
        caches: Caches::default(),
        port_map: Some(port_map.clone()),
        config,
    });

    run_controller(namespace, context).await
}

/// Spawns and runs the `CTFInstance` and `CTFTemplate` controller loops concurrently.
pub async fn run_controller(namespace: Option<String>, context: Arc<Context>) -> Result<(), Error> {
    let client = &context.client;
    let (instances, templates, services, replica_sets, tls_routes) = if let Some(ref ns) = namespace
    {
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

    // Single template watcher updates cache before feeding both controllers.
    let template_watcher_stream = watcher(templates, Config::default())
        .default_backoff()
        .inspect(move |res| {
            if let Ok(event) = res {
                handle_template_watcher_event(event, &template_cache);
            }
        });

    // Shared in-memory reflector store for CTFTemplate
    let (template_store, template_writer) = store_shared(64);
    let template_subscriber = template_writer
        .subscribe()
        .expect("template writer created with store_shared must be subscribable");
    let template_reflector = reflector(template_writer, template_watcher_stream);
    let template_controller_stream = template_reflector.touched_objects().predicate_filter(
        predicates::generation.combine(predicates::annotations),
        Default::default(),
    );

    let port_map_stream = context.port_map.clone();
    let services_cache = context.caches.services.clone();
    let service_stream = services_cache.watcher_stream(services, move |event| {
        if let Some(ref pm) = port_map_stream {
            handle_service_port_map_event(event, pm);
        }
    });

    let replica_sets_cache = context.caches.replica_sets.clone();
    let replica_set_stream = replica_sets_cache.watcher_stream(replica_sets, |_| {});

    let tls_routes_cache = context.caches.tls_routes.clone();
    let tls_route_stream = tls_routes_cache.watcher_stream(tls_routes, |_| {});

    // Initialize in-memory CTFInstance reflector store cache for watches mapping
    let (instance_store, instance_writer) = store();

    let instance_cache = context.caches.instances.clone();
    let instance_cache_task = instance_cache.clone();

    let ready_task = ready.clone();

    let instance_watcher_stream = watcher(instances, Config::default())
        .default_backoff()
        .then(move |res| {
            let cache = instance_cache_task.clone();
            let ready = ready_task.clone();

            async move {
                // Hold instance events until every child cache has completed its initial sync.
                ready.wait().await;

                if let Ok(ref event) = res {
                    handle_instance_watcher_event(event, &cache);
                }
                res
            }
        });

    let instance_reflector = reflector(instance_writer, instance_watcher_stream);
    let controller_instance_stream = instance_reflector
        .touched_objects()
        .predicate_filter(instance::instance_predicate(), Default::default());

    match namespace.as_deref() {
        Some(ns) => {
            info!(namespace = %ns, "Starting CTFInstance controller with Template tracking");
        }
        None => {
            info!("Starting CTFInstance controller across all namespaces with Template tracking");
        }
    }

    let instance_controller = Controller::for_stream(controller_instance_stream, instance_store)
        .watches_shared_stream(template_subscriber, move |template| {
            let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
            info!(
                template_name = tmpl_name,
                "CTFTemplate updated, evaluating CTFInstances requiring upgrade"
            );
            instance_cache
                .instances_to_sync(&template)
                .into_iter()
                .map(|inst| ObjectRef::from_obj(&*inst))
                .collect::<Vec<_>>()
        })
        .owns_stream(service_stream)
        .owns_stream(replica_set_stream)
        .owns_stream(tls_route_stream)
        .run(instance::reconcile, instance::error_policy, context.clone())
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
        });

    let template_ctx = context.clone();
    let template_controller = Controller::for_stream(template_controller_stream, template_store)
        .run(
            crate::controller::template::reconcile_template,
            crate::controller::template::error_policy,
            template_ctx,
        )
        .for_each(|res| async {
            match res {
                Ok((object, _action)) => {
                    info!(name = %object.name, "Successfully reconciled CTFTemplate");
                }
                Err(err) => {
                    let err_msg = err.to_string();
                    if err_msg.contains("not found") || err_msg.contains("NotFound") {
                        tracing::debug!(%err, "Template deleted before reconciliation completed");
                    } else {
                        warn!(%err, "Template controller error occurred");
                    }
                }
            }
        });

    tokio::join!(instance_controller, template_controller);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::dummy_context;
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[tokio::test]
    async fn test_handle_service_port_map_event_binds_and_unbinds() {
        let (_store, ctx) = dummy_context();
        let port_map = ctx.port_map.as_ref().unwrap();

        let lb_svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-lb-web".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                load_balancer_class: Some(crate::utils::CARDINAL_LB_CLASS.to_string()),
                ports: Some(vec![ServicePort {
                    name: Some("pwn".to_string()),
                    port: 20005,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Standard non-dummy service should be ignored
        let standard_svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-svc-web".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: 20006,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        handle_service_port_map_event(&Event::Apply(standard_svc), port_map);
        assert_eq!(port_map.get_key(Port::Tcp(20006)), None);

        // Dummy LB service should bind
        handle_service_port_map_event(&Event::Apply(lb_svc.clone()), port_map);
        let key = port_map.get_key(Port::Tcp(20005));
        assert_eq!(key, Some(ResourceKey::new("default", "chal-1", "pwn")));

        // Deleting dummy LB service should unbind
        handle_service_port_map_event(&Event::Delete(lb_svc), port_map);
        assert_eq!(port_map.get_key(Port::Tcp(20005)), None);
    }

    #[tokio::test]
    async fn test_handle_service_port_map_event_init_clears() {
        let (_store, ctx) = dummy_context();
        let port_map = ctx.port_map.as_ref().unwrap();

        let lb_svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-lb-web".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                load_balancer_class: Some(crate::utils::CARDINAL_LB_CLASS.to_string()),
                ports: Some(vec![ServicePort {
                    name: Some("pwn".to_string()),
                    port: 20005,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        handle_service_port_map_event(&Event::InitApply(lb_svc), port_map);
        assert!(port_map.get_key(Port::Tcp(20005)).is_some());

        handle_service_port_map_event(&Event::Init, port_map);
        assert_eq!(port_map.get_key(Port::Tcp(20005)), None);
    }

    #[tokio::test]
    async fn test_instances_lock_when_services_reallocating() {
        let (_store, ctx) = dummy_context();

        // Mark all auxiliary caches as initially ready
        ctx.caches.replica_sets.mark_ready();
        ctx.caches.services.mark_ready();
        ctx.caches.templates.mark_ready();
        ctx.caches.tls_routes.mark_ready();

        let gate = ReadyGate::from_caches(&ctx.caches);
        assert!(gate.is_ready(), "gate must be ready initially");

        // Services cache receives Event::Init (e.g. reconnection / re-list)
        ctx.caches.services.mark_unready();

        assert!(
            !gate.is_ready(),
            "gate must not be ready while services cache is re-syncing"
        );

        // Spawn a task that waits on the gate (simulating instance reconcile stream)
        let gate_waiter = gate.clone();
        let (unlocked_tx, mut unlocked_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            gate_waiter.wait().await;
            let _ = unlocked_tx.send(()).await;
        });

        // Verify the gate remains locked while services are being reloaded
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            unlocked_rx.try_recv().is_err(),
            "instance processing must be locked while services cache is re-syncing"
        );

        // Re-sync finishes: Event::InitDone arrives
        ctx.caches.services.mark_ready();

        // Verify gate is ready and waiter task unlocks
        assert!(gate.is_ready(), "gate must be ready after InitDone");
        let unlocked = tokio::time::timeout(Duration::from_secs(1), unlocked_rx.recv()).await;
        assert!(
            unlocked.is_ok(),
            "instance processing must resume once services sync finishes"
        );
    }
}

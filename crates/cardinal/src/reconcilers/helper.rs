use std::collections::HashSet;

use k8s_common::crd::{CTFInstance, CTFProxyRoute};
use kube::{
    Api, Resource,
    api::{ListParams, Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use crate::{
    Error,
    planners::Planner,
    reconcilers::template::ResolvedTemplate,
    routing::{RouteAllocator, RouteKey},
    utils::labels::{INSTANCE_LABEL, INSTANCE_NAMESPACE_LABEL, POD_LABEL, ROUTES_FINALIZER},
};

const PRUNE_CONCURRENCY_LIMIT: usize = 16;

/// Applies all planned child resources using Server-Side Apply and prunes orphans.
pub async fn apply_planner<P: Planner>(
    client: kube::Client,
    instance: &CTFInstance,
    template: &ResolvedTemplate,
) -> Result<(), Error> {
    let desired = P::plan(instance, template)?;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let api: Api<P::Resource> = Api::namespaced(client, ns);

    sync_resources(&api, instance_name, desired).await
}

/// Applies a list of desired resources using Server-Side Apply and prunes orphans.
pub async fn sync_resources<K>(
    api: &Api<K>,
    instance_name: &str,
    desired: Vec<K>,
) -> Result<(), Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    let patch_params = PatchParams::apply("cardinal").force();
    let mut desired_names = HashSet::new();

    for resource in desired {
        if let Some(name) = resource.meta().name.as_deref() {
            desired_names.insert(name.to_string());
            api.patch(name, &patch_params, &Patch::Apply(&resource))
                .await?;
        }
    }

    prune_orphaned_resources(api, instance_name, &desired_names).await?;
    Ok(())
}

/// Prunes orphaned child resources owned by `instance_name`.
pub async fn prune_orphaned_resources<K>(
    api: &Api<K>,
    instance_name: &str,
    desired_names: &HashSet<String>,
) -> Result<(), Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    let lp = ListParams::default().labels(&format!("{INSTANCE_LABEL}={instance_name}"));
    let list = api.list(&lp).await?;

    for existing in list {
        if let Some(name) = existing.meta().name.as_deref()
            && !desired_names.contains(name)
        {
            info!(name, "Orphaned child resource detected, deleting...");
            api.delete(name, &Default::default()).await?;
        }
    }

    Ok(())
}

/// Ensures the `aincrad.noctf.dev/routes` finalizer is attached to the CTFInstance.
pub async fn ensure_finalizer(client: kube::Client, instance: &CTFInstance) -> Result<(), Error> {
    let has_finalizer = instance
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.iter().any(|s| s == ROUTES_FINALIZER))
        .unwrap_or(false);

    if !has_finalizer {
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let instances: Api<CTFInstance> = Api::namespaced(client, ns);

        let patch = serde_json::json!({
            "metadata": {
                "finalizers": [ROUTES_FINALIZER]
            }
        });
        instances
            .patch(name, &PatchParams::default(), &Patch::Merge(patch))
            .await?;
    }
    Ok(())
}

/// Removes the `aincrad.noctf.dev/routes` finalizer from the CTFInstance.
pub async fn remove_finalizer(client: kube::Client, instance: &CTFInstance) -> Result<(), Error> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instances: Api<CTFInstance> = Api::namespaced(client, ns);

    let remaining_finalizers: Vec<String> = instance
        .metadata
        .finalizers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|f| *f != ROUTES_FINALIZER)
        .cloned()
        .collect();

    let patch = serde_json::json!({
        "metadata": {
            "finalizers": remaining_finalizers
        }
    });
    instances
        .patch(name, &PatchParams::default(), &Patch::Merge(patch))
        .await?;
    Ok(())
}

/// Applies cross-namespace CTFProxyRoute resources into the system namespace, deleting stale routes first.
pub async fn apply_proxy_routes(
    client: kube::Client,
    system_namespace: &str,
    instance: &CTFInstance,
    desired_routes: Vec<CTFProxyRoute>,
    allocator: &RouteAllocator,
) -> Result<(), Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(client, system_namespace);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let desired_names: HashSet<String> = desired_routes
        .iter()
        .filter_map(|r| r.meta().name.clone())
        .collect();

    // 1. Delete old/orphaned CTFProxyRoute resources FIRST before creating/updating new ones
    let lp = ListParams::default().labels(&format!(
        "{INSTANCE_LABEL}={instance_name},{INSTANCE_NAMESPACE_LABEL}={instance_ns}"
    ));
    let existing_list = api.list(&lp).await?;

    for existing in existing_list {
        if let Some(name) = existing.meta().name.as_deref()
            && !desired_names.contains(name)
        {
            info!(
                name,
                system_namespace, "Pruning stale CTFProxyRoute before applying new routes..."
            );
            api.delete(name, &Default::default()).await?;

            if let Ok(k8s_common::crd::ProxyRouteKey::Tcp(old_port)) =
                name.parse::<k8s_common::crd::ProxyRouteKey>()
                && let Some(pod_name) = existing
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(POD_LABEL))
            {
                let route_key = RouteKey::new(instance_ns, instance_name, pod_name);
                allocator.release_if_bound(&route_key, old_port);
            }
        }
    }

    // 2. Apply desired CTFProxyRoute resources via Server-Side Apply
    let patch_params = PatchParams::apply("cardinal").force();
    for route in desired_routes {
        if let Some(name) = route.meta().name.as_deref() {
            api.patch(name, &patch_params, &Patch::Apply(&route)).await?;
        }
    }

    Ok(())
}

/// Deletes all CTFProxyRoutes belonging to a CTFInstance across namespaces and removes finalizer.
pub async fn cleanup_instance_routes(
    client: kube::Client,
    system_namespace: &str,
    instance: &CTFInstance,
    allocator: Option<&RouteAllocator>,
) -> Result<(), Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(client.clone(), system_namespace);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let lp = ListParams::default().labels(&format!(
        "{INSTANCE_LABEL}={instance_name},{INSTANCE_NAMESPACE_LABEL}={instance_ns}"
    ));
    let list = api.list(&lp).await?;

    for route in list {
        if let Some(name) = route.meta().name.as_deref() {
            info!(
                name,
                system_namespace, "Deleting CTFProxyRoute on instance finalizer cleanup..."
            );
            let _ = api.delete(name, &Default::default()).await;

            if let Some(alloc) = allocator
                && let Some(pod_name) = route
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(POD_LABEL))
            {
                let route_key = RouteKey::new(instance_ns, instance_name, pod_name);
                alloc.release(&route_key);
            }
        }
    }

    remove_finalizer(client, instance).await?;
    Ok(())
}

/// Prunes dangling CTFProxyRoute resources in the system namespace that do not belong to any active CTFInstance.
pub async fn prune_unreferenced_proxy_routes(
    client: kube::Client,
    system_namespace: &str,
    live_instances: &HashSet<(String, String)>,
    allocator: &RouteAllocator,
) -> Result<usize, Error> {
    use futures::StreamExt;

    let api: Api<CTFProxyRoute> = Api::namespaced(client, system_namespace);
    let routes = api.list(&Default::default()).await?;

    let orphaned_routes: Vec<_> = routes
        .into_iter()
        .filter(|route| {
            if let Some(labels) = route.metadata.labels.as_ref() {
                let instance_name = labels.get(INSTANCE_LABEL);
                let instance_ns = labels
                    .get(INSTANCE_NAMESPACE_LABEL)
                    .map(|s| s.as_str())
                    .unwrap_or("default");

                match instance_name {
                    Some(inst) => {
                        !live_instances.contains(&(instance_ns.to_string(), inst.to_string()))
                    }
                    None => true,
                }
            } else {
                true
            }
        })
        .collect();

    let total_orphans = orphaned_routes.len();
    if total_orphans == 0 {
        return Ok(0);
    }

    info!(
        total_orphans,
        system_namespace, "Pruning dangling CTFProxyRoutes in parallel..."
    );

    let results: Vec<Result<(), Error>> = futures::stream::iter(orphaned_routes)
        .map(|route| {
            let api = api.clone();
            let system_ns = system_namespace.to_string();
            async move {
                if let Some(name) = route.meta().name.as_deref() {
                    info!(
                        name,
                        system_namespace = %system_ns,
                        "Pruning dangling CTFProxyRoute..."
                    );
                    api.delete(name, &Default::default()).await?;

                    if let Some(labels) = route.metadata.labels.as_ref()
                        && let (Some(inst), Some(pod)) =
                            (labels.get(INSTANCE_LABEL), labels.get(POD_LABEL))
                    {
                        let instance_ns = labels
                            .get(INSTANCE_NAMESPACE_LABEL)
                            .map(|s| s.as_str())
                            .unwrap_or("default");
                        let route_key = RouteKey::new(instance_ns, inst, pod);
                        allocator.release(&route_key);
                    }
                }
                Ok(())
            }
        })
        .buffer_unordered(PRUNE_CONCURRENCY_LIMIT)
        .collect()
        .await;

    for res in results {
        res?;
    }

    Ok(total_orphans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::planners::ReplicaSetPlanner;
    use crate::routing::PortsStore;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client, dummy_resolved_template};
    use k8s_common::PortRange;
    use k8s_openapi::api::apps::v1::ReplicaSet;

    #[tokio::test]
    async fn test_apply_planner_success() {
        let client = dummy_kube_client();
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);

        let res = apply_planner::<ReplicaSetPlanner>(client, &instance, &template).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_prune_orphaned_resources() {
        let client = dummy_kube_client();
        let api: Api<ReplicaSet> = Api::namespaced(client, "default");
        let mut desired = HashSet::new();
        desired.insert("chal-1-web".to_string());

        let res = prune_orphaned_resources(&api, "chal-1", &desired).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_and_remove_finalizer() {
        let client = dummy_kube_client();
        let mut instance = dummy_instance("chal-1", None);

        assert!(ensure_finalizer(client.clone(), &instance).await.is_ok());

        instance.metadata.finalizers = Some(vec![ROUTES_FINALIZER.to_string()]);
        assert!(remove_finalizer(client, &instance).await.is_ok());
    }

    #[tokio::test]
    async fn test_apply_and_cleanup_proxy_routes() {
        let client = dummy_kube_client();
        let instance = dummy_instance("chal-1", None);
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports, "seed", "c.sk8.dog", 4433);

        let res = apply_proxy_routes(
            client.clone(),
            "aincrad-system",
            &instance,
            vec![],
            &allocator,
        )
        .await;
        assert!(res.is_ok());

        let clean_res =
            cleanup_instance_routes(client, "aincrad-system", &instance, Some(&allocator)).await;
        assert!(clean_res.is_ok());
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes() {
        let client = dummy_kube_client();
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports, "seed", "c.sk8.dog", 4433);
        let mut live = HashSet::new();
        live.insert(("default".to_string(), "chal-1".to_string()));

        let res = prune_unreferenced_proxy_routes(
            client,
            "aincrad-system",
            &live,
            &allocator,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_port_and_target_mutation_lifecycle() {
        use axum::body::Body;
        use axum::http::{Response, StatusCode};
        use k8s_common::crd::{
            CTFProxyRoute, CTFProxyRouteSpec, CTFRouteBackend, CTFRouteSpec, CTFRouteSpecTCP,
            CTFRouteSpecTLS,
        };
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use tower::service_fn;

        let instance = dummy_instance("chal-1", None);
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports.clone(), "seed", "c.sk8.dog", 4433);
        let route_key = RouteKey::new("default", "chal-1", "pwn");

        // --- Scenario A: Fixed(20001) -> Fixed(20002) ---
        allocator.sync(&route_key, 20001);
        assert_eq!(ports.active_ports(), vec![20001]);

        let spec_fixed_2 = CTFRouteSpec {
            tcp: Some(CTFRouteSpecTCP { port: Some(20002) }),
            backend: CTFRouteBackend {
                service: "pwn".into(),
                port: 1337,
            },
            ..Default::default()
        };
        allocator.allocate(&route_key, &spec_fixed_2).unwrap();
        assert_eq!(ports.active_ports(), vec![20002]);

        // Mock client having old route p20001 in cluster
        let mock_service = service_fn(|req: axum::http::Request<kube::client::Body>| async move {
            let path = req.uri().path();
            if req.method() == axum::http::Method::GET && path.contains("ctfproxyroutes") {
                let existing_route = serde_json::json!({
                    "apiVersion": "aincrad.noctf.dev/v1",
                    "kind": "CTFProxyRouteList",
                    "metadata": {},
                    "items": [{
                        "apiVersion": "aincrad.noctf.dev/v1",
                        "kind": "CTFProxyRoute",
                        "metadata": {
                            "name": "p20001",
                            "namespace": "aincrad-system",
                            "labels": {
                                "aincrad.noctf.dev/instance": "chal-1",
                                "aincrad.noctf.dev/instance-namespace": "default",
                                "aincrad.noctf.dev/pod": "pwn"
                            }
                        },
                        "spec": {
                            "backend": "chal-1-pwn.default.svc.cluster.local:1337"
                        }
                    }]
                });
                let body_str = serde_json::to_string(&existing_route).unwrap();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(body_str))
                        .unwrap(),
                )
            } else {
                let patched_route = serde_json::json!({
                    "apiVersion": "aincrad.noctf.dev/v1",
                    "kind": "CTFProxyRoute",
                    "metadata": {
                        "name": "p20002",
                        "namespace": "aincrad-system"
                    },
                    "spec": {
                        "backend": "chal-1-pwn.default.svc.cluster.local:1337"
                    }
                });
                let body_str = serde_json::to_string(&patched_route).unwrap();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(body_str))
                    .unwrap())
            }
        });

        let client = kube::Client::new(mock_service, "default");
        let desired_route_2 = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20002".to_string()),
                namespace: Some("aincrad-system".to_string()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "chal-1-pwn.default.svc.cluster.local:1337".to_string(),
                ..Default::default()
            },
        };

        apply_proxy_routes(
            client,
            "aincrad-system",
            &instance,
            vec![desired_route_2],
            &allocator,
        )
        .await
        .unwrap();

        // 20002 remains active in PortsStore after pruning p20001
        assert_eq!(ports.active_ports(), vec![20002]);

        use k8s_common::crd::ProxyRouteKey;

        // --- Scenario B: Fixed(20002) -> Auto(0) ---
        let spec_auto = CTFRouteSpec {
            tcp: Some(CTFRouteSpecTCP { port: None }),
            backend: CTFRouteBackend {
                service: "pwn".into(),
                port: 1337,
            },
            ..Default::default()
        };
        let allocated_auto = allocator.allocate(&route_key, &spec_auto).unwrap();
        assert!(matches!(
            allocated_auto.proxy_key,
            ProxyRouteKey::Tcp(port) if (30000..=30010).contains(&port)
        ));
        let auto_p = match allocated_auto.proxy_key {
            ProxyRouteKey::Tcp(port) => port,
            _ => unreachable!(),
        };
        assert_eq!(ports.active_ports(), vec![auto_p]);

        // --- Scenario C: TCP -> TLS ---
        let spec_tls = CTFRouteSpec {
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".into()),
            }),
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 80,
            },
            ..Default::default()
        };
        let allocated_tls = allocator.allocate(&route_key, &spec_tls).unwrap();
        assert!(matches!(allocated_tls.proxy_key, ProxyRouteKey::Route(_)));

        // Releasing previous auto port frees it completely
        assert!(allocator.release_if_bound(&route_key, auto_p));
        assert!(ports.active_ports().is_empty());
    }
}

use std::collections::HashSet;

use k8s_common::{
    ROUTE_LABEL,
    crd::{CTFInstance, CTFProxyRoute},
};
use kube::{
    Api, Resource,
    api::{ListParams, Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{info, warn};

use crate::{
    Context, Error,
    cache::ResourceKey,
    planners::Planner,
    reconcilers::template::ResolvedTemplate,
    routing::RouteAllocator,
    utils::labels::{INSTANCE_LABEL, INSTANCE_NAMESPACE_LABEL, POD_LABEL, ROUTES_FINALIZER},
};

const PRUNE_CONCURRENCY_LIMIT: usize = 16;

/// Applies all planned child resources using Server-Side Apply and prunes orphans.
pub async fn apply_planner<P: Planner>(
    client: kube::Client,
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
) -> Result<(), Error> {
    let desired = P::plan(instance, template, ctx)?;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let api: Api<P::Resource> = Api::namespaced(client, ns);

    let desired_names = sync_resources(&api, P::KIND, desired).await?;
    if P::PRUNE_ORPHANS {
        prune_orphaned_resources(&api, instance_name, &desired_names).await
    } else {
        Ok(())
    }
}

/// Applies a list of desired resources using Server-Side Apply and prunes orphans.
pub async fn sync_resources<K>(
    api: &Api<K>,
    kind: &'static str,
    desired: Vec<K>,
) -> Result<HashSet<String>, Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    let patch_params = PatchParams::apply("cardinal").force();
    let mut desired_names = HashSet::new();

    for resource in desired {
        if let Some(name) = resource.meta().name.as_deref() {
            desired_names.insert(name.to_string());
            api.patch(name, &patch_params, &Patch::Apply(&resource))
                .await
                .map_err(|e| Error::ApplyResource {
                    kind,
                    name: name.to_string(),
                    source: Box::new(e),
                })?;
        }
    }
    Ok(desired_names)
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
                let route_key = ResourceKey::new(instance_ns, instance_name, pod_name);
                allocator.release_if_bound(&route_key, old_port);
            }
        }
    }

    // 2. Apply desired CTFProxyRoute resources via Server-Side Apply
    let patch_params = PatchParams::apply("cardinal").force();
    for route in desired_routes {
        if let Some(name) = route.meta().name.as_deref() {
            api.patch(name, &patch_params, &Patch::Apply(&route))
                .await
                .map_err(|e| Error::ApplyResource {
                    kind: "CTFProxyRoute",
                    name: name.to_string(),
                    source: Box::new(e),
                })?;
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
            match api.delete(name, &Default::default()).await {
                Ok(_) => {}
                Err(kube::Error::Api(ref e)) if e.code == 404 => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    if let Some(alloc) = allocator {
        alloc.release_instance(instance_ns, instance_name);
    }

    remove_finalizer(client, instance).await?;
    Ok(())
}

/// Deletes a batch of CTFProxyRoutes in parallel, releasing their allocator mappings.
pub async fn delete_proxy_routes_batch(
    api: &Api<CTFProxyRoute>,
    system_namespace: &str,
    routes: Vec<CTFProxyRoute>,
    allocator: &RouteAllocator,
) -> (Vec<CTFProxyRoute>, Option<Error>) {
    use futures::StreamExt;

    let results: Vec<Result<(), (CTFProxyRoute, Error)>> = futures::stream::iter(routes)
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

                    match api.delete(name, &Default::default()).await {
                        Ok(_) => {}
                        Err(kube::Error::Api(ref e)) if e.code == 404 => {}
                        Err(err) => return Err((route, err.into())),
                    }

                    if let Some(labels) = route.metadata.labels.as_ref()
                        && let (Some(inst), Some(pod)) =
                            (labels.get(INSTANCE_LABEL), labels.get(ROUTE_LABEL))
                    {
                        let instance_ns = labels
                            .get(INSTANCE_NAMESPACE_LABEL)
                            .map(|s| s.as_str())
                            .unwrap_or("default");
                        let route_key = ResourceKey::new(instance_ns, inst, pod);
                        allocator.release(&route_key);
                    }
                }
                Ok(())
            }
        })
        .buffer_unordered(PRUNE_CONCURRENCY_LIMIT)
        .collect()
        .await;

    let mut failed = Vec::new();
    let mut last_error = None;
    for res in results {
        if let Err((route, err)) = res {
            failed.push(route);
            last_error = Some(err);
        }
    }

    (failed, last_error)
}

/// Prunes dangling CTFProxyRoute resources in the system namespace that do not belong to any active CTFInstance.
pub async fn prune_unreferenced_proxy_routes(
    client: kube::Client,
    system_namespace: &str,
    live_instances: &HashSet<(String, String)>,
    allocator: &RouteAllocator,
) -> Result<usize, Error> {
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

    let mut pending = orphaned_routes;
    let mut delay = std::time::Duration::from_millis(200);
    let mut attempts = 3;

    while !pending.is_empty() && attempts > 0 {
        let (failed, last_err) =
            delete_proxy_routes_batch(&api, system_namespace, pending, allocator).await;
        if failed.is_empty() {
            return Ok(total_orphans);
        }

        attempts -= 1;
        pending = failed;

        if attempts > 0 {
            warn!(
                remaining = pending.len(),
                attempts_left = attempts,
                "Some orphaned CTFProxyRoutes failed to delete, retrying in {:?}...",
                delay
            );
            tokio::time::sleep(delay).await;
            delay *= 2;
        } else if let Some(err) = last_err {
            return Err(err);
        }
    }

    Ok(total_orphans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planners::ReplicaSetPlanner;
    use crate::test_utils::tests::{
        dummy_context, dummy_instance, dummy_kube_client, dummy_resolved_template,
    };

    #[tokio::test]
    async fn test_apply_planner_success() {
        let client = dummy_kube_client();
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        let (_store, ctx) = dummy_context();

        let res = apply_planner::<ReplicaSetPlanner>(client, &instance, &template, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_planner_failure_returns_apply_resource_error() {
        use axum::body::Body;
        use axum::http::{Response, StatusCode};
        use tower::service_fn;

        let mock_service = service_fn(|_req: axum::http::Request<kube::client::Body>| async move {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(
                        r#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"webhook rejected","code":500}"#,
                    ))
                    .unwrap(),
            )
        });

        let client = kube::Client::new(mock_service, "default");
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        let (_store, ctx) = dummy_context();

        let res = apply_planner::<ReplicaSetPlanner>(client, &instance, &template, &ctx).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            Error::ApplyResource { kind, name, source } => {
                assert_eq!(kind, "ReplicaSet");
                assert!(name.starts_with("chal-1-web"));
                assert!(source.to_string().contains("webhook rejected"));
            }
            other => panic!("Expected ApplyResource, got: {:?}", other),
        }
    }

    // ... other tests unchanged ...
}

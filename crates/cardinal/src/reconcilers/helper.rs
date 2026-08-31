use std::collections::HashSet;

use k8s_common::crd::{CTFInstance, CTFProxyRoute};
use kube::{
    Api, Resource,
    api::{Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{info, warn};

use crate::{
    Context, Error, cache::ResourceCache, planners::Planner,
    reconcilers::template::ResolvedTemplate, utils::labels::ROUTES_FINALIZER,
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
    let api: Api<P::Resource> = Api::namespaced(client, ns);

    let desired_names = sync_resources(&api, P::KIND, desired).await?;
    if let Some(existing_names) = P::cached_names(instance, ctx) {
        prune_orphaned_resources(&api, &desired_names, existing_names).await?;
    }
    Ok(())
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

/// Deletes any of `existing_names` that are not in `desired_names`.
pub async fn prune_orphaned_resources<K>(
    api: &Api<K>,
    desired_names: &HashSet<String>,
    existing_names: Vec<String>,
) -> Result<(), Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    for name in existing_names {
        if !desired_names.contains(&name) {
            info!(name, "Orphaned child resource detected, deleting...");
            api.delete(&name, &Default::default()).await?;
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

/// Applies cross-namespace CTFProxyRoute resources into the system namespace,
/// pruning stale routes recorded in the live cache first.
///
/// The proxy-route watcher keeps the cache (and the allocator) in sync with the
/// cluster, so this only lists the cluster to apply/delete; orphan detection
/// reads the cache rather than re-listing every reconcile.
pub async fn apply_proxy_routes(
    ctx: &Context,
    instance: &CTFInstance,
    desired_routes: Vec<CTFProxyRoute>,
) -> Result<(), Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(ctx.client.clone(), &ctx.system_namespace);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let desired_names: HashSet<String> = desired_routes
        .iter()
        .filter_map(|r| r.meta().name.clone())
        .collect();

    // 1. Delete stale routes the cache saw but the plan no longer wants.
    let stale = ctx
        .caches
        .proxy_routes
        .names(instance_ns, instance_name)
        .into_iter()
        .filter(|name| !desired_names.contains(name));
    for name in stale {
        info!(
            name,
            system_namespace = %ctx.system_namespace,
            "Pruning stale CTFProxyRoute before applying new routes..."
        );
        match api.delete(&name, &Default::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(ref e)) if e.code == 404 => {}
            Err(e) => return Err(e.into()),
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

/// Deletes all CTFProxyRoutes belonging to a CTFInstance (found via the live
/// cache) and removes the routes finalizer.
///
/// The watcher releases allocator bindings as the deleted routes stream back
/// through; no manual release is needed here.
pub async fn cleanup_instance_routes(ctx: &Context, instance: &CTFInstance) -> Result<(), Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(ctx.client.clone(), &ctx.system_namespace);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let names = ctx.caches.proxy_routes.names(instance_ns, instance_name);
    for name in names {
        info!(
            name,
            system_namespace = %ctx.system_namespace,
            "Deleting CTFProxyRoute on instance finalizer cleanup..."
        );
        match api.delete(&name, &Default::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(ref e)) if e.code == 404 => {}
            Err(e) => return Err(e.into()),
        }
    }

    remove_finalizer(ctx.client.clone(), instance).await?;
    Ok(())
}

/// Deletes a batch of CTFProxyRoute names in parallel. Bindings are released
/// by the watcher when the deletions stream back as `Delete` events.
pub async fn delete_proxy_routes_batch(
    api: &Api<CTFProxyRoute>,
    names: Vec<String>,
) -> (Vec<String>, Option<Error>) {
    use futures::StreamExt;

    let results: Vec<Result<(), (String, Error)>> = futures::stream::iter(names)
        .map(|name| {
            let api = api.clone();
            async move {
                info!(name, "Pruning dangling CTFProxyRoute...");
                match api.delete(&name, &Default::default()).await {
                    Ok(_) => Ok(()),
                    Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(()),
                    Err(err) => Err((name, err.into())),
                }
            }
        })
        .buffer_unordered(PRUNE_CONCURRENCY_LIMIT)
        .collect()
        .await;

    let mut failed = Vec::new();
    let mut last_error = None;
    for res in results {
        if let Err((name, err)) = res {
            failed.push(name);
            last_error = Some(err);
        }
    }

    (failed, last_error)
}

/// Prunes dangling CTFProxyRoute resources in the system namespace that do not
/// belong to any active CTFInstance, driven entirely by the live cache.
pub async fn prune_unreferenced_proxy_routes(
    client: kube::Client,
    system_namespace: &str,
    proxy_routes: &ResourceCache<CTFProxyRoute>,
    live_instances: &HashSet<(String, String)>,
) -> Result<usize, Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(client, system_namespace);

    let orphaned_names: Vec<String> = proxy_routes
        .all_entries()
        .into_iter()
        .filter(|entry| {
            !live_instances.contains(&(entry.key.namespace.clone(), entry.key.instance.clone()))
        })
        .map(|entry| entry.name)
        .collect();

    let total_orphans = orphaned_names.len();
    if total_orphans == 0 {
        return Ok(0);
    }

    info!(
        total_orphans,
        system_namespace, "Pruning dangling CTFProxyRoutes in parallel..."
    );

    let mut pending = orphaned_names;
    let mut delay = std::time::Duration::from_millis(200);
    let mut attempts = 3;

    while !pending.is_empty() && attempts > 0 {
        let (failed, last_err) = delete_proxy_routes_batch(&api, pending).await;
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
        dummy_context, dummy_ctx, dummy_instance, dummy_kube_client, dummy_resolved_template,
        recording_kube_client,
    };
    use k8s_common::crd::CTFProxyRouteSpec;
    use k8s_openapi::api::apps::v1::ReplicaSet;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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

    fn proxy_route(name: &str, instance: &str, resource: &str) -> CTFProxyRoute {
        CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("aincrad-system".to_string()),
                labels: Some(crate::btreemap! {
                    crate::utils::labels::NAMESPACE_LABEL => "default",
                    crate::utils::labels::INSTANCE_LABEL => instance,
                    crate::utils::labels::RESOURCE_LABEL => resource,
                }),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "web.default.svc.cluster.local:80".to_string(),
                policy: Default::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_prune_orphaned_resources_deletes_only_non_desired() {
        let (client, log) = recording_kube_client();
        let api: Api<ReplicaSet> = Api::all(client);

        let desired: HashSet<String> = ["keep-a".into(), "keep-b".into()].into_iter().collect();
        // Existing cache names: one kept, one orphaned.
        let existing = vec!["keep-a".to_string(), "stale-1".to_string()];

        prune_orphaned_resources(&api, &desired, existing)
            .await
            .expect("prune should succeed");
        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("stale-1")),
            "orphaned 'stale-1' must be deleted"
        );
        assert!(
            !log.iter()
                .any(|s| s.contains("DELETE") && s.contains("keep-a")),
            "desired 'keep-a' must not be deleted"
        );
    }

    #[tokio::test]
    async fn test_prune_orphaned_resources_deletes_nothing_when_desired_all() {
        let (client, log) = recording_kube_client();
        let api: Api<ReplicaSet> = Api::all(client);

        let desired: HashSet<String> = ["only".into()].into_iter().collect();
        prune_orphaned_resources(&api, &desired, vec!["only".to_string()])
            .await
            .expect("prune should succeed");
        assert_eq!(
            log.lock().unwrap().len(),
            0,
            "no deletes should issue when everything is desired"
        );
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_prunes_stale_from_cache() {
        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_ctx(client, vec![]);

        let instance = dummy_instance("chal-1", None);
        // Seed a stale route in the cache that the plan will no longer produce.
        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(proxy_route(
                "p30005", "chal-1", "web",
            )));

        // Desired now wants only rwhoami.
        let desired = vec![proxy_route("rwhoami", "chal-1", "main")];
        apply_proxy_routes(&ctx, &instance, desired)
            .await
            .expect("apply should succeed");

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("p30005")),
            "stale cached route must be deleted first"
        );
        assert!(
            log.iter()
                .any(|s| s.contains("PATCH") && s.contains("rwhoami")),
            "desired route must be applied via SSA"
        );
        assert!(
            !log.iter()
                .any(|s| s.contains("DELETE") && s.contains("rwhoami")),
            "desired route must not be deleted"
        );
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_no_stale_no_delete() {
        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_ctx(client, vec![]);
        let instance = dummy_instance("chal-1", None);

        let desired = vec![proxy_route("rwhoami", "chal-1", "main")];
        apply_proxy_routes(&ctx, &instance, desired)
            .await
            .expect("apply should succeed");

        let log = log.lock().unwrap();
        assert!(
            !log.iter().any(|s| s.starts_with("DELETE")),
            "an empty cache must not produce any deletes"
        );
        assert!(
            log.iter()
                .any(|s| s.contains("PATCH") && s.contains("rwhoami")),
            "desired route must still be applied"
        );
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes_diffs_against_live_instances() {
        use crate::cache::ResourceCache;

        let (client, log) = recording_kube_client();
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(proxy_route(
            "p30001", "chal-1", "web",
        )));
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(proxy_route(
            "p30002",
            "orphan-chal",
            "pwn",
        )));

        let live: std::collections::HashSet<(String, String)> =
            [("default".to_string(), "chal-1".to_string())]
                .into_iter()
                .collect();

        let pruned =
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live)
                .await
                .expect("prune should succeed");
        assert_eq!(pruned, 1, "only the orphaned route should be pruned");

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("p30002")),
            "orphan route must be deleted"
        );
        assert!(
            !log.iter()
                .any(|s| s.contains("DELETE") && s.contains("p30001")),
            "live instance's route must survive"
        );
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes_zero_when_all_live() {
        use crate::cache::ResourceCache;

        let (client, log) = recording_kube_client();
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(proxy_route(
            "p30001", "chal-1", "web",
        )));

        let live: std::collections::HashSet<(String, String)> =
            [("default".to_string(), "chal-1".to_string())]
                .into_iter()
                .collect();

        let pruned =
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live)
                .await
                .expect("prune should succeed");
        assert_eq!(pruned, 0);
        assert_eq!(
            log.lock().unwrap().len(),
            0,
            "nothing to prune when every route's instance is live"
        );
    }
}

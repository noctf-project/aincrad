use std::collections::HashSet;

use k8s_common::crd::{CTFInstance, CTFProxyRoute};
use kube::{
    Api, Resource,
    api::{DeleteParams, ListParams, Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{info, warn};

use crate::{
    Context, Error,
    cache::ResourceCache,
    planners::Planner,
    reconcilers::template::ResolvedTemplate,
    utils::labels::{
        INSTANCE_GENERATION_LABEL, INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE,
        NAMESPACE_LABEL, ROUTES_FINALIZER,
    },
};

const PRUNE_CONCURRENCY_LIMIT: usize = 16;

/// Applies all planned child resources using Server-Side Apply and prunes stale generations.
pub async fn apply_planner<P: Planner>(
    api: Api<P::Resource>,
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
) -> Result<Vec<P::Resource>, Error> {
    let mut desired = P::plan(instance, template, ctx)?;
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let current_gen = instance.metadata.generation.unwrap_or(1);

    let ns_str = instance_ns.to_string();
    let name_str = instance_name.to_string();
    let gen_str = current_gen.to_string();

    for resource in &mut desired {
        let meta = resource.meta_mut();
        meta.managed_fields = None;
        if meta.namespace.as_deref() == instance.metadata.namespace.as_deref() {
            meta.owner_references = instance.controller_owner_ref(&()).map(|o| vec![o]);
        }
        let labels = meta.labels.get_or_insert_with(Default::default);
        labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
        labels.insert(NAMESPACE_LABEL.to_string(), ns_str.clone());
        labels.insert(INSTANCE_LABEL.to_string(), name_str.clone());
        labels.insert(INSTANCE_GENERATION_LABEL.to_string(), gen_str.clone());
    }

    let applied = P::apply(&api, desired, ctx).await?;

    let desired_names: HashSet<String> = applied
        .iter()
        .filter_map(|r| r.meta().name.clone())
        .collect();

    prune_dangling_children::<P>(&api, instance, &desired_names, ctx).await?;

    Ok(applied)
}

/// Prunes any child resources of kind `P::KIND` that are no longer desired.
async fn prune_dangling_children<P: Planner>(
    api: &Api<P::Resource>,
    instance: &CTFInstance,
    desired_names: &HashSet<String>,
    ctx: &Context,
) -> Result<(), Error> {
    let mut dangling = HashSet::new();

    if let Some(last_children) = instance
        .status
        .as_ref()
        .and_then(|s| s.children.get(P::KIND))
    {
        for name in last_children {
            if !desired_names.contains(name) {
                dangling.insert(name.clone());
            }
        }
    }

    if let Some(cached_names) = P::cached_names(instance, ctx) {
        for name in cached_names {
            if !desired_names.contains(&name) {
                dangling.insert(name);
            }
        }
    }

    for name in dangling {
        info!(name = %name, kind = P::KIND, "Pruning orphaned child resource...");
        match api.delete(&name, &Default::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {}
            Err(e) => {
                return Err(Error::ApplyResource {
                    kind: P::KIND,
                    name,
                    source: Box::new(e),
                });
            }
        }
    }

    Ok(())
}

/// Applies a list of desired resources using Server-Side Apply.
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

/// Deletes all CTFProxyRoutes belonging to a CTFInstance using label selection
/// and removes the routes finalizer.
pub async fn cleanup_instance_routes(ctx: &Context, instance: &CTFInstance) -> Result<(), Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(ctx.client.clone(), &ctx.system_namespace);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let delete_lp = ListParams::default().labels(&format!(
        "{NAMESPACE_LABEL}={instance_ns},{INSTANCE_LABEL}={instance_name}"
    ));
    match api
        .delete_collection(&DeleteParams::default(), &delete_lp)
        .await
    {
        Ok(_) => {}
        Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {}
        Err(e) => {
            return Err(Error::ApplyResource {
                kind: "CTFProxyRoute",
                name: format!("{instance_name} (routes cleanup)"),
                source: Box::new(e),
            });
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
/// belong to any active CTFInstance in the managed namespace (or across all namespaces if none specified).
pub async fn prune_unreferenced_proxy_routes(
    client: kube::Client,
    system_namespace: &str,
    proxy_routes: &ResourceCache<CTFProxyRoute>,
    live_instances: &HashSet<(String, String)>,
    managed_namespace: Option<&str>,
) -> Result<usize, Error> {
    let api: Api<CTFProxyRoute> = Api::namespaced(client, system_namespace);

    let orphaned_names: Vec<String> = proxy_routes
        .all_entries()
        .into_iter()
        .filter(|entry| {
            // Static or system routes without a tenant namespace must not be pruned.
            if entry.key.namespace.is_empty() {
                return false;
            }
            if let Some(target_ns) = managed_namespace
                && entry.key.namespace != target_ns
            {
                return false;
            }
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
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[tokio::test]
    async fn test_apply_planner_success() {
        let client = dummy_kube_client();
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        let (_store, ctx) = dummy_context();

        let api = Api::namespaced(client, "default");
        let res = apply_planner::<ReplicaSetPlanner>(api, &instance, &template, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_planner_prunes_stale_child_by_name() {
        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_context();

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: std::collections::BTreeMap::from([(
                "ReplicaSet".to_string(),
                vec!["chal-1-web-OLDHASH".to_string()],
            )]),
            ..Default::default()
        });
        let template = dummy_resolved_template(1);

        let api = Api::namespaced(client, "default");
        apply_planner::<ReplicaSetPlanner>(api, &instance, &template, &ctx)
            .await
            .expect("apply succeeds");

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("PATCH") && s.contains("chal-1-web")),
            "current generation must be patched"
        );
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("chal-1-web-OLDHASH")),
            "stale child must be pruned by name"
        );
    }

    #[tokio::test]
    async fn test_apply_planner_skips_prune_on_generation_one() {
        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_context();

        let mut instance = dummy_instance("chal-1", None);
        instance.metadata.generation = Some(1);
        let template = dummy_resolved_template(1);

        let api = Api::namespaced(client, "default");
        apply_planner::<ReplicaSetPlanner>(api, &instance, &template, &ctx)
            .await
            .expect("apply succeeds");

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("PATCH") && s.contains("chal-1-web")),
            "current generation must be patched"
        );
        assert!(
            !log.iter().any(|s| s.contains("DELETE")),
            "pruning must be skipped on generation one"
        );
    }

    #[tokio::test]
    async fn test_apply_planner_prunes_cached_orphan_not_in_status() {
        use k8s_openapi::api::apps::v1::ReplicaSet;
        use kube::runtime::watcher::Event;

        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_context();

        let mut zombie_rs = ReplicaSet::default();
        zombie_rs.metadata.name = Some("chal-1-web-ZOMBIE".to_string());
        zombie_rs.metadata.namespace = Some("default".to_string());
        zombie_rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL.to_string() => "default".to_string(),
            crate::utils::labels::INSTANCE_LABEL.to_string() => "chal-1".to_string(),
            crate::utils::labels::RESOURCE_LABEL.to_string() => "web".to_string(),
        });
        ctx.caches.replica_sets.handle(&Event::Apply(zombie_rs));

        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);

        let api = Api::namespaced(client, "default");
        apply_planner::<ReplicaSetPlanner>(api, &instance, &template, &ctx)
            .await
            .expect("apply succeeds");

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("chal-1-web-ZOMBIE")),
            "cached orphan missing from status must be pruned"
        );
        assert!(
            !log.iter()
                .any(|s| s.contains("DELETE") && !s.contains("chal-1-web-ZOMBIE")),
            "desired child must never be deleted"
        );
    }

    #[tokio::test]
    async fn test_apply_planner_steady_state_skips_pruning() {
        use k8s_openapi::api::apps::v1::ReplicaSet;
        use kube::runtime::watcher::Event;

        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_context();

        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);

        let desired = ReplicaSetPlanner::plan(&instance, &template, &ctx).unwrap();
        let desired_name = desired[0].metadata.name.clone().unwrap();

        let mut synced_instance = instance.clone();
        synced_instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: std::collections::BTreeMap::from([(
                "ReplicaSet".to_string(),
                vec![desired_name.clone()],
            )]),
            ..Default::default()
        });

        let mut rs = ReplicaSet::default();
        rs.metadata.name = Some(desired_name.clone());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL.to_string() => "default".to_string(),
            crate::utils::labels::INSTANCE_LABEL.to_string() => "chal-1".to_string(),
            crate::utils::labels::RESOURCE_LABEL.to_string() => "web".to_string(),
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs));

        let api = Api::namespaced(client, "default");
        apply_planner::<ReplicaSetPlanner>(api, &synced_instance, &template, &ctx)
            .await
            .expect("apply succeeds");

        let log = log.lock().unwrap();
        assert!(
            !log.iter().any(|s| s.contains("DELETE")),
            "steady state must not issue any delete calls"
        );
    }

    #[tokio::test]
    async fn test_cleanup_instance_routes_uses_label_selector() {
        let (client, log) = recording_kube_client();
        let (_store, ctx) = dummy_ctx(client, vec![]);

        let instance = dummy_instance("chal-1", None);
        cleanup_instance_routes(&ctx, &instance)
            .await
            .expect("cleanup succeeds");

        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|s| s.contains("DELETE")
                && s.contains("aincrad.noctf.dev%2Fnamespace%3Ddefault")
                && s.contains("aincrad.noctf.dev%2Finstance%3Dchal-1")),
            "instance routes must be deleted using label selector"
        );
    }

    #[tokio::test]
    async fn test_apply_planner_uncached_resource_succeeds() {
        use crate::planners::NetworkPolicyPlanner;

        let client = dummy_kube_client();
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        let (_store, ctx) = dummy_context();

        let api = Api::namespaced(client, "default");
        let res = apply_planner::<NetworkPolicyPlanner>(api, &instance, &template, &ctx).await;
        assert!(res.is_ok(), "uncached planner must apply without errors");
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

        let api = Api::namespaced(client, "default");
        let res = apply_planner::<ReplicaSetPlanner>(api, &instance, &template, &ctx).await;
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
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live, None)
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
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live, None)
                .await
                .expect("prune should succeed");
        assert_eq!(pruned, 0);
        assert_eq!(
            log.lock().unwrap().len(),
            0,
            "nothing to prune when every route's instance is live"
        );
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes_scoped_to_managed_namespace() {
        use crate::cache::ResourceCache;

        let (client, log) = recording_kube_client();
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();

        // Route in team-a (managed, live)
        let mut r1 = proxy_route("p30001", "chal-1", "web");
        r1.metadata.labels.as_mut().unwrap().insert(
            crate::utils::labels::NAMESPACE_LABEL.to_string(),
            "team-a".to_string(),
        );
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(r1));

        // Route in team-a (managed, orphaned)
        let mut r2 = proxy_route("p30002", "dead-chal", "pwn");
        r2.metadata.labels.as_mut().unwrap().insert(
            crate::utils::labels::NAMESPACE_LABEL.to_string(),
            "team-a".to_string(),
        );
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(r2));

        // Route in team-b (unmanaged, orphaned from team-a's perspective)
        let mut r3 = proxy_route("p30003", "other-chal", "web");
        r3.metadata.labels.as_mut().unwrap().insert(
            crate::utils::labels::NAMESPACE_LABEL.to_string(),
            "team-b".to_string(),
        );
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(r3));

        // Live set only knows team-a instances
        let live: std::collections::HashSet<(String, String)> =
            [("team-a".to_string(), "chal-1".to_string())]
                .into_iter()
                .collect();

        // Pruning scoped to team-a must only prune r2, not r3
        let pruned = prune_unreferenced_proxy_routes(
            client,
            "aincrad-system",
            &proxy_routes,
            &live,
            Some("team-a"),
        )
        .await
        .expect("prune should succeed");
        assert_eq!(
            pruned, 1,
            "only orphaned route in managed namespace should be pruned"
        );

        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|s| s.contains("DELETE") && s.contains("p30002")),
            "team-a orphan must be deleted"
        );
        assert!(
            !log.iter()
                .any(|s| s.contains("DELETE") && s.contains("p30003")),
            "unmanaged team-b route must NOT be deleted"
        );
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes_preserves_unlabeled_static_routes() {
        use crate::cache::ResourceCache;

        let (client, log) = recording_kube_client();
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();

        let mut static_route = proxy_route("p30005", "unknown", "static");
        static_route.metadata.labels = None;
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(static_route));

        let live: std::collections::HashSet<(String, String)> =
            [("default".to_string(), "chal-1".to_string())]
                .into_iter()
                .collect();

        let pruned =
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live, None)
                .await
                .expect("prune should succeed");
        assert_eq!(pruned, 0, "unlabeled/static route must be preserved");

        let log = log.lock().unwrap();
        assert!(
            !log.iter().any(|s| s.contains("DELETE")),
            "static route must not be deleted"
        );
    }

    #[tokio::test]
    async fn test_prune_unreferenced_proxy_routes_prunes_empty_instance_with_namespace() {
        use crate::cache::ResourceCache;

        let (client, log) = recording_kube_client();
        let proxy_routes = ResourceCache::<CTFProxyRoute>::new();

        let empty_instance_route = proxy_route("p30006", "", "web");
        proxy_routes.handle(&kube::runtime::watcher::Event::Apply(empty_instance_route));

        let live: std::collections::HashSet<(String, String)> =
            [("default".to_string(), "chal-1".to_string())]
                .into_iter()
                .collect();

        let pruned =
            prune_unreferenced_proxy_routes(client, "aincrad-system", &proxy_routes, &live, None)
                .await
                .expect("prune should succeed");
        assert_eq!(pruned, 1, "route with namespace but empty instance must be pruned");

        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|s| s.contains("DELETE") && s.contains("p30006")),
            "p30006 must be deleted"
        );
    }
}

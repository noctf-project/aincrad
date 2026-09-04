use std::collections::HashSet;

use k8s_common::{
    crd::CTFInstance,
    labels::{
        INSTANCE_GENERATION_LABEL, INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE,
        NAMESPACE_LABEL,
    },
};
use kube::{
    Api, Resource,
    api::{Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use crate::{Context, Error, planners::Planner, reconcilers::template::ResolvedTemplate};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planners::ReplicaSetPlanner;
    use crate::test_utils::tests::{
        dummy_context, dummy_instance, dummy_kube_client, dummy_resolved_template,
        recording_kube_client,
    };
    use k8s_common::labels::RESOURCE_LABEL;

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
            NAMESPACE_LABEL.to_string() => "default".to_string(),
            INSTANCE_LABEL.to_string() => "chal-1".to_string(),
            RESOURCE_LABEL.to_string() => "web".to_string(),
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
            NAMESPACE_LABEL.to_string() => "default".to_string(),
            INSTANCE_LABEL.to_string() => "chal-1".to_string(),
            RESOURCE_LABEL.to_string() => "web".to_string(),
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
}

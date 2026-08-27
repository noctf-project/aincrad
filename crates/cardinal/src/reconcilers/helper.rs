use std::collections::HashSet;

use k8s_common::crd::CTFInstance;
use kube::{
    Api, Resource,
    api::{ListParams, Patch, PatchParams},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use crate::{
    Error, planners::Planner, reconcilers::template::ResolvedTemplate,
    utils::labels::INSTANCE_LABEL,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planners::ReplicaSetPlanner;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client, dummy_resolved_template};
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
    async fn test_apply_planner_api_error_on_patch() {
        use crate::test_utils::tests::error_kube_client;
        let client = error_kube_client(500);
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);

        let res = apply_planner::<ReplicaSetPlanner>(client, &instance, &template).await;
        assert!(matches!(res, Err(Error::Kube(_))));
    }

    #[tokio::test]
    async fn test_prune_orphaned_resources_api_error() {
        use crate::test_utils::tests::error_kube_client;
        let client = error_kube_client(503);
        let api: Api<ReplicaSet> = Api::namespaced(client, "default");
        let desired = HashSet::new();

        let res = prune_orphaned_resources(&api, "chal-1", &desired).await;
        assert!(matches!(res, Err(Error::Kube(_))));
    }
}

use std::collections::HashSet;

use kube::{Api, Resource, ResourceExt, api::ListParams};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use crate::{
    Error,
    utils::labels::{INSTANCE_LABEL, TEMPLATE_GEN_ANNOTATION},
};

use k8s_common::crd::CTFInstance;

/// Reconciles a single child Kubernetes resource using the exact generation matching pattern.
///
/// - **Rule 1 (`workload_gen == instance_gen`)**: Do nothing (Skip), unless `sync_enabled` is true and `instance_gen != target_gen`.
/// - **Rule 2 (`workload_gen != instance_gen AND instance_gen == target_gen`)**: Perform update.
/// - **Rule 3 (`workload_gen != instance_gen AND instance_gen != target_gen` or missing)**: Fail with `Error::TemplateGenShifted`.
pub async fn reconcile_child_resource<K>(
    api: &Api<K>,
    name: &str,
    instance: &CTFInstance,
    target_gen: &str,
    sync_enabled: bool,
    mut build_resource: impl FnMut() -> K,
) -> Result<(), Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    let instance_gen = instance
        .annotations()
        .get(TEMPLATE_GEN_ANNOTATION)
        .map(String::as_str);

    match api.get_opt(name).await? {
        None => {
            if instance_gen == Some(target_gen) {
                info!(
                    name,
                    "Child resource missing or deleted, creating at target generation..."
                );
                let mut resource = build_resource();
                set_gen_annotation_and_owner(&mut resource, instance, target_gen);
                api.create(&Default::default(), &resource).await?;
                Ok(())
            } else {
                Err(Error::TemplateGenShifted {
                    instance_name: name.to_string(),
                    target_gen: target_gen.to_string(),
                })
            }
        }
        Some(existing) => {
            let workload_gen = existing
                .annotations()
                .get(TEMPLATE_GEN_ANNOTATION)
                .map(String::as_str);

            if workload_gen == instance_gen {
                if sync_enabled && instance_gen != Some(target_gen) {
                    return Err(Error::TemplateGenShifted {
                        instance_name: name.to_string(),
                        target_gen: target_gen.to_string(),
                    });
                }
                // Rule 1: workload_gen == instance_gen -> Do nothing
                return Ok(());
            }

            if instance_gen == Some(target_gen) {
                // Rule 2: workload_gen != instance_gen and instance_gen == target_gen -> Perform update
                info!(name, "Updating child resource to target generation...");
                let mut resource = build_resource();
                set_gen_annotation_and_owner(&mut resource, instance, target_gen);
                resource.meta_mut().resource_version = existing.resource_version();
                api.replace(name, &Default::default(), &resource).await?;
                Ok(())
            } else {
                // Rule 3: workload_gen != instance_gen and instance_gen != target_gen -> Fail so we update CTFInstance and requeue
                Err(Error::TemplateGenShifted {
                    instance_name: name.to_string(),
                    target_gen: target_gen.to_string(),
                })
            }
        }
    }
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

fn set_gen_annotation_and_owner<K: Resource>(
    resource: &mut K,
    instance: &CTFInstance,
    target_gen: &str,
) {
    let meta = resource.meta_mut();
    meta.managed_fields = None;
    let annotations = meta.annotations.get_or_insert_with(Default::default);
    annotations.insert(TEMPLATE_GEN_ANNOTATION.to_string(), target_gen.to_string());

    if let Some(owner) = instance.controller_owner_ref(&()) {
        meta.owner_references = Some(vec![owner]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client};
    use k8s_openapi::api::apps::v1::ReplicaSet;

    #[tokio::test]
    async fn test_reconcile_child_resource_missing_synced() {
        let client = dummy_kube_client();
        let api: Api<ReplicaSet> = Api::namespaced(client, "default");
        let instance = dummy_instance("chal-1", Some("1"));

        let res = reconcile_child_resource(&api, "chal-1-web", &instance, "1", false, || {
            let mut rs = ReplicaSet::default();
            rs.metadata.name = Some("chal-1-web".to_string());
            rs
        })
        .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_child_resource_missing_gen_shifted() {
        let client = dummy_kube_client();
        let api: Api<ReplicaSet> = Api::namespaced(client, "default");
        let instance = dummy_instance("chal-1", Some("1"));

        let res = reconcile_child_resource(&api, "chal-1-web", &instance, "2", false, || {
            let mut rs = ReplicaSet::default();
            rs.metadata.name = Some("chal-1-web".to_string());
            rs
        })
        .await;

        assert!(matches!(res, Err(Error::TemplateGenShifted { .. })));
    }

    #[tokio::test]
    async fn test_set_gen_annotation_and_owner() {
        let instance = dummy_instance("chal-1", Some("1"));
        let mut rs = ReplicaSet::default();
        rs.metadata.name = Some("chal-1-web".to_string());

        set_gen_annotation_and_owner(&mut rs, &instance, "1");

        let annotations = rs.metadata.annotations.as_ref().unwrap();
        assert_eq!(annotations.get(TEMPLATE_GEN_ANNOTATION).unwrap(), "1");

        let owners = rs.metadata.owner_references.as_ref().unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].name, "chal-1");
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
    async fn test_reconcile_child_resource_api_error_on_get() {
        use crate::test_utils::tests::error_kube_client;
        let client = error_kube_client(500);
        let api: Api<ReplicaSet> = Api::namespaced(client, "default");
        let instance = dummy_instance("chal-1", Some("1"));

        let res = reconcile_child_resource(&api, "chal-1-web", &instance, "1", false, || {
            let mut rs = ReplicaSet::default();
            rs.metadata.name = Some("chal-1-web".to_string());
            rs
        })
        .await;

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

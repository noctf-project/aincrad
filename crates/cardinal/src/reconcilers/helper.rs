use std::collections::HashSet;

use kube::{Api, Resource, ResourceExt, api::ListParams};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;

use crate::{
    Error,
    utils::labels::{INSTANCE_LABEL, TEMPLATE_GEN_ANNOTATION},
};

/// Reconciles a single child Kubernetes resource using the exact generation matching pattern.
///
/// - **Rule 1 (`workload_gen == instance_gen`)**: Do nothing (Skip), unless `sync_enabled` is true and `instance_gen != target_gen`.
/// - **Rule 2 (`workload_gen != instance_gen AND instance_gen == target_gen`)**: Perform update.
/// - **Rule 3 (`workload_gen != instance_gen AND instance_gen != target_gen` or missing)**: Fail with `Error::TemplateGenShifted`.
pub async fn reconcile_child_resource<K>(
    api: &Api<K>,
    name: &str,
    instance_gen: Option<&str>,
    target_gen: &str,
    sync_enabled: bool,
    mut build_resource: impl FnMut() -> K,
) -> Result<(), Error>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    match api.get_opt(name).await? {
        None => {
            if instance_gen == Some(target_gen) {
                info!(
                    name,
                    "Child resource missing or deleted, creating at target generation..."
                );
                let mut resource = build_resource();
                set_gen_annotation(&mut resource, target_gen);
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
                set_gen_annotation(&mut resource, target_gen);
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

fn set_gen_annotation<K: Resource>(resource: &mut K, target_gen: &str) {
    let annotations = resource
        .meta_mut()
        .annotations
        .get_or_insert_with(Default::default);
    annotations.insert(TEMPLATE_GEN_ANNOTATION.to_string(), target_gen.to_string());
}

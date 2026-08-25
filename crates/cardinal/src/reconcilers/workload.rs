use std::collections::{BTreeMap, HashSet};

use k8s_common::crd::CTFInstance;
use k8s_openapi::api::apps::v1::ReplicaSet;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error, btreemap,
    reconcilers::{
        helper::{prune_orphaned_resources, reconcile_child_resource},
        template::ResolvedTemplate,
    },
    resources::build_replicaset_spec,
    utils::hash_str_crockford,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
    utils::naming::resource_name,
};

/// Reconciles ReplicaSets for the target CTFInstance.
#[instrument(skip(ctx, instance, template))]
pub async fn reconcile(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
    instance_gen: Option<&str>,
    target_gen: &str,
) -> Result<(), Error> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let replica_sets: Api<ReplicaSet> = Api::namespaced(ctx.client.clone(), ns);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let sync = instance.spec.sync;

    let mut desired_names = HashSet::new();

    // Construct nested params context map so templates render {{ params.xxx }}
    let mut context_map = BTreeMap::new();
    context_map.insert("params".to_string(), &template.params_map);

    for pod_tmpl in &template.spec.pods {
        let pod_override = instance.spec.pods.iter().find(|p| p.name == pod_tmpl.name);
        let replicas = pod_override
            .map(|p| p.replicas)
            .unwrap_or(pod_tmpl.replicas);

        let patched_pod_spec = template.get_patched_pod_spec(pod_tmpl, &context_map)?;

        // Compute 10-character Crockford Base32 hash of the rendered PodSpec
        let spec_json = serde_json::to_string(&patched_pod_spec).unwrap_or_default();
        let full_hash = hash_str_crockford(&spec_json);
        let pod_hash = &full_hash[..10.min(full_hash.len())];

        let suffix = format!("{}-{}", pod_tmpl.name, pod_hash);
        let rs_name = resource_name(instance_name, &suffix);
        desired_names.insert(rs_name.clone());

        let labels = btreemap! {
            MANAGED_BY_LABEL => MANAGED_BY_VALUE,
            INSTANCE_LABEL => instance_name,
            POD_LABEL => pod_tmpl.name.as_str(),
        };

        reconcile_child_resource(
            &replica_sets,
            &rs_name,
            instance_gen,
            target_gen,
            sync,
            || {
                let mut rs = ReplicaSet::default();
                rs.metadata.name = Some(rs_name.clone());
                rs.metadata.namespace = Some(ns.to_string());
                rs.metadata.labels = Some(labels.clone());
                rs.spec = Some(build_replicaset_spec(
                    instance_name,
                    pod_tmpl,
                    patched_pod_spec.clone(),
                    replicas,
                ));
                rs
            },
        )
        .await?;
    }

    prune_orphaned_resources(&replica_sets, instance_name, &desired_names).await?;

    Ok(())
}

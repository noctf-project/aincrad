use k8s_common::crd::CTFInstance;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error, btreemap,
    reconcilers::{helper::reconcile_child_resource, template::ResolvedTemplate},
    resources::get_networkpolicy_spec,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE},
    utils::naming::resource_name,
};

/// Reconciles NetworkPolicy isolation for the target CTFInstance.
#[instrument(skip(ctx, instance, template))]
pub async fn reconcile(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
    instance_gen: Option<&str>,
    target_gen: &str,
) -> Result<(), Error> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let netpols: Api<NetworkPolicy> = Api::namespaced(ctx.client.clone(), ns);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let target_name = resource_name(instance_name, "np");
    let sync = instance.spec.sync;

    // Collect names of specific pods in the template that allow internet egress
    let allowed_internet_pods: Vec<String> = template
        .spec
        .pods
        .iter()
        .filter(|pod| pod.allow_internet)
        .map(|pod| pod.name.clone())
        .collect();

    let labels = btreemap! {
        MANAGED_BY_LABEL => MANAGED_BY_VALUE,
        INSTANCE_LABEL => instance_name,
    };

    reconcile_child_resource(
        &netpols,
        &target_name,
        instance_gen,
        target_gen,
        sync,
        || {
            let mut np = NetworkPolicy::default();
            np.metadata.name = Some(target_name.clone());
            np.metadata.namespace = Some(ns.to_string());
            np.metadata.labels = Some(labels.clone());
            np.spec = Some(get_networkpolicy_spec(
                instance_name,
                &allowed_internet_pods,
            ));
            np
        },
    )
    .await?;

    Ok(())
}

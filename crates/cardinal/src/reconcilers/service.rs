use std::collections::HashSet;

use k8s_common::crd::CTFInstance;
use k8s_openapi::api::core::v1::Service;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error,
    reconcilers::{
        helper::{prune_orphaned_resources, reconcile_child_resource},
        template::ResolvedTemplate,
    },
    resources::build_headless_service,
    utils::naming::resource_name,
};

/// Reconciles Headless ClusterIP Services for the target CTFInstance.
#[instrument(skip(ctx, instance, template))]
pub async fn reconcile(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
    instance_gen: Option<&str>,
    target_gen: &str,
) -> Result<(), Error> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let services: Api<Service> = Api::namespaced(ctx.client.clone(), ns);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let sync = instance.spec.sync;

    let mut desired_names = HashSet::new();

    for pod in &template.spec.pods {
        let svc_name = resource_name(instance_name, &pod.name);
        desired_names.insert(svc_name.clone());

        reconcile_child_resource(&services, &svc_name, instance_gen, target_gen, sync, || {
            build_headless_service(instance_name, pod, Some(ns))
        })
        .await?;
    }

    prune_orphaned_resources(&services, instance_name, &desired_names).await?;

    Ok(())
}

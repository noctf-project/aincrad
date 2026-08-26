use std::collections::HashSet;

use k8s_common::crd::CTFInstance;
use k8s_openapi::api::core::v1::Service;
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error, btreemap,
    reconcilers::{
        helper::{prune_orphaned_resources, reconcile_child_resource},
        template::ResolvedTemplate,
    },
    resources::build_headless_service_spec,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
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

        let labels = btreemap! {
            MANAGED_BY_LABEL => MANAGED_BY_VALUE,
            INSTANCE_LABEL => instance_name,
            POD_LABEL => pod.name.as_str(),
        };

        reconcile_child_resource(&services, &svc_name, instance_gen, target_gen, sync, || {
            let mut svc = Service::default();
            svc.metadata.name = Some(svc_name.clone());
            svc.metadata.namespace = Some(ns.to_string());
            svc.metadata.labels = Some(labels.clone());
            svc.spec = Some(build_headless_service_spec(instance_name, pod));
            svc
        })
        .await?;
    }

    prune_orphaned_resources(&services, instance_name, &desired_names).await?;

    Ok(())
}

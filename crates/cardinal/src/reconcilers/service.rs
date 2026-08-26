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
) -> Result<(), Error> {
    let target_gen = template.metadata.generation.unwrap_or(1).to_string();
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

        reconcile_child_resource(&services, &svc_name, instance, &target_gen, sync, || {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client, dummy_resolved_template};

    #[tokio::test]
    async fn test_reconcile_service_success() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", Some("1"));
        let template = dummy_resolved_template(1);

        let res = reconcile(&instance, &template, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_service_gen_shifted() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", Some("1"));
        let template = dummy_resolved_template(2);

        let res = reconcile(&instance, &template, &ctx).await;
        assert!(matches!(res, Err(Error::TemplateGenShifted { .. })));
    }
}

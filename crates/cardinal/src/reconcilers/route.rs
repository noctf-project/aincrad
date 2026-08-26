use std::collections::HashSet;

use k8s_common::crd::{CTFInstance, CTFRoute};
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error, btreemap,
    reconcilers::{
        helper::{prune_orphaned_resources, reconcile_child_resource},
        template::ResolvedTemplate,
    },
    resources::build_ctfroute_spec,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
    utils::naming::resource_name,
};

/// Reconciles CTFRoute resources for dynamic routing/ingress.
#[instrument(skip(ctx, instance, template))]
pub async fn reconcile(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
) -> Result<(), Error> {
    let target_gen = template.metadata.generation.unwrap_or(1).to_string();
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let routes: Api<CTFRoute> = Api::namespaced(ctx.client.clone(), ns);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let sync = instance.spec.sync;

    let mut desired_names = HashSet::new();

    for route_tmpl in &template.spec.routes {
        let route_name = resource_name(instance_name, &route_tmpl.name);
        desired_names.insert(route_name.clone());

        let route_override = instance
            .spec
            .routes
            .iter()
            .find(|r| r.name == route_tmpl.name);

        let merged_spec = build_ctfroute_spec(instance_name, &route_tmpl.spec, route_override);

        let labels = btreemap! {
            MANAGED_BY_LABEL => MANAGED_BY_VALUE,
            INSTANCE_LABEL => instance_name,
            POD_LABEL => route_tmpl.name.as_str(),
        };

        reconcile_child_resource(&routes, &route_name, instance, &target_gen, sync, || {
            let mut route = CTFRoute::new(&route_name, merged_spec.clone());
            route.metadata.namespace = Some(ns.to_string());
            route.metadata.labels = Some(labels.clone());
            route
        })
        .await?;
    }

    prune_orphaned_resources(&routes, instance_name, &desired_names).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client, dummy_resolved_template};

    #[tokio::test]
    async fn test_reconcile_route_success() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", Some("1"));
        let mut template = dummy_resolved_template(1);
        template
            .spec
            .routes
            .push(k8s_common::crd::CTFTemplateSpecRoute {
                name: "web".to_string(),
                spec: k8s_common::crd::CTFRouteSpec {
                    backend: k8s_common::crd::CTFRouteBackend {
                        service: "web".to_string(),
                        port: 80,
                    },
                    ..Default::default()
                },
            });

        let res = reconcile(&instance, &template, &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_route_gen_shifted() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", Some("1"));
        let mut template = dummy_resolved_template(2);
        template
            .spec
            .routes
            .push(k8s_common::crd::CTFTemplateSpecRoute {
                name: "web".to_string(),
                spec: k8s_common::crd::CTFRouteSpec {
                    backend: k8s_common::crd::CTFRouteBackend {
                        service: "web".to_string(),
                        port: 80,
                    },
                    ..Default::default()
                },
            });

        let res = reconcile(&instance, &template, &ctx).await;
        assert!(matches!(res, Err(Error::TemplateGenShifted { .. })));
    }
}

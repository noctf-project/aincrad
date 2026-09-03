use std::collections::{BTreeMap, BTreeSet};

use k8s_common::crd::CTFInstance;
use k8s_common::labels::{INSTANCE_LABEL, RESOURCE_LABEL};
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::planners::get_services_map;
use crate::utils::naming::resource_name;
use crate::{Context, Error, btreemap, planners::Planner, reconcilers::template::ResolvedTemplate};

pub struct ServicePlanner;

impl Planner for ServicePlanner {
    const KIND: &'static str = "Service";

    type Resource = Service;

    fn cache(ctx: &Context) -> Option<&crate::cache::ResourceCache<Self::Resource>> {
        Some(&ctx.caches.services)
    }

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        _ctx: &Context,
    ) -> Result<Vec<Service>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let mut desired = Vec::new();
        let mut context_map = BTreeMap::new();
        let services = get_services_map(template, instance_name);
        context_map.insert("params".to_string(), &template.params_map);
        context_map.insert("services".to_string(), &services);

        for pod in &template.spec.pods {
            let svc_name = resource_name(instance_name, &pod.name);

            let labels = btreemap! {
                RESOURCE_LABEL => pod.name.as_str(),
            };

            // grab all ports and put them into the service spec
            let ports: BTreeSet<i32> = pod
                .spec
                .containers
                .iter()
                .filter_map(|x| x.ports.as_ref())
                .flat_map(|x| x.iter().map(|c| c.container_port))
                .collect();

            let svc = Service {
                metadata: ObjectMeta {
                    name: Some(svc_name),
                    namespace: Some(ns.to_string()),
                    labels: Some(labels),
                    ..Default::default()
                },
                spec: Some(ServiceSpec {
                    selector: Some(btreemap! {
                        INSTANCE_LABEL => instance_name,
                        RESOURCE_LABEL => pod.name.as_str(),
                    }),
                    ports: Some(
                        ports
                            .iter()
                            .map(|p| ServicePort {
                                port: *p,
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }),
                ..Default::default()
            };
            desired.push(svc);
        }

        Ok(desired)
    }
}

#[cfg(test)]
mod tests {
    use k8s_common::labels::INSTANCE_LABEL;

    use super::*;
    use crate::test_utils::tests::{dummy_context, dummy_instance};

    #[tokio::test]
    async fn test_cached_names_returns_instance_services() {
        let (_store, ctx) = dummy_context();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-web".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ServiceSpec::default()),
            ..Default::default()
        };
        ctx.caches
            .services
            .handle(&kube::runtime::watcher::Event::Apply(svc));

        let instance = dummy_instance("chal-1", None);
        let names = ServicePlanner::cached_names(&instance, &ctx).unwrap();
        assert_eq!(
            names,
            vec!["chal-1-web".to_string()],
            "cached_names must surface services owned by the instance"
        );
    }

    #[tokio::test]
    async fn test_cached_names_empty_when_none_cached() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let names = ServicePlanner::cached_names(&instance, &ctx).unwrap();
        assert!(names.is_empty(), "an empty cache must surface no names");
    }
}

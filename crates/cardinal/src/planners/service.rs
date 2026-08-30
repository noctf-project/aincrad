use std::collections::{BTreeMap, BTreeSet};

use k8s_common::crd::CTFInstance;
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta};
use k8s_openapi::jiff::Timestamp;

use crate::planners::get_services_map;
use crate::{
    Context, Error, btreemap,
    planners::{Planner, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
    utils::naming::resource_name,
};

pub struct ServicePlanner;

impl Planner for ServicePlanner {
    const KIND: &'static str = "Service";
    const PRUNE_ORPHANS: bool = false;

    type Resource = Service;

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
                MANAGED_BY_LABEL => MANAGED_BY_VALUE,
                INSTANCE_LABEL => instance_name,
                POD_LABEL => pod.name.as_str(),
            };

            // grab all ports and put them into the service spec
            let ports: BTreeSet<i32> = pod
                .spec
                .containers
                .iter()
                .filter_map(|x| x.ports.as_ref())
                .flat_map(|x| x.iter().map(|c| c.container_port))
                .collect();

            let mut svc = Service {
                metadata: ObjectMeta {
                    name: Some(svc_name),
                    namespace: Some(ns.to_string()),
                    labels: Some(labels),
                    ..Default::default()
                },
                spec: Some(ServiceSpec {
                    selector: Some(btreemap! {
                        INSTANCE_LABEL => instance_name,
                        POD_LABEL => pod.name.as_str(),
                    }),
                    cluster_ip: Some("None".into()),
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
            set_owner_ref(&mut svc, instance);
            desired.push(svc);
        }

        Ok(desired)
    }

    fn check_status(
        instance: &CTFInstance,
        _ctx: &Context,
    ) -> Result<(Condition, Option<k8s_common::crd::CTFInstanceResources>), Error> {
        Ok((
            Condition {
                type_: Self::KIND.to_string(),
                status: "Unknown".to_string(),
                reason: "ResourceManaged".to_string(),
                message: "Resource applied".to_string(),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: instance.metadata.generation,
            },
            None,
        ))
    }
}

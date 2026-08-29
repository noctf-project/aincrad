use k8s_common::crd::{CTFInstance, CTFInstanceStatus};
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta};
use k8s_openapi::jiff::Timestamp;

use crate::{
    Context, Error, btreemap,
    planners::{Planner, apply_condition, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
    utils::naming::resource_name,
};

pub struct ServicePlanner;

impl Planner for ServicePlanner {
    const KIND: &'static str = "Service";
    type Resource = Service;

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        _ctx: &Context,
    ) -> Result<Vec<Service>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let mut desired = Vec::new();

        for pod in &template.spec.pods {
            let svc_name = resource_name(instance_name, &pod.name);

            let labels = btreemap! {
                MANAGED_BY_LABEL => MANAGED_BY_VALUE,
                INSTANCE_LABEL => instance_name,
                POD_LABEL => pod.name.as_str(),
            };

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
                    ports: Some(vec![ServicePort {
                        port: 80,
                        ..Default::default()
                    }]),
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
        _instance: &CTFInstance,
        status: &mut CTFInstanceStatus,
        _ctx: &Context,
    ) -> Result<(), Error> {
        apply_condition(
            status,
            Condition {
                type_: Self::KIND.to_string(),
                status: "True".to_string(),
                reason: "ResourceManaged".to_string(),
                message: "TODO: Sync status".to_string(),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: None,
            },
        );
        Ok(())
    }
}

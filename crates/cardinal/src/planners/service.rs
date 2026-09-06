use std::collections::BTreeSet;

use k8s_common::crd::{CTFInstance, RouteTarget};
use k8s_common::labels::{INSTANCE_LABEL, RESOURCE_LABEL};
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Patch, PatchParams};

use crate::cache::{ResourceCache, ResourceKey};
use crate::planners::Planner;
use crate::planners::helpers::build_merged_route_spec;
use crate::reconcilers::template::ResolvedTemplate;
use crate::routing::{Port, PortError, RouteError};
use crate::utils::naming::resource_name;
use crate::{Context, Error, btreemap};

pub use crate::utils::CARDINAL_LB_CLASS;

pub struct ServicePlanner;

/// Plans standard ClusterIP Services for internal inter-pod communication.
pub fn plan_services(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    _ctx: &Context,
) -> Result<Vec<Service>, Error> {
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let mut desired = Vec::new();

    for pod in &template.spec.pods {
        let svc_name = resource_name(&format!("{instance_name}-svc"), &pod.name);

        let labels = btreemap! {
            INSTANCE_LABEL => instance_name,
            RESOURCE_LABEL => pod.name.as_str(),
        };

        let mut ports: BTreeSet<i32> = pod
            .spec
            .containers
            .iter()
            .filter_map(|x| x.ports.as_ref())
            .flat_map(|x| x.iter().map(|c| c.container_port))
            .collect();

        for r in &template.spec.routes {
            if r.backend.service == pod.name && r.tls.is_some() {
                ports.insert(r.backend.port as i32);
            }
        }

        if ports.is_empty() {
            continue;
        }

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
                cluster_ip: Some("None".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        desired.push(svc);
    }

    Ok(desired)
}

/// Plans dummy LoadBalancer Services that reserve and expose TCP challenge ports.
pub fn plan_load_balancers(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
) -> Result<Vec<Service>, Error> {
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let mut desired = Vec::new();

    for pod in &template.spec.pods {
        let mut service_ports = Vec::new();

        for route_tmpl in &template.spec.routes {
            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);
            let merged_spec = build_merged_route_spec(route_tmpl, route_override);

            if merged_spec.backend.service != pod.name {
                continue;
            }

            let Some(RouteTarget::Port(port_opt, proto)) = merged_spec.target() else {
                continue;
            };

            let port = port_opt.unwrap_or(0);
            let port_enum = match proto {
                k8s_common::crd::RouteProtocol::Tcp => Port::Tcp(port),
                k8s_common::crd::RouteProtocol::Udp => Port::Udp(port),
            };

            if port != 0
                && let Some(port_map) = ctx.port_map.as_deref()
                && !port_map.is_reserved_port(port)
            {
                return Err(RouteError::Port(PortError::OutOfRange(port_enum)).into());
            }

            service_ports.push(ServicePort {
                name: Some(route_tmpl.name.clone()),
                port: port as i32,
                protocol: Some(proto.as_str().to_string()),
                target_port: Some(IntOrString::Int(merged_spec.backend.port as i32)),
                ..Default::default()
            });
        }

        if service_ports.is_empty() {
            continue;
        }

        let lb_name = resource_name(&format!("{instance_name}-lb"), &pod.name);
        let labels = btreemap! {
            INSTANCE_LABEL => instance_name,
            RESOURCE_LABEL => pod.name.as_str(),
        };

        let lb_svc = Service {
            metadata: ObjectMeta {
                name: Some(lb_name),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                load_balancer_class: Some(CARDINAL_LB_CLASS.to_string()),
                external_traffic_policy: Some("Cluster".to_string()),
                allocate_load_balancer_node_ports: Some(false),
                selector: Some(btreemap! {
                    INSTANCE_LABEL => instance_name,
                    RESOURCE_LABEL => pod.name.as_str(),
                }),
                ports: Some(service_ports),
                ..Default::default()
            }),
            ..Default::default()
        };

        desired.push(lb_svc);
    }

    Ok(desired)
}

/// Applies ClusterIP services using Server-Side Apply.
pub async fn apply_services(
    api: &kube::Api<Service>,
    services: Vec<Service>,
    _ctx: &Context,
) -> Result<Vec<Service>, Error> {
    crate::reconcilers::helper::sync_resources(api, ServicePlanner::KIND, services.clone()).await?;
    Ok(services)
}

/// Allocates ports, applies LoadBalancer services via Server-Side Apply, and patches status ingress IP.
pub async fn apply_load_balancers(
    api: &kube::Api<Service>,
    mut lb_services: Vec<Service>,
    ctx: &Context,
) -> Result<Vec<Service>, Error> {
    let mut bound_entries = Vec::new();

    if let Some(port_map) = ctx.port_map.as_deref() {
        for lb in &mut lb_services {
            let lb_name = lb.metadata.name.as_deref().unwrap_or("unknown");
            let lb_ns = lb.metadata.namespace.as_deref().unwrap_or("default");
            let instance_name = lb
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(INSTANCE_LABEL))
                .map(|s| s.as_str())
                .unwrap_or(lb_name);
            let pod_resource = lb
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(RESOURCE_LABEL))
                .map(|s| s.as_str())
                .unwrap_or(lb_name);

            if let Some(ref mut ports) = lb.spec.as_mut().and_then(|s| s.ports.as_mut()) {
                let requests: Vec<(ResourceKey, Port)> = ports
                    .iter()
                    .map(|p| {
                        let route_name = p.name.as_deref().unwrap_or(pod_resource);
                        let key = ResourceKey::new(lb_ns, instance_name, route_name);
                        let port_num = if p.port == 0 { 0 } else { p.port as u16 };
                        let port = match p.protocol.as_deref() {
                            Some("UDP") => Port::Udp(port_num),
                            _ => Port::Tcp(port_num),
                        };
                        (key, port)
                    })
                    .collect();

                let candidates = port_map
                    .find_free_ports(&requests)
                    .await
                    .map_err(RouteError::Port)?;

                for (p, cand) in ports.iter_mut().zip(&candidates) {
                    p.port = cand.port_number() as i32;
                }

                bound_entries.extend(requests.into_iter().map(|(key, _)| key).zip(candidates));
            }
        }
    }

    crate::reconcilers::helper::sync_resources(api, ServicePlanner::KIND, lb_services.clone())
        .await?;

    if let Some(port_map) = ctx.port_map.as_deref() {
        for (key, cand) in bound_entries {
            port_map.bind(cand.port(), key);
        }
    }

    if let Some(ref ip) = ctx.load_balancer_ip {
        let status_patch = serde_json::json!({
            "status": {
                "loadBalancer": {
                    "ingress": [{ "ip": ip }]
                }
            }
        });
        for lb in &lb_services {
            if let Some(name) = lb.metadata.name.as_deref() {
                api.patch_status(name, &PatchParams::default(), &Patch::Merge(&status_patch))
                    .await?;
            }
        }
    }

    Ok(lb_services)
}

impl Planner for ServicePlanner {
    const KIND: &'static str = "Service";

    type Resource = Service;

    fn cache(ctx: &Context) -> Option<&ResourceCache<Self::Resource>> {
        Some(&ctx.caches.services)
    }

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<Service>, Error> {
        let mut desired = plan_services(instance, template, ctx)?;
        let lbs = plan_load_balancers(instance, template, ctx)?;
        desired.extend(lbs);
        Ok(desired)
    }

    async fn apply(
        api: &kube::Api<Self::Resource>,
        desired: Vec<Self::Resource>,
        ctx: &Context,
    ) -> Result<Vec<Self::Resource>, Error> {
        let (lbs, standard_svcs): (Vec<_>, Vec<_>) = desired.into_iter().partition(|s| {
            s.spec.as_ref().and_then(|sp| sp.type_.as_deref()) == Some("LoadBalancer")
        });

        let mut applied = apply_services(api, standard_svcs, ctx).await?;
        let applied_lbs = apply_load_balancers(api, lbs, ctx).await?;
        applied.extend(applied_lbs);
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use k8s_common::crd::{RouteBackend, RouteSpec};
    use k8s_common::labels::INSTANCE_LABEL;

    use super::*;
    use crate::test_utils::tests::{dummy_context, dummy_instance, dummy_resolved_template};

    #[tokio::test]
    async fn test_plan_services_and_load_balancers() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);

        tmpl.spec.routes.push(RouteSpec {
            name: "pwn".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 1337,
                protocol: None,
            },
            port: Some(0),
            tls: None,
        });

        let svcs = ServicePlanner::plan(&instance, &tmpl, &ctx).unwrap();
        assert_eq!(svcs.len(), 2);

        let svc = &svcs[0];
        assert_eq!(svc.metadata.name.as_deref(), Some("chal-1-svc-web"));

        let lb = &svcs[1];
        assert_eq!(lb.metadata.name.as_deref(), Some("chal-1-lb-web"));
        assert_eq!(
            lb.spec.as_ref().and_then(|s| s.type_.as_deref()),
            Some("LoadBalancer")
        );
        assert_eq!(
            lb.spec
                .as_ref()
                .and_then(|s| s.load_balancer_class.as_deref()),
            Some(CARDINAL_LB_CLASS)
        );
        assert_eq!(
            lb.spec
                .as_ref()
                .and_then(|s| s.external_traffic_policy.as_deref()),
            Some("Cluster")
        );
        assert_eq!(
            lb.spec
                .as_ref()
                .and_then(|s| s.allocate_load_balancer_node_ports),
            Some(false)
        );
        assert_eq!(
            lb.spec.as_ref().and_then(|s| s.ports.as_ref()).unwrap()[0].port,
            0
        );
    }

    #[tokio::test]
    async fn test_plan_load_balancers_reserved_port_valid() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);

        tmpl.spec.routes.push(RouteSpec {
            name: "pwn".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 1337,
                protocol: None,
            },
            port: Some(20005),
            tls: None,
        });

        let lbs = plan_load_balancers(&instance, &tmpl, &ctx).unwrap();
        assert_eq!(lbs.len(), 1);
        let port = lbs[0].spec.as_ref().unwrap().ports.as_ref().unwrap()[0].port;
        assert_eq!(port, 20005);
    }

    #[tokio::test]
    async fn test_plan_load_balancers_reserved_port_invalid() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);

        tmpl.spec.routes.push(RouteSpec {
            name: "pwn".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 1337,
                protocol: None,
            },
            port: Some(9999),
            tls: None,
        });

        let res = plan_load_balancers(&instance, &tmpl, &ctx);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_apply_load_balancers_allocates_port_and_patches_ip() {
        let (_store, ctx_inner) = dummy_context();
        let mut ctx = Arc::unwrap_or_clone(ctx_inner);
        ctx.load_balancer_ip = Some("192.168.1.100".to_string());
        let ctx = Arc::new(ctx);

        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);

        tmpl.spec.routes.push(RouteSpec {
            name: "pwn".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 1337,
                protocol: None,
            },
            port: Some(0),
            tls: None,
        });

        let desired = ServicePlanner::plan(&instance, &tmpl, &ctx).unwrap();
        let api = kube::Api::<Service>::default_namespaced(ctx.client.clone());
        let applied = ServicePlanner::apply(&api, desired, &ctx).await.unwrap();

        assert_eq!(applied.len(), 2);
        let lb = applied
            .iter()
            .find(|s| s.metadata.name.as_deref() == Some("chal-1-lb-web"))
            .unwrap();
        let allocated_port = lb.spec.as_ref().unwrap().ports.as_ref().unwrap()[0].port;
        assert!((30000..=30010).contains(&allocated_port));
    }

    #[tokio::test]
    async fn test_cached_names_returns_instance_services() {
        let (_store, ctx) = dummy_context();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-svc-web".to_string()),
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
            vec!["chal-1-svc-web".to_string()],
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

    #[tokio::test]
    async fn test_plan_services_skips_pods_without_container_ports() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);
        tmpl.spec.pods[0].spec.containers[0].ports = None;
        tmpl.spec.routes.clear();

        let svcs = ServicePlanner::plan(&instance, &tmpl, &ctx).unwrap();
        assert!(
            svcs.is_empty(),
            "pod without container ports and without routes must produce no ClusterIP service"
        );
    }

    #[tokio::test]
    async fn test_plan_services_includes_route_backend_ports() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut tmpl = dummy_resolved_template(1);
        tmpl.spec.pods[0].spec.containers[0].ports = None;
        tmpl.spec.routes = vec![RouteSpec {
            name: "terminal".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 7681,
                protocol: None,
            },
            tls: Some(k8s_common::crd::RouteSpecTLS { prefix: None }),
            ..Default::default()
        }];

        let svcs = ServicePlanner::plan(&instance, &tmpl, &ctx).unwrap();
        assert_eq!(svcs.len(), 1);
        assert_eq!(svcs[0].metadata.name.as_deref(), Some("chal-1-svc-web"));
        let ports = svcs[0].spec.as_ref().unwrap().ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 7681);
    }
}

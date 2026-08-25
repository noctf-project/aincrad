use k8s_common::crd::CTFTemplateSpecPod;
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::btreemap;
use crate::utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL};
use crate::utils::naming::resource_name;

/// Builds a Headless ClusterIP Service manifest for a specific pod within a CTFInstance.
///
/// - Name: `resource_name(instance_name, pod_name)`
/// - ClusterIP: `"None"` (Headless Service)
/// - Selector: Matches `INSTANCE_LABEL => instance_name` and `POD_LABEL => pod_name`
pub fn build_headless_service(
    instance_name: &str,
    pod_tmpl: &CTFTemplateSpecPod,
    namespace: Option<&str>,
) -> Service {
    let svc_name = resource_name(instance_name, &pod_tmpl.name);
    let ns = namespace.unwrap_or("default");

    let labels = btreemap! {
        MANAGED_BY_LABEL => MANAGED_BY_VALUE,
        INSTANCE_LABEL => instance_name,
        POD_LABEL => pod_tmpl.name.as_str(),
    };

    let selector = btreemap! {
        INSTANCE_LABEL => instance_name,
        POD_LABEL => pod_tmpl.name.as_str(),
    };

    // Extract ports from pod container specs if available
    let mut service_ports = Vec::new();
    for container in &pod_tmpl.spec.containers {
        if let Some(ports) = &container.ports {
            for port in ports {
                let port_name = port
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("port-{}", port.container_port));
                service_ports.push(ServicePort {
                    name: Some(port_name),
                    port: port.container_port,
                    target_port: Some(IntOrString::Int(port.container_port)),
                    protocol: port.protocol.clone(),
                    ..Default::default()
                });
            }
        }
    }

    let mut svc = Service::default();
    svc.metadata.name = Some(svc_name);
    svc.metadata.namespace = Some(ns.to_string());
    svc.metadata.labels = Some(labels);
    svc.spec = Some(ServiceSpec {
        cluster_ip: Some("None".into()),
        selector: Some(selector),
        ports: if service_ports.is_empty() {
            None
        } else {
            Some(service_ports)
        },
        ..Default::default()
    });

    svc
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Container, ContainerPort, PodSpec};

    #[test]
    fn test_build_headless_service() {
        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            spec: PodSpec {
                containers: vec![Container {
                    name: "web-container".into(),
                    ports: Some(vec![ContainerPort {
                        container_port: 8080,
                        name: Some("http".into()),
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let svc = build_headless_service("team-alpha", &pod_tmpl, Some("challenges"));
        assert_eq!(svc.metadata.name, Some("team-alpha-c-web".to_string()));
        assert_eq!(svc.metadata.namespace, Some("challenges".to_string()));

        let spec = svc.spec.unwrap();
        assert_eq!(spec.cluster_ip, Some("None".into()));

        let selector = spec.selector.unwrap();
        assert_eq!(
            selector.get(INSTANCE_LABEL),
            Some(&"team-alpha".to_string())
        );
        assert_eq!(selector.get(POD_LABEL), Some(&"web".to_string()));

        let ports = spec.ports.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[0].name, Some("http".into()));
    }
}

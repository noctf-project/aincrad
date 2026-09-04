use k8s_common::crd::CTFInstance;
use k8s_common::labels::{INSTANCE_LABEL, RESOURCE_LABEL};
use k8s_openapi::api::networking::v1::NetworkPolicyIngressRule;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use k8s_openapi::{
    api::networking::v1::{
        IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
        NetworkPolicySpec,
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta},
        util::intstr::IntOrString,
    },
};

use crate::{
    Context, Error, btreemap, planners::Planner, reconcilers::template::ResolvedTemplate,
    utils::naming::resource_name,
};

pub struct NetworkPolicyPlanner;

impl Planner for NetworkPolicyPlanner {
    const KIND: &'static str = "NetworkPolicy";
    // networkpolicies are tractable
    type Resource = NetworkPolicy;

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        _ctx: &Context,
    ) -> Result<Vec<NetworkPolicy>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let allowed_internet_pods: Vec<&str> = template
            .spec
            .pods
            .iter()
            .filter(|pod| pod.allow_internet)
            .map(|pod| pod.name.as_str())
            .collect();

        let route_ports: Vec<NetworkPolicyPort> = template
            .spec
            .routes
            .iter()
            .filter_map(|r| {
                let override_spec = instance.spec.routes.iter().find(|ov| ov.name == r.name);
                let merged = crate::planners::helpers::build_merged_route_spec(r, override_spec);
                match merged.target() {
                    Some(k8s_common::crd::RouteTarget::Port(_, proto)) => Some(NetworkPolicyPort {
                        port: Some(IntOrString::Int(merged.backend.port as i32)),
                        protocol: Some(proto.as_str().to_string()),
                        end_port: None,
                    }),
                    _ => None,
                }
            })
            .collect();

        let int = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(resource_name(instance_name, "int")),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(plan_internal_spec(instance_name, route_ports)),
        };

        let ext = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(resource_name(instance_name, "ext")),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(plan_external_spec(instance_name, &allowed_internet_pods)),
        };

        Ok(vec![int, ext])
    }
}

fn plan_internal_spec(
    instance_name: &str,
    route_ports: Vec<NetworkPolicyPort>,
) -> NetworkPolicySpec {
    let mut ingress_rules = vec![NetworkPolicyIngressRule {
        from: Some(vec![NetworkPolicyPeer {
            pod_selector: Some(LabelSelector {
                match_labels: Some(btreemap! {
                    INSTANCE_LABEL => instance_name,
                }),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        ..Default::default()
    }];

    if !route_ports.is_empty() {
        ingress_rules.push(NetworkPolicyIngressRule {
            from: Some(vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector::default()),
                ..Default::default()
            }]),
            ports: Some(route_ports),
        });
    }

    let egress_rules = {
        let mut rules = Vec::new();

        let udp_egress = vec![NetworkPolicyPort {
            port: Some(IntOrString::Int(53)),
            protocol: Some("UDP".to_string()),
            end_port: None,
        }];

        rules.push(NetworkPolicyEgressRule {
            to: Some(vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        INSTANCE_LABEL => instance_name,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        });

        rules.push(NetworkPolicyEgressRule {
            ports: Some(udp_egress),
            to: Some(vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        "k8s-app".to_string() => "kube-dns".to_string(),
                    }),
                    ..Default::default()
                }),
                namespace_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        "kubernetes.io/metadata.name".to_string() => "kube-system".to_string(),
                    }),
                    ..Default::default()
                }),
                ip_block: None,
            }]),
        });
        rules
    };

    NetworkPolicySpec {
        pod_selector: Some(LabelSelector {
            match_labels: Some(btreemap! {
                INSTANCE_LABEL => instance_name,
            }),
            ..Default::default()
        }),
        policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
        egress: Some(egress_rules),
        ingress: Some(ingress_rules),
    }
}

fn plan_external_spec(instance_name: &str, allowed_pods: &[&str]) -> NetworkPolicySpec {
    NetworkPolicySpec {
        pod_selector: Some(LabelSelector {
            match_labels: Some(btreemap! {
                INSTANCE_LABEL => instance_name,
            }),
            match_expressions: Some(allowed_pods).filter(|arr| !arr.is_empty()).map(|arr| {
                vec![LabelSelectorRequirement {
                    key: RESOURCE_LABEL.to_string(),
                    operator: "In".to_string(),
                    values: Some(arr.iter().map(|s| s.to_string()).collect()),
                }]
            }),
        }),
        policy_types: Some(vec!["Egress".to_string()]),
        egress: (!allowed_pods.is_empty()).then_some(vec![NetworkPolicyEgressRule {
            ports: Some(vec![NetworkPolicyPort {
                port: None,
                protocol: None,
                end_port: None,
            }]),
            to: Some(vec![NetworkPolicyPeer {
                pod_selector: None,
                namespace_selector: None,
                ip_block: Some(IPBlock {
                    cidr: "0.0.0.0/0".to_string(),
                    except: Some(vec![
                        "10.0.0.0/8".to_string(),
                        "172.16.0.0/12".to_string(),
                        "192.168.0.0/16".to_string(),
                    ]),
                }),
            }]),
        }]),
        ingress: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_context, dummy_instance, dummy_resolved_template};
    use k8s_common::crd::CTFTemplateSpecPod;
    use k8s_openapi::api::core::v1::{Container, PodSpec};

    #[tokio::test]
    async fn test_plan_network_policy_default_isolated() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1); // default pod has allow_internet: false

        let policies = NetworkPolicyPlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(policies.len(), 2);

        let int_policy = &policies[0];
        assert_eq!(int_policy.metadata.name.as_deref(), Some("chal-1-int"));
        let int_spec = int_policy.spec.as_ref().unwrap();
        assert_eq!(
            int_spec.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );
        assert_eq!(int_spec.ingress.as_ref().unwrap().len(), 1);
        assert_eq!(int_spec.egress.as_ref().unwrap().len(), 2);

        let ext_policy = &policies[1];
        assert_eq!(ext_policy.metadata.name.as_deref(), Some("chal-1-ext"));
        let ext_spec = ext_policy.spec.as_ref().unwrap();
        assert_eq!(ext_spec.policy_types, Some(vec!["Egress".to_string()]));
        assert!(
            ext_spec.egress.is_none(),
            "isolated challenge must have no egress rules in ext policy"
        );
        assert!(
            ext_spec
                .pod_selector
                .as_ref()
                .unwrap()
                .match_expressions
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_plan_network_policy_with_internet_allowed() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);

        template.spec.pods = vec![
            CTFTemplateSpecPod {
                name: "web".to_string(),
                allow_internet: true,
                replicas: 1,
                patch_spec: None,
                spec: PodSpec {
                    containers: vec![Container {
                        name: "app".to_string(),
                        image: Some("nginx".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            },
            CTFTemplateSpecPod {
                name: "db".to_string(),
                allow_internet: false,
                replicas: 1,
                patch_spec: None,
                spec: PodSpec {
                    containers: vec![Container {
                        name: "db".to_string(),
                        image: Some("redis".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            },
        ];

        let policies = NetworkPolicyPlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(policies.len(), 2);

        let ext_policy = &policies[1];
        let ext_spec = ext_policy.spec.as_ref().unwrap();
        assert!(ext_spec.egress.is_some());
        let egress_rules = ext_spec.egress.as_ref().unwrap();
        assert_eq!(egress_rules.len(), 1);

        let ip_block = egress_rules[0].to.as_ref().unwrap()[0]
            .ip_block
            .as_ref()
            .unwrap();
        assert_eq!(ip_block.cidr, "0.0.0.0/0");
        assert_eq!(
            ip_block.except.as_ref().unwrap(),
            &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );

        let match_exprs = ext_spec
            .pod_selector
            .as_ref()
            .unwrap()
            .match_expressions
            .as_ref()
            .unwrap();
        assert_eq!(match_exprs.len(), 1);
        assert_eq!(match_exprs[0].key, RESOURCE_LABEL);
        assert_eq!(match_exprs[0].values, Some(vec!["web".to_string()]));
    }

    #[tokio::test]
    async fn test_plan_network_policy_multi_pod_internet_allowed() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);

        template.spec.pods = vec![
            CTFTemplateSpecPod {
                name: "web".to_string(),
                allow_internet: true,
                replicas: 1,
                patch_spec: None,
                spec: PodSpec::default(),
            },
            CTFTemplateSpecPod {
                name: "api".to_string(),
                allow_internet: true,
                replicas: 1,
                patch_spec: None,
                spec: PodSpec::default(),
            },
        ];

        let policies = NetworkPolicyPlanner::plan(&instance, &template, &ctx).unwrap();
        let ext_spec = policies[1].spec.as_ref().unwrap();
        let match_exprs = ext_spec
            .pod_selector
            .as_ref()
            .unwrap()
            .match_expressions
            .as_ref()
            .unwrap();

        assert_eq!(
            match_exprs[0].values,
            Some(vec!["web".to_string(), "api".to_string()])
        );
    }

    #[tokio::test]
    async fn test_plan_network_policy_route_ports_allows_namespace_ingress() {
        use k8s_common::crd::{RouteBackend, RouteProtocol, RouteSpec};

        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![
            RouteSpec {
                name: "web".to_string(),
                backend: RouteBackend {
                    service: "web".to_string(),
                    port: 1337,
                    protocol: Some(RouteProtocol::Tcp),
                },
                port: Some(0),
                ..Default::default()
            },
            RouteSpec {
                name: "tls-web".to_string(),
                backend: RouteBackend {
                    service: "web".to_string(),
                    port: 8443,
                    protocol: Some(RouteProtocol::Tcp),
                },
                tls: Some(k8s_common::crd::RouteSpecTLS {
                    prefix: Some("tls".into()),
                }),
                ..Default::default()
            },
        ];

        let policies = NetworkPolicyPlanner::plan(&instance, &template, &ctx).unwrap();
        let int_spec = policies[0].spec.as_ref().unwrap();
        let ingress = int_spec.ingress.as_ref().unwrap();
        assert_eq!(ingress.len(), 2);

        // First rule: pod-to-pod within instance
        assert_eq!(
            ingress[0].from.as_ref().unwrap()[0]
                .pod_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get(INSTANCE_LABEL),
            Some(&"chal-1".to_string())
        );

        // Second rule: all namespace pods can reach declared raw route port 1337 only (not TLS 8443)
        let route_rule = &ingress[1];
        assert_eq!(
            route_rule.from.as_ref().unwrap()[0]
                .pod_selector
                .as_ref()
                .unwrap(),
            &LabelSelector::default()
        );
        let ports = route_rule.ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1, "TLS route port must not be included");
        assert_eq!(ports[0].port, Some(IntOrString::Int(1337)));
        assert_eq!(ports[0].protocol, Some("TCP".to_string()));
    }
}

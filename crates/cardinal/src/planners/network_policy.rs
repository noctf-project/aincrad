use k8s_common::RESOURCE_LABEL;
use k8s_common::crd::CTFInstance;
use k8s_openapi::api::networking::v1::NetworkPolicyIngressRule;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use k8s_openapi::jiff::Timestamp;
use k8s_openapi::{
    api::networking::v1::{
        IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
        NetworkPolicySpec,
    },
    apimachinery::pkg::{
        apis::meta::v1::{Condition, LabelSelector, ObjectMeta},
        util::intstr::IntOrString,
    },
};

use crate::{
    Context, Error, btreemap,
    planners::{Planner, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE},
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

        let labels = btreemap! {
            MANAGED_BY_LABEL => MANAGED_BY_VALUE,
            INSTANCE_LABEL => instance_name,
        };

        let allowed_internet_pods: Vec<&str> = template
            .spec
            .pods
            .iter()
            .filter(|pod| pod.allow_internet)
            .map(|pod| pod.name.as_str())
            .collect();

        let mut int = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(resource_name(instance_name, "int")),
                namespace: Some(ns.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(plan_internal_spec(instance_name)),
        };
        set_owner_ref(&mut int, instance);

        let mut ext = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(resource_name(instance_name, "ext")),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(plan_external_spec(instance_name, &allowed_internet_pods)),
        };
        set_owner_ref(&mut ext, instance);

        Ok(vec![int, ext])
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

fn plan_internal_spec(instance_name: &str) -> NetworkPolicySpec {
    let ingress_rules = vec![NetworkPolicyIngressRule {
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

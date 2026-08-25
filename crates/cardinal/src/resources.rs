use std::collections::BTreeMap;

use cardinal::btreemap;
use k8s_openapi::{
    api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec,
    },
    apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
};

const BLOCKED_IPS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

pub fn get_networkpolicy_spec(instance: &str, allow_internet: bool) -> NetworkPolicySpec {
    let mut egress_rules = vec![
        NetworkPolicyEgressRule {
            to: Some(vec![
                NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "169.254.0.0/16".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(btreemap! {
                            "kubernetes.io/metadata.name" => "kube-system",
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            ports: Some(vec![
                NetworkPolicyPort {
                    protocol: Some("TCP".into()),
                    port: Some(IntOrString::Int(53)),
                    ..Default::default()
                },
                NetworkPolicyPort {
                    protocol: Some("UDP".into()),
                    port: Some(IntOrString::Int(53)),
                    ..Default::default()
                },
            ]),
        },
        NetworkPolicyEgressRule {
            to: Some(vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        "aincrad.noctf.dev/instance" => instance,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        },
    ];

    if allow_internet {
        egress_rules.push(NetworkPolicyEgressRule {
            to: Some(vec![
                NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "0.0.0.0/0".into(),
                        except: Some(BLOCKED_IPS.iter().map(|&s| s.into()).collect()),
                    }),
                    ..Default::default()
                },
                // needed for l4 passthrough hairpinning
                NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(btreemap! {
                            "app.kubernetes.io/component" => "aincrad",
                        }),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(btreemap! {
                            "app.kubernetes.io/name" => "aincrad-fluct",
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            ports: None,
        });
        // traefik loopback, but only allow 8000 8443 (80/443) as traefik is unprivileged
        egress_rules.push(NetworkPolicyEgressRule {
            ports: Some(vec![
                NetworkPolicyPort {
                    protocol: Some("TCP".into()),
                    port: Some(IntOrString::Int(80)),
                    ..Default::default()
                },
                NetworkPolicyPort {
                    protocol: Some("TCP".into()),
                    port: Some(IntOrString::Int(443)),
                    ..Default::default()
                },
                NetworkPolicyPort {
                    protocol: Some("TCP".into()),
                    port: Some(IntOrString::Int(8000)),
                    ..Default::default()
                },
                NetworkPolicyPort {
                    protocol: Some("UDP".into()),
                    port: Some(IntOrString::Int(8443)),
                    ..Default::default()
                },
            ]),
            to: Some(vec![NetworkPolicyPeer {
                namespace_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        "app.kubernetes.io/component" => "traefik",
                    }),
                    ..Default::default()
                }),
                pod_selector: Some(LabelSelector {
                    match_labels: Some(btreemap! {
                        "app.kubernetes.io/name" => "traefik",
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
        })
    }

    NetworkPolicySpec {
        egress: Some(egress_rules),
        ingress: None,
        pod_selector: Some(LabelSelector::default()),
        policy_types: Some(vec!["Egress".into()]),
    }
}

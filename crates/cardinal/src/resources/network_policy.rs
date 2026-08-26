use crate::btreemap;
use crate::utils::labels::{INSTANCE_LABEL, POD_LABEL};
use k8s_openapi::{
    api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec,
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, LabelSelectorRequirement},
        util::intstr::IntOrString,
    },
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

pub fn get_networkpolicy_spec(
    instance: &str,
    allowed_internet_pods: &[String],
) -> NetworkPolicySpec {
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
                        INSTANCE_LABEL => instance,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        },
    ];

    if !allowed_internet_pods.is_empty() {
        egress_rules.push(NetworkPolicyEgressRule {
            to: Some(vec![
                NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "0.0.0.0/0".into(),
                        except: Some(BLOCKED_IPS.iter().map(|&s| s.into()).collect()),
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(btreemap! {
                            INSTANCE_LABEL => instance,
                        }),
                        match_expressions: Some(vec![LabelSelectorRequirement {
                            key: POD_LABEL.into(),
                            operator: "In".into(),
                            values: Some(allowed_internet_pods.to_vec()),
                        }]),
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
        pod_selector: Some(LabelSelector {
            match_labels: Some(btreemap! {
                INSTANCE_LABEL => instance.to_string(),
            }),
            ..Default::default()
        }),
        policy_types: Some(vec!["Egress".into()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_networkpolicy_spec_no_internet_egress() {
        let spec = get_networkpolicy_spec("team-alpha", &[]);
        let egress = spec.egress.expect("Egress rules must be present");

        // DNS rule and inter-pod rule
        assert_eq!(egress.len(), 2);

        // Inter-pod rule check
        let inter_pod_peer = &egress[1].to.as_ref().unwrap()[0];
        let pod_selector = inter_pod_peer.pod_selector.as_ref().unwrap();
        assert_eq!(
            pod_selector
                .match_labels
                .as_ref()
                .unwrap()
                .get(INSTANCE_LABEL),
            Some(&"team-alpha".to_string())
        );
    }

    #[test]
    fn test_get_networkpolicy_spec_allowed_internet_pods_match_expressions() {
        let spec = get_networkpolicy_spec("team-alpha", &["web".to_string(), "api".to_string()]);
        let egress = spec.egress.expect("Egress rules must be present");

        // DNS + Inter-pod + Internet 0.0.0.0/0 + Traefik loopback
        assert_eq!(egress.len(), 4);

        // Internet egress rule check
        let internet_rule = &egress[2];
        let peers = internet_rule.to.as_ref().unwrap();
        let internet_peer = &peers[0];

        let pod_selector = internet_peer.pod_selector.as_ref().unwrap();
        assert_eq!(
            pod_selector
                .match_labels
                .as_ref()
                .unwrap()
                .get(INSTANCE_LABEL),
            Some(&"team-alpha".to_string())
        );

        let match_exprs = pod_selector.match_expressions.as_ref().unwrap();
        assert_eq!(match_exprs.len(), 1);
        assert_eq!(match_exprs[0].key, POD_LABEL);
        assert_eq!(match_exprs[0].operator, "In");
        assert_eq!(
            match_exprs[0].values,
            Some(vec!["web".into(), "api".into()])
        );
    }
}

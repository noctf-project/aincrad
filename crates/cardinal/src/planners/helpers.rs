use std::collections::HashSet;

use k8s_common::crd::{CTFInstance, CTFInstanceStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Adds or replaces a status condition by type.
pub fn apply_condition(status: &mut CTFInstanceStatus, condition: Condition) {
    if let Some(pos) = status
        .conditions
        .iter_mut()
        .find(|c| c.type_ == condition.type_)
    {
        *pos = condition;
    } else {
        status.conditions.push(condition);
    }
}

/// Fails the reconcile if any instance pod or route override names a template
/// entry that does not exist. Silent overrides against a template are a
/// misconfiguration — for a `sync: true` instance a deleted template entry
/// (and its override) is valid, but a never-existent name is always a mistake.
pub fn validate_overrides(
    instance: &CTFInstance,
    template: &crate::reconcilers::template::ResolvedTemplate,
) -> Result<(), super::Error> {
    let mut bad: Vec<String> = Vec::new();

    let route_names: HashSet<&str> = template
        .spec
        .routes
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    for ov in &instance.spec.routes {
        if !route_names.contains(ov.name.as_str()) {
            bad.push(format!("route '{}'", ov.name));
        }
    }

    let pod_names: HashSet<&str> = template.spec.pods.iter().map(|p| p.name.as_str()).collect();
    for ov in &instance.spec.pods {
        if !pod_names.contains(ov.name.as_str()) {
            bad.push(format!("pod '{}'", ov.name));
        }
    }

    if bad.is_empty() {
        Ok(())
    } else {
        Err(super::Error::InvalidOverride(format!(
            "Instance overrides do not match any template definition: {}",
            bad.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_resolved_template};
    use k8s_common::crd::{
        CTFInstanceSpecPodOverride, CTFInstanceSpecRouteOverride, RouteBackend, RouteSpec,
        RouteSpecTCP,
    };

    #[test]
    fn test_validate_overrides_accepts_matching_overrides() {
        let mut instance = dummy_instance("chal-1", None);
        instance.spec.pods = vec![CTFInstanceSpecPodOverride {
            name: "web".into(),
            replicas: 2,
        }];
        instance.spec.routes = vec![CTFInstanceSpecRouteOverride {
            name: "chal".into(),
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            tls: None,
        }];

        let mut template = dummy_resolved_template(1);
        template.spec.pods[0].name = "web".into();
        template.spec.routes = vec![RouteSpec {
            name: "chal".into(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
        }];

        assert!(validate_overrides(&instance, &template).is_ok());
    }

    #[test]
    fn test_validate_overrides_rejects_unknown_pod_and_route() {
        let instance = dummy_instance("chal-1", None);
        let mut instance = instance;
        instance.spec.pods = vec![CTFInstanceSpecPodOverride {
            name: "typo-pod".into(),
            replicas: 2,
        }];
        instance.spec.routes = vec![CTFInstanceSpecRouteOverride {
            name: "typo-route".into(),
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            tls: None,
        }];

        let template = dummy_resolved_template(1);

        let err = validate_overrides(&instance, &template).unwrap_err();
        match err {
            super::super::Error::InvalidOverride(msg) => {
                assert!(msg.contains("pod 'typo-pod'"), "{msg}");
                assert!(msg.contains("route 'typo-route'"), "{msg}");
            }
            other => panic!("expected InvalidOverride, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_overrides_accepts_no_overrides() {
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        assert!(validate_overrides(&instance, &template).is_ok());
    }
}

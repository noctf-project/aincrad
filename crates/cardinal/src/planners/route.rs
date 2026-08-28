use k8s_common::crd::{
    CTFInstance, CTFInstanceSpecRouteOverride, CTFRoute, CTFRouteSpec, PatchValue,
};

use crate::{
    Error, btreemap,
    planners::{Planner, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL},
    utils::naming::resource_name,
};

pub struct RoutePlanner;

impl Planner for RoutePlanner {
    type Resource = CTFRoute;

    fn plan(instance: &CTFInstance, template: &ResolvedTemplate) -> Result<Vec<CTFRoute>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let mut desired = Vec::new();

        for route_tmpl in &template.spec.routes {
            let route_name = resource_name(instance_name, &route_tmpl.name);

            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);

            let merged_spec = build_ctfroute_spec(instance_name, &route_tmpl.spec, route_override);

            let labels = btreemap! {
                MANAGED_BY_LABEL => MANAGED_BY_VALUE,
                INSTANCE_LABEL => instance_name,
                POD_LABEL => route_tmpl.name.as_str(),
            };

            let mut route = CTFRoute::new(&route_name, merged_spec);
            route.metadata.namespace = Some(ns.to_string());
            route.metadata.labels = Some(labels);
            set_owner_ref(&mut route, instance);
            desired.push(route);
        }

        Ok(desired)
    }
}

/// Builds a merged `CTFRouteSpec` from a base template specification and optional instance overrides.
pub fn build_ctfroute_spec(
    instance_name: &str,
    base: &CTFRouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> CTFRouteSpec {
    let mut merged = base.clone();
    merged.backend.service = resource_name(instance_name, &merged.backend.service);

    if let Some(ov) = override_spec {
        match ov.port {
            PatchValue::Value(port) => {
                let mut tcp = merged.tcp.unwrap_or_default();
                tcp.port = Some(port);
                merged.tcp = Some(tcp);
            }
            PatchValue::Null => {
                merged.tcp = None;
            }
            PatchValue::Unset => {}
        }

        match &ov.tls {
            PatchValue::Value(tls_patch) => {
                let mut tls = merged.tls.unwrap_or_default();
                match &tls_patch.prefix {
                    PatchValue::Value(prefix) => {
                        tls.prefix = Some(prefix.clone());
                    }
                    PatchValue::Null => {
                        tls.prefix = None;
                    }
                    PatchValue::Unset => {}
                }
                merged.tls = Some(tls);
            }
            PatchValue::Null => {
                merged.tls = None;
            }
            PatchValue::Unset => {}
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFRouteBackend, CTFRouteSpecTCP, CTFRouteSpecTLS, CTFRouteSpecTLSPatch};

    #[test]
    fn test_build_ctfroute_spec_port_and_tls_overrides() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            tcp: Some(CTFRouteSpecTCP { port: Some(443) }),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            port: PatchValue::Value(8443),
            tls: PatchValue::Value(CTFRouteSpecTLSPatch {
                prefix: PatchValue::Value("custom-prefix".into()),
            }),
        };

        let merged = build_ctfroute_spec("chal-1", &base_spec, Some(&override_spec));

        assert_eq!(merged.backend.service, resource_name("chal-1", "web"));
        assert_eq!(merged.tcp, Some(CTFRouteSpecTCP { port: Some(8443) }));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            })
        );
    }

    #[test]
    fn test_build_ctfroute_spec_disable_port_via_null() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            tcp: Some(CTFRouteSpecTCP { port: Some(443) }),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            port: PatchValue::Unset,
            tls: PatchValue::Null,
        };

        let merged = build_ctfroute_spec("chal-1", &base_spec, Some(&override_spec));

        assert_eq!(merged.backend.service, resource_name("chal-1", "web"));
        assert_eq!(merged.tcp, Some(CTFRouteSpecTCP { port: Some(443) }));
        assert_eq!(merged.tls, None);
    }

    #[test]
    fn test_build_ctfroute_spec_no_override() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            tcp: Some(CTFRouteSpecTCP { port: Some(443) }),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let merged = build_ctfroute_spec("chal-1", &base_spec, None);

        assert_eq!(merged.backend.service, resource_name("chal-1", "web"));
        assert_eq!(merged.tcp, Some(CTFRouteSpecTCP { port: Some(443) }));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            })
        );
    }

    #[test]
    fn test_plan_route() {
        use crate::test_utils::tests::{dummy_instance, dummy_resolved_template};
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template
            .spec
            .routes
            .push(k8s_common::crd::CTFTemplateSpecRoute {
                name: "web".to_string(),
                spec: CTFRouteSpec {
                    backend: k8s_common::crd::CTFRouteBackend {
                        service: "web".to_string(),
                        port: 80,
                    },
                    ..Default::default()
                },
            });

        let desired = RoutePlanner::plan(&instance, &template).unwrap();
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].metadata.name.as_deref(), Some("chal-1-c-web"));
        assert_eq!(
            desired[0].metadata.owner_references.as_ref().unwrap().len(),
            1
        );
    }
}

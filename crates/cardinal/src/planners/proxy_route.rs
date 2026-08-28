use k8s_common::crd::{
    CTFInstance, CTFInstanceSpecRouteOverride, CTFInstanceStatusEndpoint, CTFProxyRoute,
    CTFProxyRouteSpec, CTFProxyRouteSpecPOW, PatchValue, RouteSpec,
};

use crate::{
    Error, btreemap,
    reconcilers::template::ResolvedTemplate,
    routing::{AllocatedRoute, RouteAllocator, RouteKey},
    utils::labels::{
        INSTANCE_LABEL, INSTANCE_NAMESPACE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL,
    },
    utils::naming::resource_name,
};

#[derive(Debug, Clone)]
pub struct PlannedRoutes {
    pub routes: Vec<CTFProxyRoute>,
    pub endpoints: Vec<CTFInstanceStatusEndpoint>,
}

pub struct ProxyRoutePlanner;

impl ProxyRoutePlanner {
    pub fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        allocator: &RouteAllocator,
        system_namespace: &str,
        cluster_domain: &str,
    ) -> Result<PlannedRoutes, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let mut routes = Vec::new();
        let mut endpoints = Vec::new();

        for route_tmpl in &template.spec.routes {
            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);

            let merged_spec = build_merged_route_spec(&route_tmpl.spec, route_override);
            let route_key = RouteKey::new(ns, instance_name, &route_tmpl.name);

            let allocated: AllocatedRoute = allocator.allocate(&route_key, &merged_spec)?;

            let backend_svc = resource_name(instance_name, &merged_spec.backend.service);
            let backend_addr = format!(
                "{}.{}.svc.{}:{}",
                backend_svc, ns, cluster_domain, merged_spec.backend.port
            );

            let labels = btreemap! {
                MANAGED_BY_LABEL => MANAGED_BY_VALUE,
                INSTANCE_LABEL => instance_name,
                INSTANCE_NAMESPACE_LABEL => ns,
                POD_LABEL => route_tmpl.name.as_str(),
            };

            let proxy_spec = CTFProxyRouteSpec {
                backend: backend_addr,
                flag: merged_spec.flag,
                secret: merged_spec.secret,
                request_uid: merged_spec.request_uid,
                pow: merged_spec.pow.map(|p| CTFProxyRouteSpecPOW {
                    difficulty: p.difficulty,
                    enable_admin_bypass: p.enable_admin_bypass,
                }),
                logs: merged_spec.logs,
                available_at: merged_spec.available_at,
            };

            let mut proxy_route = CTFProxyRoute::new(&allocated.proxy_key.to_string(), proxy_spec);
            proxy_route.metadata.namespace = Some(system_namespace.to_string());
            proxy_route.metadata.labels = Some(labels);

            routes.push(proxy_route);
            endpoints.push(allocated.endpoint);
        }

        endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));

        Ok(PlannedRoutes { routes, endpoints })
    }
}

/// Builds a merged `RouteSpec` applying optional instance-level overrides.
pub fn build_merged_route_spec(
    base: &RouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> RouteSpec {
    let mut merged = base.clone();

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
    use crate::routing::PortsStore;
    use crate::test_utils::tests::{dummy_instance, dummy_resolved_template};
    use k8s_common::PortRange;
    use k8s_common::crd::{
        CTFTemplateSpecRoute, RouteBackend, RouteSpec, RouteSpecPOW, RouteSpecTCP, RouteSpecTLS,
        RouteSpecTLSPatch,
    };
    use std::sync::Arc;

    fn make_test_allocator() -> RouteAllocator {
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        RouteAllocator::new(ports, "link-start", "c.sk8.dog", 4433)
    }

    #[test]
    fn test_plan_proxy_routes_tcp_and_tls() {
        let allocator = make_test_allocator();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![
            CTFTemplateSpecRoute {
                name: "web".to_string(),
                spec: RouteSpec {
                    backend: RouteBackend {
                        service: "web".to_string(),
                        port: 80,
                    },
                    tls: Some(RouteSpecTLS {
                        prefix: Some("whoami".into()),
                    }),
                    logs: true,
                    ..Default::default()
                },
            },
            CTFTemplateSpecRoute {
                name: "pwn".to_string(),
                spec: RouteSpec {
                    backend: RouteBackend {
                        service: "pwn".to_string(),
                        port: 1337,
                    },
                    tcp: Some(RouteSpecTCP { port: Some(0) }),
                    pow: Some(RouteSpecPOW {
                        difficulty: 5000,
                        enable_admin_bypass: true,
                    }),
                    ..Default::default()
                },
            },
        ];

        let planned = ProxyRoutePlanner::plan(
            &instance,
            &template,
            &allocator,
            "aincrad-system",
            "cluster.local",
        )
        .unwrap();

        assert_eq!(planned.routes.len(), 2);
        assert_eq!(planned.endpoints.len(), 2);

        // Check TLS route
        let tls_route = planned
            .routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('r'))
            .unwrap();
        assert_eq!(
            tls_route.metadata.namespace.as_deref(),
            Some("aincrad-system")
        );
        assert_eq!(
            tls_route.spec.backend,
            "chal-1-c-web.default.svc.cluster.local:80"
        );
        assert!(tls_route.spec.logs);

        // Check TCP route
        let tcp_route = planned
            .routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('p'))
            .unwrap();
        assert_eq!(
            tcp_route.metadata.namespace.as_deref(),
            Some("aincrad-system")
        );
        assert_eq!(
            tcp_route.spec.backend,
            "chal-1-c-pwn.default.svc.cluster.local:1337"
        );
        assert_eq!(tcp_route.spec.pow.as_ref().unwrap().difficulty, 5000);

        // Endpoints
        assert_eq!(planned.endpoints[0].name, "pwn");
        assert_eq!(planned.endpoints[0].type_, "tcp");
        assert_eq!(planned.endpoints[1].name, "web");
        assert_eq!(planned.endpoints[1].type_, "tls");
    }

    #[test]
    fn test_build_merged_route_spec_overrides() {
        let base_spec = RouteSpec {
            backend: RouteBackend {
                service: "web".into(),
                port: 8080,
            },
            tcp: Some(RouteSpecTCP { port: Some(443) }),
            tls: Some(RouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            port: PatchValue::Value(8443),
            tls: PatchValue::Value(RouteSpecTLSPatch {
                prefix: PatchValue::Value("custom-prefix".into()),
            }),
        };

        let merged = build_merged_route_spec(&base_spec, Some(&override_spec));

        assert_eq!(merged.tcp, Some(RouteSpecTCP { port: Some(8443) }));
        assert_eq!(
            merged.tls,
            Some(RouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            })
        );
    }

    #[test]
    fn test_intra_template_port_collision() {
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        let allocator = RouteAllocator::new(ports, "seed", "c.noctf.dev", 4433);

        let instance = dummy_instance("chal-1", None);
        let mut template = crate::test_utils::tests::dummy_resolved_template(1);
        template.spec.routes = vec![
            k8s_common::crd::CTFTemplateSpecRoute {
                name: "route-a".into(),
                spec: RouteSpec {
                    backend: RouteBackend {
                        service: "pwn1".into(),
                        port: 1337,
                    },
                    tcp: Some(RouteSpecTCP { port: Some(20001) }),
                    ..Default::default()
                },
            },
            k8s_common::crd::CTFTemplateSpecRoute {
                name: "route-b".into(),
                spec: RouteSpec {
                    backend: RouteBackend {
                        service: "pwn2".into(),
                        port: 1338,
                    },
                    tcp: Some(RouteSpecTCP { port: Some(20001) }),
                    ..Default::default()
                },
            },
        ];

        let res = ProxyRoutePlanner::plan(
            &instance,
            &template,
            &allocator,
            "aincrad-system",
            "cluster.local",
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            Error::RouteAllocationError(crate::routing::RouteError::Port(
                crate::routing::PortError::Occupied(port, owner),
            )) => {
                assert_eq!(port, 20001);
                assert_eq!(owner.route, "route-a");
            }
            other => panic!("Expected RouteAllocationError(Occupied), got: {:?}", other),
        }
    }
}

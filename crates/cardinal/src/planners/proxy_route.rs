use k8s_common::crd::{
    CTFInstance, CTFInstanceSpecRouteOverride, CTFInstanceStatus, CTFInstanceStatusEndpoint,
    CTFProxyRoute, CTFProxyRouteSpec, CTFProxyRouteSpecPOW, PatchValue, RouteSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::jiff::Timestamp;

use crate::{
    Context, Error, btreemap,
    planners::{Planner, apply_condition, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    routing::{AllocatedRoute, RouteKey},
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

impl Planner for ProxyRoutePlanner {
    const KIND: &'static str = "CTFProxyRoute";
    type Resource = CTFProxyRoute;

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<CTFProxyRoute>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let allocator = ctx
            .route_allocator
            .as_deref()
            .ok_or_else(|| Error::Custom("route allocator not available".to_string()))?;
        let system_namespace = &ctx.system_namespace;
        let cluster_domain = &ctx.cluster_domain;

        let mut routes = Vec::new();

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
            set_owner_ref(&mut proxy_route, instance);

            routes.push(proxy_route);
        }

        Ok(routes)
    }

    fn check_status(
        instance: &CTFInstance,
        status: &mut CTFInstanceStatus,
        ctx: &Context,
    ) -> Result<(), Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let entry = ctx
            .template_cache
            .as_ref()
            .and_then(|cache| cache.get(instance_ns, &instance.spec.template));

        let Some(entry) = entry else {
            apply_condition(
                status,
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "Unknown".to_string(),
                    reason: "TemplateNotFound".to_string(),
                    message: "No proxy routes planned without a resolved template".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        Timestamp::now(),
                    ),
                    observed_generation: None,
                },
            );
            return Ok(());
        };
        let template = &entry.template;

        let allocator = ctx.route_allocator.as_deref();
        let mut endpoints = Vec::new();
        let mut unallocated: Vec<String> = Vec::new();

        for route_tmpl in &template.spec.routes {
            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);
            let merged_spec = build_merged_route_spec(&route_tmpl.spec, route_override);
            let route_key = RouteKey::new(instance_ns, instance_name, &route_tmpl.name);

            if let Some(allocator) = allocator {
                // TLS hostnames are derived deterministically from the route key,
                // so a planned route is considered successful once applied.
                if let Some(_target) = merged_spec.target() {
                    match allocator.allocate(&route_key, &merged_spec) {
                        Ok(alloc) => endpoints.push(alloc.endpoint),
                        Err(_) => unallocated.push(route_tmpl.name.clone()),
                    }
                } else {
                    unallocated.push(route_tmpl.name.clone());
                }
            } else {
                unallocated.push(route_tmpl.name.clone());
            }
        }

        if unallocated.is_empty() {
            endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
            status.endpoints = endpoints;

            apply_condition(
                status,
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "True".to_string(),
                    reason: "RoutesAllocated".to_string(),
                    message: format!("{} proxy route(s) allocated", template.spec.routes.len()),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        Timestamp::now(),
                    ),
                    observed_generation: None,
                },
            );
            return Ok(());
        }

        apply_condition(
            status,
            Condition {
                type_: Self::KIND.to_string(),
                status: "Unknown".to_string(),
                reason: "RoutesNotAllocated".to_string(),
                message: format!("Proxy route(s) not allocated: {}", unallocated.join(", ")),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: None,
            },
        );
        Ok(())
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
    use crate::test_utils::tests::{
        dummy_context, dummy_context_with_routes, dummy_instance, dummy_resolved_template,
    };
    use k8s_common::crd::{
        CTFTemplateSpecRoute, RouteBackend, RouteSpec, RouteSpecPOW, RouteSpecTCP, RouteSpecTLS,
        RouteSpecTLSPatch,
    };

    #[tokio::test]
    async fn test_plan_proxy_routes_tcp_and_tls() {
        let (_store, ctx) = dummy_context();
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

        let routes = ProxyRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(routes.len(), 2);

        let tls_route = routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('r'))
            .unwrap();
        assert_eq!(
            tls_route.metadata.namespace.as_deref(),
            Some("aincrad-system")
        );
        assert_eq!(
            tls_route.spec.backend,
            "chal-1-web.default.svc.cluster.local:80"
        );
        assert!(tls_route.spec.logs);

        let tcp_route = routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('p'))
            .unwrap();
        assert_eq!(
            tcp_route.metadata.namespace.as_deref(),
            Some("aincrad-system")
        );
        assert_eq!(
            tcp_route.spec.backend,
            "chal-1-pwn.default.svc.cluster.local:1337"
        );
        assert_eq!(tcp_route.spec.pow.as_ref().unwrap().difficulty, 5000);
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
                prefix: Some("custom-prefix".into())
            })
        );
    }

    #[tokio::test]
    async fn test_tls_route_sets_endpoint_and_marks_routes_allocated() {
        use k8s_common::crd::{CTFTemplateSpecRoute, RouteSpecTLS};

        let tls_route = CTFTemplateSpecRoute {
            name: "web".to_string(),
            spec: RouteSpec {
                backend: RouteBackend {
                    service: "web".into(),
                    port: 80,
                },
                tls: Some(RouteSpecTLS {
                    prefix: Some("web".into()),
                }),
                ..Default::default()
            },
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tls_route]);

        let mut status = CTFInstanceStatus::default();
        ProxyRoutePlanner::check_status(&dummy_instance("chal-1", None), &mut status, &ctx)
            .unwrap();

        assert!(
            !status.endpoints.is_empty(),
            "TLS endpoint must appear in instance status"
        );
        let tls_ep = status
            .endpoints
            .iter()
            .find(|e| e.type_ == "tls")
            .expect("TLS endpoint present");
        assert_eq!(tls_ep.name, "web");

        let cond = status
            .conditions
            .iter()
            .find(|c| c.type_ == ProxyRoutePlanner::KIND)
            .unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "RoutesAllocated");
    }

    #[tokio::test]
    async fn test_no_routes_marks_condition_true() {
        let (_store, ctx) = dummy_context();

        let mut status = CTFInstanceStatus::default();
        ProxyRoutePlanner::check_status(&dummy_instance("chal-1", None), &mut status, &ctx)
            .unwrap();

        assert!(
            status.endpoints.is_empty(),
            "no routes means no endpoints"
        );
        let cond = status
            .conditions
            .iter()
            .find(|c| c.type_ == ProxyRoutePlanner::KIND)
            .unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "RoutesAllocated");
    }
}

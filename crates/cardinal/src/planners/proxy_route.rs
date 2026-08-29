use std::collections::BTreeMap;

use k8s_common::{
    ROUTE_LABEL,
    crd::{
        CTFInstance, CTFInstanceSpecRouteOverride, CTFInstanceStatusEndpoint, CTFProxyRoute,
        CTFProxyRouteSpec, RouteSpec,
    },
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::jiff::Timestamp;

use crate::{
    Context, Error, btreemap,
    planners::Planner,
    reconcilers::template::ResolvedTemplate,
    routing::{AllocatedRoute, RouteKey},
    utils::labels::{INSTANCE_LABEL, INSTANCE_NAMESPACE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE},
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

        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), &template.params_map);

        for route_tmpl in &template.spec.routes {
            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);

            let policy = template.get_patched_route_policy(route_tmpl, &context_map)?;
            let mut merged_spec = route_tmpl.clone();
            merged_spec.policy = policy;
            let merged_spec = build_merged_route_spec(&merged_spec, route_override);
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
                ROUTE_LABEL => route_tmpl.name.as_str(),
            };

            let proxy_spec = CTFProxyRouteSpec {
                backend: backend_addr,
                policy: merged_spec.policy,
            };

            let mut proxy_route = CTFProxyRoute::new(&allocated.proxy_key.to_string(), proxy_spec);
            proxy_route.metadata.namespace = Some(system_namespace.to_string());
            proxy_route.metadata.labels = Some(labels);

            routes.push(proxy_route);
        }

        Ok(routes)
    }

    fn check_status(
        instance: &CTFInstance,
        ctx: &Context,
    ) -> Result<(Condition, Option<k8s_common::crd::CTFInstanceResources>), Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let entry = ctx
            .template_cache
            .as_ref()
            .and_then(|cache| cache.get(instance_ns, &instance.spec.template));

        let Some(entry) = entry else {
            return Ok((
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
                None,
            ));
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
            let merged_spec = build_merged_route_spec(route_tmpl, route_override);
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

        let now: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time =
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(Timestamp::now());

        if unallocated.is_empty() {
            endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
            return Ok((
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "True".to_string(),
                    reason: "RoutesAllocated".to_string(),
                    message: format!("{} proxy route(s) allocated", template.spec.routes.len()),
                    last_transition_time: now.clone(),
                    observed_generation: instance.metadata.generation,
                },
                Some(k8s_common::crd::CTFInstanceResources {
                    endpoints: Some(endpoints),
                }),
            ));
        }

        Ok((
            Condition {
                type_: Self::KIND.to_string(),
                status: "False".to_string(),
                reason: "RoutesNotAllocated".to_string(),
                message: format!("Proxy route(s) not allocated: {}", unallocated.join(", ")),
                last_transition_time: now,
                observed_generation: instance.metadata.generation,
            },
            Some(k8s_common::crd::CTFInstanceResources {
                endpoints: Some(endpoints),
            }),
        ))
    }
}

/// Builds a merged `RouteSpec` applying optional instance-level overrides.
pub fn build_merged_route_spec(
    base: &RouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> RouteSpec {
    let mut merged = base.clone();

    if let Some(ov) = override_spec {
        // The override always wins on conflict. An explicit tcp turns the route
        // into a TCP route (clearing any template tls) and vice versa.
        if let Some(tcp) = &ov.tcp {
            let mut tcp_cfg = merged.tcp.unwrap_or_default();
            if let Some(port) = tcp.port {
                tcp_cfg.port = Some(port);
            }
            merged.tcp = Some(tcp_cfg);
            merged.tls = None;
        } else if let Some(tls) = &ov.tls {
            merged.tls = Some(tls.clone());
            merged.tcp = None;
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
        RouteBackend, RoutePolicySpec, RouteSpec, RouteSpecPOW, RouteSpecTCP, RouteSpecTLS,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_plan_proxy_routes_tcp_and_tls() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![
            RouteSpec {
                name: "web".to_string(),
                backend: RouteBackend {
                    service: "web".to_string(),
                    port: 80,
                },
                tls: Some(RouteSpecTLS {
                    prefix: Some("whoami".into()),
                }),
                policy: RoutePolicySpec {
                    logs: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            RouteSpec {
                name: "pwn".to_string(),
                backend: RouteBackend {
                    service: "pwn".to_string(),
                    port: 1337,
                },
                tcp: Some(RouteSpecTCP { port: Some(0) }),
                policy: RoutePolicySpec {
                    pow: Some(RouteSpecPOW {
                        difficulty: 5000,
                        enable_admin_bypass: true,
                    }),
                    ..Default::default()
                },
                ..Default::default()
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
        assert!(tls_route.spec.policy.logs);

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
        assert_eq!(tcp_route.spec.policy.pow.as_ref().unwrap().difficulty, 5000);
    }

    #[tokio::test]
    async fn test_plan_proxy_routes_do_not_set_owner_ref() {
        // Cross-namespace owner refs are invalid and would GC the route.
        // Its lifecycle is governed by the finalizer + label pruning instead.
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![RouteSpec {
            name: "web".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tls: Some(RouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        }];

        let routes = ProxyRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(routes.len(), 1);
        assert!(
            routes[0].metadata.owner_references.is_none(),
            "CTFProxyRoute must not reference a cross-namespace owner"
        );
    }

    #[tokio::test]
    async fn test_plan_proxy_routes_patches_policy() {
        use crate::planners::replicaset::ROUTE_POLICY_PATCH_BLACKLIST;
        use crate::reconcilers::template::ResolvedTemplate;
        use k8s_common::SpecPatcher;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use serde_json::json;

        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);

        let patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/flag", "value": "{{ params.FLAG }}" }
        ]))
        .unwrap();
        let patcher = SpecPatcher::new(&ROUTE_POLICY_PATCH_BLACKLIST, patch).unwrap();

        let route = RouteSpec {
            name: "web".into(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tls: Some(RouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let mut route_patchers = std::collections::HashMap::new();
        route_patchers.insert("web".to_string(), Some(patcher));

        let mut params_map = BTreeMap::new();
        params_map.insert("FLAG".to_string(), "CTF{patched}".to_string());

        let template = ResolvedTemplate {
            metadata: ObjectMeta::default(),
            spec: k8s_common::crd::CTFTemplateSpec {
                routes: vec![route],
                ..Default::default()
            },
            pod_patchers: Arc::new(std::collections::HashMap::new()),
            route_patchers: Arc::new(route_patchers),
            params_map,
        };

        let routes = ProxyRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        let tls_route = routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('r'))
            .unwrap();
        assert_eq!(tls_route.spec.policy.flag.as_deref(), Some("CTF{patched}"));
    }

    #[test]
    fn test_build_merged_route_spec_tcp_override_wins() {
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
            tcp: Some(RouteSpecTCP { port: Some(8443) }),
            tls: None,
        };

        let merged = build_merged_route_spec(&base_spec, Some(&override_spec));
        assert_eq!(merged.tcp, Some(RouteSpecTCP { port: Some(8443) }));
        assert_eq!(
            merged.tls, None,
            "an explicit tcp override must clear a conflicting template tls"
        );
    }

    #[test]
    fn test_build_merged_route_spec_tls_override_wins() {
        let base_spec = RouteSpec {
            backend: RouteBackend {
                service: "web".into(),
                port: 8080,
            },
            tcp: Some(RouteSpecTCP { port: Some(443) }),
            ..Default::default()
        };

        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            tcp: None,
            tls: Some(RouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            }),
        };

        let merged = build_merged_route_spec(&base_spec, Some(&override_spec));
        assert_eq!(
            merged.tls,
            Some(RouteSpecTLS {
                prefix: Some("custom-prefix".into())
            })
        );
        assert_eq!(
            merged.tcp, None,
            "an explicit tls override must clear a conflicting template tcp"
        );
    }

    #[test]
    fn test_build_merged_route_spec_inherits_when_no_override() {
        let base_spec = RouteSpec {
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
        };
        let override_spec = CTFInstanceSpecRouteOverride {
            name: "main".into(),
            tcp: None,
            tls: None,
        };

        let merged = build_merged_route_spec(&base_spec, Some(&override_spec));
        assert_eq!(merged.tcp, Some(RouteSpecTCP { port: Some(0) }));
        assert_eq!(merged.tls, None);
    }

    #[tokio::test]
    async fn test_tls_route_sets_endpoint_and_marks_routes_allocated() {
        let tls_route = RouteSpec {
            name: "web".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tls: Some(RouteSpecTLS {
                prefix: Some("web".into()),
            }),
            ..Default::default()
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tls_route]);

        let (cond, payload) =
            ProxyRoutePlanner::check_status(&dummy_instance("chal-1", None), &ctx).unwrap();

        let endpoints = payload
            .expect("endpoints payload present")
            .endpoints
            .expect("endpoints list present");
        assert!(
            !endpoints.is_empty(),
            "TLS endpoint must appear in instance status"
        );
        let tls_ep = endpoints
            .iter()
            .find(|e| e.type_ == "tls")
            .expect("TLS endpoint present");
        assert_eq!(tls_ep.name, "web");

        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "RoutesAllocated");
    }

    #[tokio::test]
    async fn test_no_routes_marks_condition_true() {
        let (_store, ctx) = dummy_context();

        let (cond, payload) =
            ProxyRoutePlanner::check_status(&dummy_instance("chal-1", None), &ctx).unwrap();

        assert!(
            payload.is_none()
                || payload
                    .unwrap()
                    .endpoints
                    .as_ref()
                    .is_none_or(|e| e.is_empty()),
            "no routes means no endpoints"
        );
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "RoutesAllocated");
    }
}

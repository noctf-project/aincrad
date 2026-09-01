use std::collections::BTreeMap;

use k8s_common::{
    RESOURCE_LABEL,
    crd::{
        CTFInstance, CTFInstanceSpecRouteOverride, CTFInstanceStatusEndpoint, CTFProxyRoute,
        CTFProxyRouteSpec, EndpointTarget, RouteSpec, RouteTarget,
    },
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::jiff::Timestamp;

use crate::{
    Context, Error, btreemap,
    cache::{ResourceKey, ResourceProjection},
    planners::Planner,
    reconcilers::template::ResolvedTemplate,
    routing::{PortCandidate, PortError, RouteError, derive_hostname, format_tls_host},
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

    fn cache(ctx: &Context) -> Option<&crate::cache::ResourceCache<Self::Resource>> {
        Some(&ctx.caches.proxy_routes)
    }

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<CTFProxyRoute>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let port_map = ctx
            .port_map
            .as_deref()
            .ok_or_else(|| Error::Custom("port map not available".to_string()))?;
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
            let route_key = ResourceKey::new(ns, instance_name, &route_tmpl.name);

            let route_name = match merged_spec.target() {
                Some(RouteTarget::Tcp(tcp)) => {
                    let port = tcp.port.unwrap_or(0);
                    if port != 0 {
                        if !port_map.is_reserved_port(port) {
                            return Err(RouteError::Port(PortError::OutOfRange(port)).into());
                        }
                        format!("p{port}")
                    } else {
                        "p0".to_string()
                    }
                }
                Some(RouteTarget::Tls(tls)) => {
                    let hostname =
                        derive_hostname(&ctx.route_seed, &route_key, tls.prefix.as_deref());
                    format!("r{hostname}")
                }
                None => return Err(RouteError::MissingTarget.into()),
            };

            let backend_svc = resource_name(instance_name, &merged_spec.backend.service);
            let backend_addr = format!(
                "{}.{}.svc.{}:{}",
                backend_svc, ns, cluster_domain, merged_spec.backend.port
            );

            let labels = btreemap! {
                RESOURCE_LABEL => route_tmpl.name.as_str(),
            };

            let proxy_spec = CTFProxyRouteSpec {
                backend: backend_addr,
                policy: merged_spec.policy,
            };

            let mut proxy_route = CTFProxyRoute::new(&route_name, proxy_spec);
            proxy_route.metadata.namespace = Some(system_namespace.to_string());
            proxy_route.metadata.labels = Some(labels);

            routes.push(proxy_route);
        }

        Ok(routes)
    }

    async fn apply(
        api: &kube::Api<Self::Resource>,
        desired: Vec<Self::Resource>,
        ctx: &Context,
    ) -> Result<(), Error> {
        let port_map = ctx
            .port_map
            .as_deref()
            .ok_or_else(|| Error::Custom("port map not available".to_string()))?;

        for mut route in desired {
            let name = route.metadata.name.as_deref().unwrap_or_default();

            if let Some(port_str) = name.strip_prefix('p') {
                let requested_port: u16 = port_str.parse().unwrap_or(0);
                let key = ResourceProjection::key(&route);

                const MAX_OCC_ATTEMPTS: usize = 3;
                let mut attempts = 0;
                let max_attempts = if requested_port == 0 {
                    MAX_OCC_ATTEMPTS
                } else {
                    1
                };
                loop {
                    match port_map
                        .find_free_port(&key, requested_port)
                        .map_err(RouteError::Port)?
                    {
                        PortCandidate::Bound(port) => {
                            route.metadata.name = Some(format!("p{port}"));
                            crate::reconcilers::helper::sync_resources(
                                api,
                                Self::KIND,
                                vec![route],
                            )
                            .await?;
                            break;
                        }
                        PortCandidate::Available(port) => {
                            route.metadata.name = Some(format!("p{port}"));
                            match api.create(&kube::api::PostParams::default(), &route).await {
                                Ok(_) => {
                                    port_map.bind(port, key.clone());
                                    break;
                                }
                                Err(kube::Error::Api(ref api_err)) if api_err.code == 409 => {
                                    if requested_port != 0 {
                                        return Err(RouteError::Port(PortError::Occupied(
                                            port,
                                            ResourceKey::new("unknown", "collision", ""),
                                        ))
                                        .into());
                                    }
                                    let collision_key =
                                        ResourceKey::new("unknown", "collision", "");
                                    port_map.bind(port, collision_key);
                                    attempts += 1;
                                    if attempts >= max_attempts {
                                        return Err(RouteError::Port(PortError::Exhausted).into());
                                    }
                                }
                                Err(e) => {
                                    return Err(Error::ApplyResource {
                                        kind: Self::KIND,
                                        name: format!("p{port}"),
                                        source: Box::new(e),
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                crate::reconcilers::helper::sync_resources(api, Self::KIND, vec![route]).await?;
            }
        }

        Ok(())
    }

    fn check_status(
        instance: &CTFInstance,
        ctx: &Context,
    ) -> Result<(Condition, Option<k8s_common::crd::CTFInstanceResources>), Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let instance_ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let cached = ctx
            .caches
            .proxy_routes
            .for_instance(instance_ns, instance_name);

        let expected_names = instance
            .status
            .as_ref()
            .and_then(|s| s.children.get(Self::KIND));

        let now = k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(Timestamp::now());

        let Some(expected) = expected_names else {
            if cached.is_empty() {
                return Ok((
                    Condition {
                        type_: Self::KIND.to_string(),
                        status: "False".to_string(),
                        reason: "Pending".to_string(),
                        message: "ProxyRoutes not yet present in cache".to_string(),
                        last_transition_time: now,
                        observed_generation: instance.metadata.generation,
                    },
                    None,
                ));
            }
            let endpoints = build_endpoints(&cached, &ctx.hostname_suffix, ctx.tls_port);
            return Ok((
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "True".to_string(),
                    reason: "RoutesAllocated".to_string(),
                    message: format!("All {} proxy route(s) allocated", cached.len()),
                    last_transition_time: now,
                    observed_generation: instance.metadata.generation,
                },
                Some(k8s_common::crd::CTFInstanceResources {
                    endpoints: Some(endpoints),
                }),
            ));
        };

        if expected.is_empty() {
            return Ok((
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "True".to_string(),
                    reason: "RoutesAllocated".to_string(),
                    message: "No proxy routes defined".to_string(),
                    last_transition_time: now,
                    observed_generation: instance.metadata.generation,
                },
                Some(k8s_common::crd::CTFInstanceResources {
                    endpoints: Some(Vec::new()),
                }),
            ));
        }

        let mut missing = Vec::new();
        let mut matched = Vec::new();
        for exp in expected {
            if let Some(entry) = cached.iter().find(|e| &e.name == exp) {
                matched.push(entry);
            } else {
                missing.push(exp.as_str());
            }
        }

        let endpoints = build_endpoints(matched, &ctx.hostname_suffix, ctx.tls_port);
        let (status, reason, message) = if missing.is_empty() {
            (
                "True",
                "RoutesAllocated",
                format!("All {} proxy route(s) allocated", expected.len()),
            )
        } else {
            (
                "False",
                "RoutesNotAllocated",
                format!("Proxy route(s) not allocated: {}", missing.join(", ")),
            )
        };

        Ok((
            Condition {
                type_: Self::KIND.to_string(),
                status: status.to_string(),
                reason: reason.to_string(),
                message,
                last_transition_time: now,
                observed_generation: instance.metadata.generation,
            },
            Some(k8s_common::crd::CTFInstanceResources {
                endpoints: Some(endpoints),
            }),
        ))
    }
}

/// Converts a cached proxy route entry into an instance status endpoint.
fn entry_to_endpoint(
    entry: &crate::cache::resource::ResourceEntry<()>,
    hostname_suffix: &str,
    tls_port: u16,
) -> Option<CTFInstanceStatusEndpoint> {
    if let Some(port_str) = entry.name.strip_prefix('p') {
        let port = port_str.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        Some(CTFInstanceStatusEndpoint {
            name: entry.key.resource.clone(),
            type_: "tcp".to_string(),
            target: EndpointTarget {
                host: hostname_suffix.to_string(),
                port,
            },
        })
    } else if let Some(hostname) = entry.name.strip_prefix('r') {
        let fqdn = format_tls_host(hostname_suffix, hostname);
        Some(CTFInstanceStatusEndpoint {
            name: entry.key.resource.clone(),
            type_: "tls".to_string(),
            target: EndpointTarget {
                host: fqdn,
                port: tls_port,
            },
        })
    } else {
        None
    }
}

/// Builds and sorts deterministic endpoints from a collection of cached proxy route entries.
fn build_endpoints<'a>(
    entries: impl IntoIterator<Item = &'a crate::cache::resource::ResourceEntry<()>>,
    hostname_suffix: &str,
    tls_port: u16,
) -> Vec<CTFInstanceStatusEndpoint> {
    let mut endpoints: Vec<_> = entries
        .into_iter()
        .filter_map(|e| entry_to_endpoint(e, hostname_suffix, tls_port))
        .collect();
    endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
    endpoints
}

/// Builds a merged `RouteSpec` applying optional instance-level overrides.
pub fn build_merged_route_spec(
    base: &RouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> RouteSpec {
    let mut merged = base.clone();

    if let Some(ov) = override_spec {
        // Override wins on conflict. An explicit tcp turns the route into TCP and vice versa.
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
        CTFProxyRouteSpec, RouteBackend, RoutePolicySpec, RouteSpec, RouteSpecPOW, RouteSpecTCP,
        RouteSpecTLS,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::sync::Arc;

    fn proxy_route(name: &str, instance: &str, resource: &str) -> CTFProxyRoute {
        CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("aincrad-system".to_string()),
                labels: Some(crate::btreemap! {
                    crate::utils::labels::NAMESPACE_LABEL => "default",
                    crate::utils::labels::INSTANCE_LABEL => instance,
                    crate::utils::labels::RESOURCE_LABEL => resource,
                }),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "web.default.svc.cluster.local:80".to_string(),
                policy: Default::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_cached_names_returns_instance_proxy_routes() {
        let (_store, ctx) = dummy_context();
        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(proxy_route(
                "p30005", "chal-1", "web",
            )));

        let instance = dummy_instance("chal-1", None);
        let names = ProxyRoutePlanner::cached_names(&instance, &ctx).unwrap();
        assert_eq!(
            names,
            vec!["p30005".to_string()],
            "cached_names must surface proxy routes owned by the instance"
        );
    }

    #[tokio::test]
    async fn test_cached_names_ignores_other_instances() {
        let (_store, ctx) = dummy_context();
        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(proxy_route(
                "p30002", "chal-2", "pwn",
            )));

        let instance = dummy_instance("chal-1", None);
        let names = ProxyRoutePlanner::cached_names(&instance, &ctx).unwrap();
        assert!(
            names.is_empty(),
            "another instance's proxy routes must not be surfaced"
        );
    }

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

        let tcp_route = routes
            .iter()
            .find(|r| r.metadata.name.as_deref().unwrap().starts_with('p'))
            .unwrap();
        assert_eq!(
            tcp_route.metadata.namespace.as_deref(),
            Some("aincrad-system")
        );
        assert_eq!(tcp_route.metadata.name.as_deref(), Some("p0"));
        assert_eq!(
            tcp_route.spec.backend,
            "chal-1-pwn.default.svc.cluster.local:1337"
        );
        assert_eq!(tcp_route.spec.policy.pow.as_ref().unwrap().difficulty, 5000);
    }

    #[tokio::test]
    async fn test_plan_proxy_routes_fixed_tcp_in_range() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![RouteSpec {
            name: "admin".to_string(),
            backend: RouteBackend {
                service: "admin".to_string(),
                port: 8080,
            },
            tcp: Some(RouteSpecTCP { port: Some(20005) }),
            ..Default::default()
        }];

        let routes = ProxyRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metadata.name.as_deref(), Some("p20005"));
    }

    #[tokio::test]
    async fn test_plan_proxy_routes_fixed_tcp_out_of_range() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![RouteSpec {
            name: "admin".to_string(),
            backend: RouteBackend {
                service: "admin".to_string(),
                port: 8080,
            },
            tcp: Some(RouteSpecTCP { port: Some(10000) }),
            ..Default::default()
        }];

        let res = ProxyRoutePlanner::plan(&instance, &template, &ctx);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_plan_proxy_routes_do_not_set_owner_ref() {
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
        let (_store, ctx) = dummy_context();
        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(proxy_route(
                "rweb-abc12345",
                "chal-1",
                "web",
            )));

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: btreemap! {
                "CTFProxyRoute".to_string() => vec!["rweb-abc12345".to_string()],
            },
            ..Default::default()
        });

        let (cond, payload) = ProxyRoutePlanner::check_status(&instance, &ctx).unwrap();

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

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: btreemap! {
                "CTFProxyRoute".to_string() => Vec::new(),
            },
            ..Default::default()
        });

        let (cond, payload) = ProxyRoutePlanner::check_status(&instance, &ctx).unwrap();

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

    #[tokio::test]
    async fn test_check_status_unallocated_when_tcp_proxy_route_missing() {
        let (_store, ctx) = dummy_context();

        let mut instance = dummy_instance("chal-1", None);
        instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: btreemap! {
                "CTFProxyRoute".to_string() => vec!["p30005".to_string()],
            },
            ..Default::default()
        });

        let (cond, payload) = ProxyRoutePlanner::check_status(&instance, &ctx).unwrap();

        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "RoutesNotAllocated");
        assert!(payload.unwrap().endpoints.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_check_status_allocated_when_tcp_proxy_route_cached() {
        let tcp_route = RouteSpec {
            name: "pwn".to_string(),
            backend: RouteBackend {
                service: "pwn".into(),
                port: 1337,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
        };
        let (_store, ctx) = dummy_context_with_routes(vec![tcp_route]);

        ctx.caches
            .proxy_routes
            .handle(&kube::runtime::watcher::Event::Apply(proxy_route(
                "p30005", "chal-1", "pwn",
            )));

        let (cond, payload) =
            ProxyRoutePlanner::check_status(&dummy_instance("chal-1", None), &ctx).unwrap();

        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "RoutesAllocated");
        let endpoints = payload.unwrap().endpoints.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "pwn");
        assert_eq!(endpoints[0].type_, "tcp");
        assert_eq!(endpoints[0].target.port, 30005);
        assert_eq!(endpoints[0].target.host, "c.noctf.dev");
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_allocates_port_and_binds() {
        let (_template_store, ctx) = dummy_context();
        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");

        let mut planned_route = proxy_route("p0", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_ok());

        let key = ResourceKey::new("default", "chal-1", "pwn");
        let candidate = ctx.port_map.as_ref().unwrap().find_free_port(&key, 0);
        assert!(matches!(candidate, Ok(PortCandidate::Bound(_))));
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_bound_port_updates_via_ssa() {
        let (_store, ctx) = dummy_context();
        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");

        let key = ResourceKey::new("default", "chal-1", "pwn");
        ctx.port_map.as_ref().unwrap().bind(30005, key);

        let mut planned_route = proxy_route("p0", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_fixed_port_within_range_binds() {
        let (_store, ctx) = dummy_context();
        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");

        let mut planned_route = proxy_route("p20005", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_ok());

        let key = ResourceKey::new("default", "chal-1", "pwn");
        assert_eq!(ctx.port_map.as_ref().unwrap().get_key(20005), Some(key));
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_fixed_port_occupied_fails() {
        let (_store, ctx) = dummy_context();
        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");

        let other_key = ResourceKey::new("default", "other-chal", "pwn");
        ctx.port_map.as_ref().unwrap().bind(20005, other_key);

        let mut planned_route = proxy_route("p20005", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_409_conflict_retries_and_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();

        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());
        let service = tower::service_fn(move |_req: axum::http::Request<kube::client::Body>| {
            let count = calls_clone.fetch_add(1, Ordering::SeqCst);
            async move {
                if count == 0 {
                    let status = serde_json::json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": "already exists",
                        "reason": "AlreadyExists",
                        "code": 409
                    });
                    let body_str = serde_json::to_string(&status).unwrap();
                    Ok::<_, std::convert::Infallible>(
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::CONFLICT)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body_str))
                            .unwrap(),
                    )
                } else {
                    let body = serde_json::json!({
                        "apiVersion": "aincrad.noctf.dev/v1",
                        "kind": "CTFProxyRoute",
                        "metadata": { "name": "p30001", "namespace": "aincrad-system" },
                        "spec": { "backend": "pwn.default.svc.cluster.local:1337" }
                    });
                    let body_str = serde_json::to_string(&body).unwrap();
                    Ok::<_, std::convert::Infallible>(
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body_str))
                            .unwrap(),
                    )
                }
            }
        });

        let client = kube::Client::new(service, config.default_namespace);
        let (_store, ctx) = dummy_context();
        let ctx = Context {
            client,
            ..(*ctx).clone()
        };

        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");
        let mut planned_route = proxy_route("p0", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let key = ResourceKey::new("default", "chal-1", "pwn");
        let candidate = ctx.port_map.as_ref().unwrap().find_free_port(&key, 0);
        assert!(matches!(candidate, Ok(PortCandidate::Bound(_))));
    }

    #[tokio::test]
    async fn test_apply_proxy_routes_exhausted_after_max_409_conflicts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();

        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());
        let service = tower::service_fn(move |_req: axum::http::Request<kube::client::Body>| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            async move {
                let status = serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "already exists",
                    "reason": "AlreadyExists",
                    "code": 409
                });
                let body_str = serde_json::to_string(&status).unwrap();
                Ok::<_, std::convert::Infallible>(
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::CONFLICT)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body_str))
                        .unwrap(),
                )
            }
        });

        let client = kube::Client::new(service, config.default_namespace);
        let (_store, ctx) = dummy_context();
        let ctx = Context {
            client,
            ..(*ctx).clone()
        };

        let api = kube::Api::<CTFProxyRoute>::namespaced(ctx.client.clone(), "aincrad-system");
        let mut planned_route = proxy_route("p0", "chal-1", "pwn");
        planned_route.spec.backend = "pwn.default.svc.cluster.local:1337".to_string();

        let res = ProxyRoutePlanner::apply(&api, vec![planned_route], &ctx).await;
        assert!(res.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}

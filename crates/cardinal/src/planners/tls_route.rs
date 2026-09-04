use k8s_common::{
    crd::{
        BackendRef, CTFInstance, ParentReference, RouteTarget, TLSRoute, TLSRouteRule, TLSRouteSpec,
    },
    labels::RESOURCE_LABEL,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::{
    Context, Error, btreemap,
    cache::ResourceKey,
    planners::{Planner, helpers::build_merged_route_spec},
    reconcilers::template::ResolvedTemplate,
    routing::{derive_hostname, format_tls_host},
    utils::naming::resource_name,
};

pub struct TLSRoutePlanner;

impl Planner for TLSRoutePlanner {
    const KIND: &'static str = "TLSRoute";
    type Resource = TLSRoute;

    fn cache(ctx: &Context) -> Option<&crate::cache::ResourceCache<Self::Resource>> {
        Some(&ctx.caches.tls_routes)
    }

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<TLSRoute>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let mut routes = Vec::new();

        for route_tmpl in &template.spec.routes {
            let route_override = instance
                .spec
                .routes
                .iter()
                .find(|r| r.name == route_tmpl.name);

            let merged_spec = build_merged_route_spec(route_tmpl, route_override);
            let Some(RouteTarget::Tls(tls)) = merged_spec.target() else {
                continue;
            };

            let route_key = ResourceKey::new(ns, instance_name, &route_tmpl.name);
            let hostname = derive_hostname(&ctx.route_seed, &route_key, tls.prefix.as_deref());
            let route_name = resource_name(instance_name, &route_tmpl.name);
            let fqdn = format_tls_host(&ctx.hostname_suffix, &hostname);
            let backend_svc = resource_name(
                &format!("{instance_name}-svc"),
                &merged_spec.backend.service,
            );

            let labels = btreemap! {
                RESOURCE_LABEL => route_tmpl.name.as_str(),
            };

            let tls_route = TLSRoute {
                metadata: ObjectMeta {
                    name: Some(route_name),
                    namespace: Some(ns.to_string()),
                    labels: Some(labels),
                    ..Default::default()
                },
                spec: TLSRouteSpec {
                    parent_refs: Some(vec![ParentReference {
                        name: "envoy".to_string(),
                        namespace: Some(ctx.system_namespace.clone()),
                        ..Default::default()
                    }]),
                    hostnames: vec![fqdn],
                    rules: vec![TLSRouteRule {
                        name: None,
                        backend_refs: vec![BackendRef {
                            name: backend_svc,
                            port: Some(merged_spec.backend.port),
                            ..Default::default()
                        }],
                    }],
                },
            };

            routes.push(tls_route);
        }

        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_context, dummy_instance, dummy_resolved_template};
    use k8s_common::{
        crd::{CTFInstanceSpecRouteOverride, RouteBackend, RouteSpec, RouteSpecTCP, RouteSpecTLS},
        labels::{INSTANCE_LABEL, NAMESPACE_LABEL, RESOURCE_LABEL},
    };

    fn dummy_tls_route(name: &str, instance: &str, resource: &str) -> TLSRoute {
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    NAMESPACE_LABEL => "default",
                    INSTANCE_LABEL => instance,
                    RESOURCE_LABEL => resource,
                }),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: Some(vec![ParentReference {
                    name: "envoy".to_string(),
                    namespace: Some("aincrad-system".to_string()),
                    ..Default::default()
                }]),
                hostnames: vec!["web.c.noctf.dev".to_string()],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        name: "chal-1-web".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }],
                }],
            },
        }
    }

    #[tokio::test]
    async fn test_cached_names_returns_instance_tls_routes() {
        let (_store, ctx) = dummy_context();
        ctx.caches
            .tls_routes
            .handle(&kube::runtime::watcher::Event::Apply(dummy_tls_route(
                "chal-1-web",
                "chal-1",
                "web",
            )));

        let instance = dummy_instance("chal-1", None);
        let names = TLSRoutePlanner::cached_names(&instance, &ctx).unwrap();
        assert_eq!(names, vec!["chal-1-web".to_string()]);
    }

    #[tokio::test]
    async fn test_cached_names_empty_when_none_cached() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let names = TLSRoutePlanner::cached_names(&instance, &ctx).unwrap();
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn test_plan_tls_routes_generates_gateway_objects() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("busybox", None);
        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![
            RouteSpec {
                name: "echo".to_string(),
                backend: RouteBackend {
                    service: "echo".to_string(),
                    port: 1337,
                },
                tls: Some(RouteSpecTLS {
                    prefix: Some("echo".into()),
                }),
                ..Default::default()
            },
            RouteSpec {
                name: "tcp-route".to_string(),
                backend: RouteBackend {
                    service: "echo".to_string(),
                    port: 1338,
                },
                tcp: Some(RouteSpecTCP { port: Some(0) }),
                ..Default::default()
            },
        ];

        let routes = TLSRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(
            routes.len(),
            1,
            "TCP route must be ignored by TLSRoutePlanner"
        );

        let route = &routes[0];
        assert_eq!(route.metadata.name.as_deref(), Some("busybox-echo"));
        assert_eq!(route.metadata.namespace.as_deref(), Some("default"));

        let labels = route.metadata.labels.as_ref().unwrap();
        assert_eq!(labels.get(RESOURCE_LABEL), Some(&"echo".to_string()));

        let parent_refs = route.spec.parent_refs.as_ref().unwrap();
        assert_eq!(parent_refs.len(), 1);
        assert_eq!(parent_refs[0].name, "envoy");
        assert_eq!(parent_refs[0].namespace.as_deref(), Some("aincrad-system"));

        assert_eq!(route.spec.hostnames.len(), 1);
        assert!(route.spec.hostnames[0].starts_with("echo-"));
        assert!(route.spec.hostnames[0].ends_with(".c.noctf.dev"));

        assert_eq!(route.spec.rules.len(), 1);
        let backend_refs = &route.spec.rules[0].backend_refs;
        assert_eq!(backend_refs.len(), 1);
        assert_eq!(backend_refs[0].name, "busybox-svc-echo");
        assert_eq!(backend_refs[0].port, Some(1337));
    }

    #[tokio::test]
    async fn test_plan_tls_routes_with_instance_override() {
        let (_store, ctx) = dummy_context();
        let mut instance = dummy_instance("chal-1", None);
        instance.spec.routes = vec![CTFInstanceSpecRouteOverride {
            name: "web".to_string(),
            tls: Some(RouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            }),
            tcp: None,
        }];

        let mut template = dummy_resolved_template(1);
        template.spec.routes = vec![RouteSpec {
            name: "web".to_string(),
            backend: RouteBackend {
                service: "web".to_string(),
                port: 80,
            },
            tls: Some(RouteSpecTLS {
                prefix: Some("default-prefix".into()),
            }),
            ..Default::default()
        }];

        let routes = TLSRoutePlanner::plan(&instance, &template, &ctx).unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].spec.hostnames[0].starts_with("custom-prefix-"));
        assert!(routes[0].spec.hostnames[0].ends_with(".c.noctf.dev"));
    }
}

use std::collections::HashSet;

use k8s_common::crd::{
    CTFInstance, CTFInstanceSpecRouteOverride, CTFRoute, CTFRouteSpec, PatchValue,
};
use kube::Api;
use tracing::instrument;

use crate::{
    Context, Error,
    reconcilers::{
        helper::{prune_orphaned_resources, reconcile_child_resource},
        template::ResolvedTemplate,
    },
    utils::naming::resource_name,
};

/// Merges a base `CTFRouteSpec` from a template with an optional `CTFInstanceSpecRouteOverride`.
pub fn merge_route_spec(
    base: &CTFRouteSpec,
    override_spec: Option<&CTFInstanceSpecRouteOverride>,
) -> CTFRouteSpec {
    let mut merged = base.clone();

    if let Some(ov) = override_spec {
        match ov.port {
            PatchValue::Value(port) => {
                merged.port = Some(port);
            }
            PatchValue::Null => {
                merged.port = None;
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

/// Reconciles CTFRoute resources for dynamic routing/ingress.
#[instrument(skip(ctx, instance, template))]
pub async fn reconcile(
    instance: &CTFInstance,
    template: &ResolvedTemplate,
    ctx: &Context,
    instance_gen: Option<&str>,
    target_gen: &str,
) -> Result<(), Error> {
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let routes: Api<CTFRoute> = Api::namespaced(ctx.client.clone(), ns);
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let sync = instance.spec.sync;

    let mut desired_names = HashSet::new();

    for route_tmpl in &template.spec.routes {
        let route_name = resource_name(instance_name, &route_tmpl.name);
        desired_names.insert(route_name.clone());

        let route_override = instance
            .spec
            .routes
            .iter()
            .find(|r| r.name == route_tmpl.name);

        let merged_spec = merge_route_spec(&route_tmpl.spec, route_override);

        reconcile_child_resource(&routes, &route_name, instance_gen, target_gen, sync, || {
            let mut route = CTFRoute::new(&route_name, merged_spec.clone());
            route.metadata.namespace = Some(ns.to_string());
            route
        })
        .await?;
    }

    prune_orphaned_resources(&routes, instance_name, &desired_names).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFRouteBackend, CTFRouteSpecTLS, CTFRouteSpecTLSPatch};

    #[test]
    fn test_merge_route_spec_port_and_tls_overrides() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
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

        let merged = merge_route_spec(&base_spec, Some(&override_spec));

        assert_eq!(merged.port, Some(8443));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("custom-prefix".into()),
            })
        );
    }

    #[test]
    fn test_merge_route_spec_disable_port_via_null() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
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

        let merged = merge_route_spec(&base_spec, Some(&override_spec));

        assert_eq!(merged.port, Some(443));
        assert_eq!(merged.tls, None);
    }

    #[test]
    fn test_merge_route_spec_no_override() {
        let base_spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "web".into(),
                port: 8080,
            },
            port: Some(443),
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let merged = merge_route_spec(&base_spec, None);

        assert_eq!(merged.port, Some(443));
        assert_eq!(
            merged.tls,
            Some(CTFRouteSpecTLS {
                prefix: Some("whoami".into()),
            })
        );
    }
}

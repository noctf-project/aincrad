use k8s_common::crd::{CTFInstance, CTFInstanceStatus, CTFInstanceStatusEndpoint};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use tracing::{info, instrument};

use crate::{Context, Error};

/// Computes the child route status summary (ready routes count M, total routes count N, and endpoints list).
pub fn compute_child_route_status(
    instance: &CTFInstance,
    ctx: &Context,
) -> (usize, usize, Vec<CTFInstanceStatusEndpoint>) {
    let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let routes = ctx
        .route_cache
        .as_ref()
        .map(|cache| cache.find_instance_routes(ns, instance_name))
        .unwrap_or_default();

    let total_routes = routes.len();
    let mut ready_routes = 0;
    let mut endpoints = Vec::new();

    for route in &routes {
        let mut is_ready = false;

        if let Some(status) = &route.status {
            // Skip checking none as ready cannot exist if generation doesn't
            let is_gen_current = status.observed_generation == route.metadata.generation;

            let has_ready_condition = status
                .conditions
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True");

            let mut has_endpoints = false;

            if let Some(route_endpoints) = &status.endpoints {
                let route_name = route
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(crate::utils::labels::POD_LABEL))
                    .cloned()
                    .unwrap_or_else(|| route.metadata.name.clone().unwrap_or_default());

                if let Some(tls) = &route_endpoints.tls {
                    endpoints.push(CTFInstanceStatusEndpoint {
                        name: route_name.clone(),
                        type_: "tls".to_string(),
                        target: tls.clone(),
                    });
                    has_endpoints = true;
                }
                if let Some(tcp) = &route_endpoints.tcp {
                    endpoints.push(CTFInstanceStatusEndpoint {
                        name: route_name,
                        type_: "tcp".to_string(),
                        target: tcp.clone(),
                    });
                    has_endpoints = true;
                }
            }

            if is_gen_current && (has_ready_condition || has_endpoints) {
                is_ready = true;
            }
        }

        if is_ready {
            ready_routes += 1;
        }
    }

    endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
    (ready_routes, total_routes, endpoints)
}

/// Collects status endpoints from child resources (e.g. `CTFRoute`) stored in the route cache.
pub fn collect_child_endpoints(
    instance: &CTFInstance,
    ctx: &Context,
) -> Vec<CTFInstanceStatusEndpoint> {
    let (_, _, endpoints) = compute_child_route_status(instance, ctx);
    endpoints
}

/// Helper function to build the RoutesReady status condition based on ready routes (M) and total routes (N).
///
/// Evaluates the ratio of ready CTFRoute objects (M) against total CTFRoute objects (N).
/// Condition status transitions to True once all N routes have Ready=True or allocated endpoints.
pub fn build_routes_ready_condition(
    ready_routes: usize,
    total_routes: usize,
    now: Time,
    observed_generation: Option<i64>,
) -> Condition {
    if total_routes == 0 {
        return Condition {
            type_: "RoutesReady".to_string(),
            status: "True".to_string(),
            reason: "NoRoutes".to_string(),
            message: "No routes configured for instance".to_string(),
            last_transition_time: now,
            observed_generation,
        };
    }

    let is_ready = ready_routes >= total_routes;
    Condition {
        type_: "RoutesReady".to_string(),
        status: if is_ready {
            "True".to_string()
        } else {
            "False".to_string()
        },
        reason: if is_ready {
            "AllRoutesReady".to_string()
        } else {
            "RoutesPending".to_string()
        },
        message: format!("{ready_routes}/{total_routes} routes ready"),
        last_transition_time: now,
        observed_generation,
    }
}

/// Reconciles child resource status (such as CTFRoute endpoints) onto CTFInstance status when child workload reconciliation is skipped.
#[instrument(skip(ctx, instance))]
pub async fn reconcile_child_status(instance: &CTFInstance, ctx: &Context) -> Result<bool, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let (ready_routes, total_routes, current_endpoints) = compute_child_route_status(instance, ctx);
    let now = Time(Timestamp::now());
    let observed_gen = instance.metadata.generation;

    let routes_ready_condition =
        build_routes_ready_condition(ready_routes, total_routes, now, observed_gen);

    let mut conditions = instance
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    if let Some(pos) = conditions.iter().position(|c| c.type_ == "RoutesReady") {
        conditions[pos] = routes_ready_condition.clone();
    } else {
        conditions.push(routes_ready_condition.clone());
    }

    let observed_endpoints = instance.status.as_ref().map(|s| &s.endpoints);
    let observed_routes_ready = instance
        .status
        .as_ref()
        .and_then(|s| s.conditions.iter().find(|c| c.type_ == "RoutesReady"));

    let routes_ready_changed = match observed_routes_ready {
        Some(c) => {
            c.status != routes_ready_condition.status || c.message != routes_ready_condition.message
        }
        None => true,
    };

    if observed_endpoints == Some(&current_endpoints) && !routes_ready_changed {
        return Ok(false);
    }

    info!(
        name,
        ns, "Updating CTFInstance status endpoints and RoutesReady condition from child resources"
    );
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
    let status_patch = serde_json::json!({
        "status": {
            "endpoints": current_endpoints,
            "conditions": conditions,
        }
    });

    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(status_patch),
        )
        .await?;

    Ok(true)
}

/// Updates CTFInstance status conditions to Ready and stamps observed generations.
#[instrument(skip(ctx, instance))]
pub async fn reconcile(
    instance: &CTFInstance,
    ctx: &Context,
    template_gen: Option<i64>,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

    let now = Time(Timestamp::now());
    let observed_generation = instance.metadata.generation;
    let template_generation = template_gen;
    let restarted_at = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
        .cloned();
    let (ready_routes, total_routes, endpoints) = compute_child_route_status(instance, ctx);

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "True".to_string(),
        reason: "Reconciled".to_string(),
        message: "CTFInstance reconciled successfully".to_string(),
        last_transition_time: now.clone(),
        observed_generation,
    };

    let routes_ready_condition =
        build_routes_ready_condition(ready_routes, total_routes, now, observed_generation);

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition, routes_ready_condition],
            endpoints,
        }
    });

    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(status_patch),
        )
        .await?;

    Ok(())
}

/// Updates CTFInstance status conditions to indicate reconciliation failure.
#[instrument(skip(ctx, instance, err))]
pub async fn reconcile_failure(
    instance: &CTFInstance,
    ctx: &Context,
    err: &Error,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

    let now = Time(Timestamp::now());
    let observed_generation = instance.status.as_ref().and_then(|s| s.observed_generation);
    let template_generation = instance.status.as_ref().and_then(|s| s.template_generation);
    let restarted_at = instance
        .status
        .as_ref()
        .and_then(|s| s.restarted_at.clone());
    let endpoints = instance
        .status
        .as_ref()
        .map(|s| s.endpoints.clone())
        .unwrap_or_default();

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "False".to_string(),
        reason: "ReconciliationFailed".to_string(),
        message: err.to_string(),
        last_transition_time: now,
        observed_generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition],
            endpoints,
        }
    });

    instances
        .patch_status(
            name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(status_patch),
        )
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btreemap;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client};
    use crate::utils::labels::{INSTANCE_LABEL, POD_LABEL};
    use k8s_common::crd::{
        CTFRoute, CTFRouteEndpoints, CTFRouteSpec, CTFRouteStatus, EndpointTarget,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::store;
    use kube::runtime::watcher::Event;

    #[tokio::test]
    async fn test_reconcile_status() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let mut instance = dummy_instance("chal-1", Some("1"));
        instance.metadata.generation = Some(2);

        let res = reconcile(&instance, &ctx, Some(3)).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_failure() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", None);
        let err = Error::TemplateNotFound("missing".to_string());

        let res = reconcile_failure(&instance, &ctx, &err).await;
        assert!(res.is_ok());
    }

    #[test]
    fn test_build_routes_ready_condition() {
        let now = Time(Timestamp::now());

        // Zero expected routes
        let cond_zero = build_routes_ready_condition(0, 0, now.clone(), Some(1));
        assert_eq!(cond_zero.status, "True");
        assert_eq!(cond_zero.reason, "NoRoutes");

        // Partial routes ready (1 of 2 ready)
        let cond_pending = build_routes_ready_condition(1, 2, now.clone(), Some(1));
        assert_eq!(cond_pending.status, "False");
        assert_eq!(cond_pending.reason, "RoutesPending");
        assert_eq!(cond_pending.message, "1/2 routes ready");

        // All routes ready (2 of 2 ready)
        let cond_all = build_routes_ready_condition(2, 2, now, Some(1));
        assert_eq!(cond_all.status, "True");
        assert_eq!(cond_all.reason, "AllRoutesReady");
        assert_eq!(cond_all.message, "2/2 routes ready");
    }

    #[tokio::test]
    async fn test_collect_child_endpoints_empty_store() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", None);

        let endpoints = collect_child_endpoints(&instance, &ctx);
        assert!(endpoints.is_empty());
    }

    #[tokio::test]
    async fn test_collect_child_endpoints_from_route_store() {
        let client = dummy_kube_client();
        let (template_store, _) = store();
        let (route_store, mut route_writer) = store();

        let ctx = Context::with_stores(client, template_store, route_store);
        let instance = dummy_instance("chal-1", None);

        let route1 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-1-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 20001,
                    }),
                }),
                ..Default::default()
            }),
        };

        let route2_other_instance = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-2-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-2",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "other.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        route_writer.apply_watcher_event(&Event::Apply(route1.clone()));
        route_writer.apply_watcher_event(&Event::Apply(route2_other_instance.clone()));
        if let Some(cache) = &ctx.route_cache {
            cache.update(&route1);
            cache.update(&route2_other_instance);
        }

        let endpoints = collect_child_endpoints(&instance, &ctx);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].name, "web");
        assert_eq!(endpoints[0].type_, "tcp");
        assert_eq!(endpoints[0].target.port, 20001);
        assert_eq!(endpoints[1].name, "web");
        assert_eq!(endpoints[1].type_, "tls");
        assert_eq!(endpoints[1].target.port, 443);
    }

    #[tokio::test]
    async fn test_reconcile_child_status_no_change() {
        let client = dummy_kube_client();
        let (template_store, _) = store();
        let (route_store, mut route_writer) = store();

        let ctx = Context::with_stores(client, template_store, route_store);
        let mut instance = dummy_instance("chal-1", None);

        let route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-1-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };
        route_writer.apply_watcher_event(&Event::Apply(route.clone()));
        if let Some(cache) = &ctx.route_cache {
            cache.update(&route);
        }

        // Preset status endpoints on instance matching the route
        instance.status = Some(CTFInstanceStatus {
            endpoints: vec![CTFInstanceStatusEndpoint {
                name: "web".into(),
                type_: "tls".into(),
                target: EndpointTarget {
                    host: "web.c.noctf.dev".into(),
                    port: 443,
                },
            }],
            conditions: vec![Condition {
                type_: "RoutesReady".into(),
                status: "True".into(),
                reason: "AllRoutesReady".into(),
                message: "1/1 routes ready".into(),
                last_transition_time: Time(Timestamp::now()),
                observed_generation: None,
            }],
            ..Default::default()
        });

        let updated = reconcile_child_status(&instance, &ctx).await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn test_reconcile_child_status_updates_when_endpoints_change() {
        let client = dummy_kube_client();
        let (template_store, _) = store();
        let (route_store, mut route_writer) = store();

        let ctx = Context::with_stores(client, template_store, route_store);
        let instance = dummy_instance("chal-1", None);

        let route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-1-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };
        route_writer.apply_watcher_event(&Event::Apply(route.clone()));
        if let Some(cache) = &ctx.route_cache {
            cache.update(&route);
        }

        // Instance has no status endpoints initially
        let updated = reconcile_child_status(&instance, &ctx).await.unwrap();
        assert!(updated);
    }

    #[tokio::test]
    async fn test_compute_child_route_status_observed_generation_check() {
        let client = dummy_kube_client();
        let (template_store, _) = store();
        let (route_store, _) = store();

        let ctx = Context::with_stores(client, template_store, route_store);
        let instance = dummy_instance("chal-1", None);

        // Route with metadata.generation = 2 but status.observed_generation = 1 (unobserved spec change)
        let route_lagging = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-1-c-web".into()),
                namespace: Some("default".into()),
                generation: Some(2),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                observed_generation: Some(1),
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                conditions: vec![Condition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    reason: "OldReconciliation".into(),
                    message: "Ready on gen 1".into(),
                    last_transition_time: Time(Timestamp::now()),
                    observed_generation: Some(1),
                }],
            }),
        };

        if let Some(cache) = &ctx.route_cache {
            cache.update(&route_lagging);
        }

        // Because observed_generation (1) < generation (2), ready_routes (M) must be 0
        let (ready, total, _) = compute_child_route_status(&instance, &ctx);
        assert_eq!(total, 1);
        assert_eq!(ready, 0);
    }
}

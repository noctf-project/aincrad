use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_common::crd::CTFInstance;
use kube::Api;
use kube::runtime::controller::Action;
use tracing::info;

use k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION;

use crate::{
    Context, Error, reconcilers,
    utils::ttl::{calculate_remaining_ttl, is_expired, parse_expires_at},
};

const EXPIRES_REQUEUE_BUFFER: Duration = Duration::from_secs(5);

/// Shared context threaded through every reconcile phase.
pub struct Flow<'a> {
    pub instance: &'a CTFInstance,
    pub ctx: &'a Context,
    pub name: &'a str,
    pub ns: &'a str,
    pub expires_at: Option<DateTime<Utc>>,
}

impl<'a> Flow<'a> {
    pub fn new(instance: &'a CTFInstance, ctx: &'a Context) -> Self {
        Self {
            instance,
            ctx,
            name: instance.metadata.name.as_deref().unwrap_or("unknown"),
            ns: instance.metadata.namespace.as_deref().unwrap_or("default"),
            expires_at: parse_expires_at(instance),
        }
    }
}

/// A phase either passes work to the next phase or terminates the reconcile.
pub enum Step<T> {
    Continue(T),
    Finish(Action),
}

/// Prepared state consumed by the apply phase.
pub struct Prepared {
    pub template: reconcilers::template::ResolvedTemplate,
}

/// Drives the reconcile pipeline: lifecycle, prepare, apply, commit.
pub async fn run(instance: &CTFInstance, ctx: &Context) -> Result<Action, Error> {
    let flow = Flow::new(instance, ctx);

    if let Step::Finish(action) = lifecycle::reconcile(&flow).await? {
        return Ok(action);
    }

    let prepared = match prepare::reconcile(&flow).await? {
        Step::Continue(prepared) => prepared,
        Step::Finish(action) => return Ok(action),
    };

    let children = apply::reconcile(&flow, &prepared).await?;
    let mut evaluation = reconcilers::status::evaluate_status(instance, ctx)?;

    evaluation.children.extend(children);

    if let Some(pr_names) = evaluation
        .children
        .get(<crate::planners::ProxyRoutePlanner as crate::planners::Planner>::KIND)
        && !pr_names.is_empty()
    {
        let endpoints = crate::planners::proxy_route::endpoints_from_children(
            pr_names,
            &prepared.template.spec.routes,
            &flow.ctx.hostname_suffix,
            flow.ctx.tls_port,
        );
        evaluation.resources.endpoints = Some(endpoints);
        evaluation.conditions.retain(|c| {
            c.type_ != <crate::planners::ProxyRoutePlanner as crate::planners::Planner>::KIND
        });
        evaluation
            .conditions
            .push(k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                type_: <crate::planners::ProxyRoutePlanner as crate::planners::Planner>::KIND
                    .to_string(),
                status: "True".to_string(),
                reason: "RoutesAllocated".to_string(),
                message: format!("All {} proxy route(s) allocated", pr_names.len()),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::now(),
                ),
                observed_generation: instance.metadata.generation,
            });
    }

    reconcilers::status::commit(instance, &evaluation, ctx).await?;

    Ok(completed_action(&flow))
}

/// Returns the scheduled action once all phases completed: requeue until expiry
/// or await further changes.
fn completed_action(flow: &Flow<'_>) -> Action {
    if let Some(remaining) = calculate_remaining_ttl(flow.expires_at) {
        Action::requeue(remaining + EXPIRES_REQUEUE_BUFFER)
    } else {
        Action::await_change()
    }
}

/// Hard lifecycle concerns: finalizer, deletion cleanup, and expiry.
pub mod lifecycle {
    use super::*;

    pub async fn reconcile(flow: &Flow<'_>) -> Result<Step<()>, Error> {
        let &Flow {
            instance,
            ctx,
            name,
            ns,
            expires_at,
        } = flow;

        // The routes finalizer must be attached before anything else so deletion
        // always triggers cross-namespace cleanup.
        if instance.metadata.deletion_timestamp.is_none() {
            reconcilers::helper::ensure_finalizer(ctx.client.clone(), instance).await?;
        }

        // Passing instance: delete its proxy routes and release ports, then drop
        // the finalizer so the object can leave the cluster.
        if instance.metadata.deletion_timestamp.is_some() {
            info!(
                name,
                ns, "CTFInstance marked for deletion, cleaning up cross-namespace routes..."
            );
            reconcilers::helper::cleanup_instance_routes(ctx, instance).await?;
            return Ok(Step::Finish(Action::await_change()));
        }

        // Expired instances are authoritative-deleted here; the requeue cadence
        // only bounds how late that delete fires.
        if is_expired(expires_at) {
            info!(name, ns, "CTFInstance has expired, deleting resource...");
            let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
            instances.delete(name, &Default::default()).await?;
            return Ok(Step::Finish(Action::await_change()));
        }

        Ok(Step::Continue(()))
    }
}

/// Derives the desired state: readiness evaluation, template resolution, and
/// annotation normalization.
pub mod prepare {
    use super::*;

    pub async fn reconcile(flow: &Flow<'_>) -> Result<Step<Prepared>, Error> {
        let &Flow {
            instance,
            ctx,
            name,
            ns,
            ..
        } = flow;

        // Resolve the CTFTemplate referenced by instance.spec.template.
        let template = reconcilers::template::reconcile(instance, ctx).await?;

        // Reject overrides that name template entries which do not exist,
        // rather than silently ignoring them.
        crate::planners::validate_overrides(instance, &template)?;

        // Skip planning and applying if the instance is already synced with its
        // observed spec generation and template version. Runtime child unreadiness
        // (e.g. transient pod crashes) must not trigger re-application or roll
        // template generations for non-synced instances.
        if is_observed(instance)
            && !crate::utils::versions::requires_template_upgrade(&template.metadata, instance)
        {
            info!(
                name,
                ns, "Instance spec is synced, updating status and skipping plan/apply"
            );
            let evaluation = reconcilers::status::evaluate_status(instance, ctx)?;
            reconcilers::status::commit(instance, &evaluation, ctx).await?;
            return Ok(Step::Finish(completed_action(flow)));
        }
        info!(
            name,
            ns, "Instance spec out of sync, planning and applying children"
        );

        // A non-numeric or non-positive minTemplateGeneration is rewritten to the
        // template's current generation, short-circuiting the reconcile.
        if let Some(raw_val) = instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(MIN_TEMPLATE_GENERATION_ANNOTATION))
        {
            match raw_val.parse::<i64>() {
                Ok(parsed) if parsed > 0 => {}
                _ => {
                    let valid_gen = template.metadata.generation.unwrap_or(1);
                    info!(
                        name,
                        ns,
                        raw_val,
                        valid_gen,
                        "Rewriting invalid minTemplateGeneration annotation"
                    );
                    patch_min_template_annotation(flow, valid_gen).await?;
                    return Ok(Step::Finish(Action::requeue(Duration::from_millis(100))));
                }
            }
        }

        // A requested generation above the template's current generation is capped.
        let min_gen = instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(MIN_TEMPLATE_GENERATION_ANNOTATION))
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&g| g > 0);

        if let (Some(requested), Some(template_gen)) = (min_gen, template.metadata.generation)
            && requested > template_gen
        {
            info!(
                name,
                ns, requested, template_gen, "Capping minTemplateGeneration annotation"
            );
            patch_min_template_annotation(flow, template_gen).await?;
            return Ok(Step::Finish(Action::requeue(Duration::from_millis(100))));
        }

        Ok(Step::Continue(Prepared { template }))
    }
}

/// Applies every planned child resource.
pub mod apply {
    use super::*;
    use crate::planners::{
        NetworkPolicyPlanner, Planner, ProxyRoutePlanner, ReplicaSetPlanner, ServicePlanner,
        TLSRoutePlanner,
    };
    use crate::reconcilers::helper::apply_planner;
    use std::collections::BTreeMap;

    async fn apply_and_record<P: Planner>(
        api: Api<P::Resource>,
        flow: &Flow<'_>,
        prepared: &Prepared,
        children: &mut BTreeMap<String, Vec<String>>,
    ) -> Result<Vec<P::Resource>, Error> {
        let applied = apply_planner::<P>(api, flow.instance, &prepared.template, flow.ctx).await?;
        let names = applied
            .iter()
            .filter_map(|r| kube::Resource::meta(r).name.clone())
            .collect();
        children.insert(P::KIND.to_string(), names);
        Ok(applied)
    }

    pub async fn reconcile(
        flow: &Flow<'_>,
        prepared: &Prepared,
    ) -> Result<BTreeMap<String, Vec<String>>, Error> {
        let ns = flow
            .instance
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default");
        let mut children = BTreeMap::new();

        apply_and_record::<ReplicaSetPlanner>(
            Api::namespaced(flow.ctx.client.clone(), ns),
            flow,
            prepared,
            &mut children,
        )
        .await?;
        apply_and_record::<ServicePlanner>(
            Api::namespaced(flow.ctx.client.clone(), ns),
            flow,
            prepared,
            &mut children,
        )
        .await?;
        apply_and_record::<NetworkPolicyPlanner>(
            Api::namespaced(flow.ctx.client.clone(), ns),
            flow,
            prepared,
            &mut children,
        )
        .await?;
        apply_and_record::<TLSRoutePlanner>(
            Api::namespaced(flow.ctx.client.clone(), ns),
            flow,
            prepared,
            &mut children,
        )
        .await?;

        if flow.ctx.port_map.is_some() {
            let api = Api::namespaced(flow.ctx.client.clone(), &flow.ctx.system_namespace);
            apply_and_record::<ProxyRoutePlanner>(api, flow, prepared, &mut children).await?;
        }

        Ok(children)
    }
}

use crate::reconcilers::status::is_observed;

/// Patches the minTemplateGeneration annotation to `target_gen`.
async fn patch_min_template_annotation(flow: &Flow<'_>, target_gen: i64) -> Result<(), Error> {
    let instances: Api<CTFInstance> = Api::namespaced(flow.ctx.client.clone(), flow.ns);
    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                MIN_TEMPLATE_GENERATION_ANNOTATION: target_gen.to_string()
            }
        }
    });
    instances
        .patch(
            flow.name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(patch),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_context, dummy_instance};
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::labels::EXPIRES_AT_ANNOTATION;

    #[tokio::test]
    async fn test_completed_action_without_expiry() {
        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let flow = Flow::new(&instance, &ctx);
        assert_eq!(completed_action(&flow), Action::await_change());
    }

    #[tokio::test]
    async fn test_completed_action_with_future_expiry() {
        let (_store, ctx) = dummy_context();
        let mut instance = dummy_instance("chal-1", None);
        let future_time = Utc::now() + ChronoDuration::seconds(60);
        instance.metadata.annotations = Some(crate::btreemap! {
            EXPIRES_AT_ANNOTATION.to_string() => future_time.to_rfc3339(),
        });
        let flow = Flow::new(&instance, &ctx);
        let action = completed_action(&flow);
        assert!(format!("{action:?}").contains("requeue"));
    }

    #[tokio::test]
    async fn test_completed_action_with_past_expiry() {
        let (_store, ctx) = dummy_context();
        let mut instance = dummy_instance("chal-1", None);
        let past_time = Utc::now() - ChronoDuration::seconds(60);
        instance.metadata.annotations = Some(crate::btreemap! {
            EXPIRES_AT_ANNOTATION.to_string() => past_time.to_rfc3339(),
        });
        let flow = Flow::new(&instance, &ctx);
        assert_eq!(completed_action(&flow), Action::await_change());
    }

    #[tokio::test]
    async fn test_apply_reconcile_records_all_children_uniformly() {
        use crate::planners::Planner;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let (_store, ctx) = dummy_context();
        let instance = dummy_instance("chal-1", None);
        let flow = Flow::new(&instance, &ctx);
        let prepared = Prepared {
            template: crate::reconcilers::template::ResolvedTemplate {
                metadata: ObjectMeta::default(),
                spec: k8s_common::crd::CTFTemplateSpec {
                    pods: vec![k8s_common::crd::CTFTemplateSpecPod {
                        name: "web".to_string(),
                        spec: k8s_openapi::api::core::v1::PodSpec::default(),
                        replicas: 1,
                        allow_internet: false,
                        patch_spec: None,
                    }],
                    routes: vec![k8s_common::crd::RouteSpec {
                        name: "tcp".to_string(),
                        backend: k8s_common::crd::RouteBackend {
                            service: "web".to_string(),
                            port: 80,
                        },
                        tcp: Some(k8s_common::crd::RouteSpecTCP { port: None }),
                        ..Default::default()
                    }],
                    params: Default::default(),
                },
                pod_patchers: Default::default(),
                params_map: Default::default(),
            },
        };

        let children = apply::reconcile(&flow, &prepared).await.unwrap();

        assert!(children.contains_key(crate::planners::ReplicaSetPlanner::KIND));
        assert!(children.contains_key(crate::planners::ServicePlanner::KIND));
        assert!(children.contains_key(crate::planners::NetworkPolicyPlanner::KIND));
        assert!(children.contains_key(crate::planners::TLSRoutePlanner::KIND));
        assert!(children.contains_key(crate::planners::ProxyRoutePlanner::KIND));

        let pr_names = children
            .get(crate::planners::ProxyRoutePlanner::KIND)
            .unwrap();
        assert_eq!(pr_names.len(), 1);
        assert!(pr_names[0].starts_with('p'));
    }
}

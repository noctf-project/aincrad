use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_common::crd::CTFInstance;
use kube::Api;
use kube::runtime::controller::Action;
use tracing::info;

use crate::{
    Context, Error, reconcilers,
    utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION,
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

/// Prepared state consumed by the apply and commit phases.
pub struct Prepared {
    pub template: reconcilers::template::ResolvedTemplate,
    pub evaluation: reconcilers::status::Evaluation,
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

    apply::reconcile(&flow, &prepared).await?;
    reconcilers::status::commit(instance, &prepared.evaluation, ctx).await?;

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
            reconcilers::helper::cleanup_instance_routes(
                ctx.client.clone(),
                &ctx.system_namespace,
                instance,
                ctx.route_allocator.as_deref(),
            )
            .await?;
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

        // Evaluate every child condition without writing. Only when all are True,
        // nothing has changed since the last apply, and the instance no longer
        // requires an upgrade can we skip reconciling.
        let evaluation = reconcilers::status::evaluate_status(instance, ctx)?;
        if evaluation.is_ready()
            && is_observed(instance)
            && !crate::utils::versions::requires_template_upgrade(
                template.metadata.generation,
                instance,
            )
        {
            info!(name, ns, "Instance ready, skipping reconciliation");
            return Ok(Step::Finish(completed_action(flow)));
        }
        info!(name, ns, "Instance not ready, reconciling children");

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

        Ok(Step::Continue(Prepared {
            template,
            evaluation,
        }))
    }
}

/// Applies every planned child resource.
pub mod apply {
    use super::*;
    use crate::planners::{
        NetworkPolicyPlanner, Planner, ProxyRoutePlanner, ReplicaSetPlanner, ServicePlanner,
    };
    use crate::reconcilers::helper::{apply_planner, apply_proxy_routes};

    pub async fn reconcile(flow: &Flow<'_>, prepared: &Prepared) -> Result<(), Error> {
        let instance = flow.instance;
        let template = &prepared.template;

        apply_planner::<ReplicaSetPlanner>(flow.ctx.client.clone(), instance, template, flow.ctx)
            .await?;
        apply_planner::<NetworkPolicyPlanner>(
            flow.ctx.client.clone(),
            instance,
            template,
            flow.ctx,
        )
        .await?;
        apply_planner::<ServicePlanner>(flow.ctx.client.clone(), instance, template, flow.ctx)
            .await?;

        if let Some(allocator) = &flow.ctx.route_allocator {
            let routes = ProxyRoutePlanner::plan(instance, template, flow.ctx)?;
            apply_proxy_routes(
                flow.ctx.client.clone(),
                &flow.ctx.system_namespace,
                instance,
                routes,
                allocator,
            )
            .await?;
        }

        Ok(())
    }
}

/// Returns true when the instance's status has observed the current spec
/// generation and restart annotation, meaning this reconcile pass found nothing
/// new to apply.
fn is_observed(instance: &CTFInstance) -> bool {
    match (
        instance.status.as_ref().and_then(|s| s.observed_generation),
        instance.metadata.generation,
    ) {
        (Some(observed), Some(current)) if observed < current => return false,
        (None, Some(_)) => return false,
        _ => {}
    }

    // restartedAt doesn't bump metadata.generation, so it must be checked
    // separately or restart requests would be swallowed by the Ready gate.
    let status_restarted_at = instance
        .status
        .as_ref()
        .and_then(|s| s.restarted_at.as_deref());
    let annotation_restarted_at = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(crate::utils::labels::RESTARTED_AT_ANNOTATION))
        .map(|s| s.as_str());

    status_restarted_at == annotation_restarted_at
}

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

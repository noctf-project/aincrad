use k8s_common::crd::{CTFInstance, CTFInstanceStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use tracing::instrument;

use crate::{Context, Error};

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

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "True".to_string(),
        reason: "Reconciled".to_string(),
        message: "CTFInstance reconciled successfully".to_string(),
        last_transition_time: now.clone(),
        observed_generation,
    };

    let synced_condition = Condition {
        type_: "Synced".to_string(),
        status: "True".to_string(),
        reason: "Reconciled".to_string(),
        message: "Resource synced with template".to_string(),
        last_transition_time: now,
        observed_generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation,
            template_generation,
            restarted_at,
            conditions: vec![ready_condition, synced_condition],
            endpoints: vec![],
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

    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: "False".to_string(),
        reason: "ReconciliationFailed".to_string(),
        message: err.to_string(),
        last_transition_time: now.clone(),
        observed_generation,
    };

    let synced_condition = Condition {
        type_: "Synced".to_string(),
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
            conditions: vec![ready_condition, synced_condition],
            endpoints: vec![],
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
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client};

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
}

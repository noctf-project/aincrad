use k8s_common::crd::{CTFInstance, CTFInstanceStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::{Api, ResourceExt};
use tracing::{info, instrument};

use crate::{Context, Error, utils::labels::TEMPLATE_GEN_ANNOTATION};

/// Updates CTFInstance status conditions, observedGeneration, and stamps template-generation annotation.
#[instrument(skip(ctx, instance))]
pub async fn reconcile(
    instance: &CTFInstance,
    ctx: &Context,
    target_gen: &str,
    is_ready: bool,
) -> Result<(), Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
    let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

    let instance_gen = instance
        .annotations()
        .get(TEMPLATE_GEN_ANNOTATION)
        .map(String::as_str);

    if instance_gen != Some(target_gen) {
        info!(
            name,
            target_gen, "Stamping template-generation annotation on CTFInstance"
        );
        let mut patch = instance.clone();
        let annotations = patch
            .metadata
            .annotations
            .get_or_insert_with(Default::default);
        annotations.insert(TEMPLATE_GEN_ANNOTATION.to_string(), target_gen.to_string());

        let patch_params = kube::api::PatchParams::apply("cardinal");
        instances
            .patch(name, &patch_params, &kube::api::Patch::Apply(patch))
            .await?;
    }

    let now = Time(Timestamp::now());
    let ready_condition = Condition {
        type_: "Ready".to_string(),
        status: if is_ready { "True" } else { "False" }.to_string(),
        reason: if is_ready { "Reconciled" } else { "Progressing" }.to_string(),
        message: if is_ready {
            "CTFInstance reconciled successfully".to_string()
        } else {
            "Reconciling child resources".to_string()
        },
        last_transition_time: now.clone(),
        observed_generation: instance.metadata.generation,
    };

    let synced_condition = Condition {
        type_: "Synced".to_string(),
        status: if is_ready { "True" } else { "False" }.to_string(),
        reason: if is_ready { "Reconciled" } else { "TemplateGenShifted" }.to_string(),
        message: if is_ready {
            "Resource synced with template generation".to_string()
        } else {
            "Updating instance template-generation".to_string()
        },
        last_transition_time: now,
        observed_generation: instance.metadata.generation,
    };

    let status_patch = serde_json::json!({
        "status": CTFInstanceStatus {
            observed_generation: instance.metadata.generation,
            conditions: vec![ready_condition, synced_condition],
            endpoints: vec![],
        }
    });

    let patch_params = kube::api::PatchParams::apply("cardinal");
    instances
        .patch_status(name, &patch_params, &kube::api::Patch::Merge(status_patch))
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_kube_client};

    #[tokio::test]
    async fn test_reconcile_status_ready() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", Some("1"));

        let res = reconcile(&instance, &ctx, "1", true).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_reconcile_status_progressing() {
        let client = dummy_kube_client();
        let ctx = Context::new(client);
        let instance = dummy_instance("chal-1", None);

        let res = reconcile(&instance, &ctx, "2", false).await;
        assert!(res.is_ok());
    }
}

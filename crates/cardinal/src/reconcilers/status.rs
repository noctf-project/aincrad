use k8s_common::crd::CTFInstance;
use kube::{Api, ResourceExt};
use tracing::{info, instrument};

use crate::{Context, Error, utils::labels::TEMPLATE_GEN_ANNOTATION};

/// Updates CTFInstance status and stamps template-generation annotation on CTFInstance.
#[instrument(skip(ctx, instance))]
pub async fn reconcile(
    instance: &CTFInstance,
    ctx: &Context,
    target_gen: &str,
) -> Result<(), Error> {
    let instance_gen = instance
        .annotations()
        .get(TEMPLATE_GEN_ANNOTATION)
        .map(String::as_str);

    if instance_gen != Some(target_gen) {
        let name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);

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
        let _ = instances
            .patch(name, &patch_params, &kube::api::Patch::Apply(patch))
            .await;
    }

    Ok(())
}

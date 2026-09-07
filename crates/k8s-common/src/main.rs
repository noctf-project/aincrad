use k8s_common::{
    Error, crd::*, generate_ctfinstance_admission_policy, generate_ctftemplate_admission_policy,
};
use kube::CustomResourceExt;

fn main() -> Result<(), Error> {
    let crds = [CTFTemplate::crd(), CTFInstance::crd()];
    for crd in crds {
        println!("{}---", generate_crd("yaml", crd)?);
    }

    let (instance_policy, instance_binding) = generate_ctfinstance_admission_policy();
    let instance_policy_yaml = serde_yaml::to_string(&instance_policy)
        .map_err(|e| Error::Custom(format!("failed to serialize instance policy: {e}")))?;
    let instance_binding_yaml = serde_yaml::to_string(&instance_binding)
        .map_err(|e| Error::Custom(format!("failed to serialize instance binding: {e}")))?;

    let (template_policy, template_binding) = generate_ctftemplate_admission_policy();
    let template_policy_yaml = serde_yaml::to_string(&template_policy)
        .map_err(|e| Error::Custom(format!("failed to serialize template policy: {e}")))?;
    let template_binding_yaml = serde_yaml::to_string(&template_binding)
        .map_err(|e| Error::Custom(format!("failed to serialize template binding: {e}")))?;

    println!("{instance_policy_yaml}---");
    println!("{instance_binding_yaml}---");
    println!("{template_policy_yaml}---");
    println!("{template_binding_yaml}---");

    Ok(())
}

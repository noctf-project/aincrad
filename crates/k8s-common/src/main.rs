use k8s_common::{Error, crd::*, generate_ctfinstance_admission_policy};
use kube::CustomResourceExt;

fn main() -> Result<(), Error> {
    let crds = [CTFRoute::crd(), CTFTemplate::crd(), CTFInstance::crd()];
    for crd in crds {
        println!("{}---", generate_crd("yaml", crd)?);
    }

    let (policy, binding) = generate_ctfinstance_admission_policy();
    let policy_yaml = serde_yaml::to_string(&policy)
        .map_err(|e| Error::Custom(format!("failed to serialize policy: {e}")))?;
    let binding_yaml = serde_yaml::to_string(&binding)
        .map_err(|e| Error::Custom(format!("failed to serialize binding: {e}")))?;

    println!("{policy_yaml}---");
    println!("{binding_yaml}---");

    Ok(())
}

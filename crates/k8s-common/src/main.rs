use k8s_common::{Error, crd::*};
use kube::CustomResourceExt;

fn main() -> Result<(), Error> {
    let crds = [CTFRoute::crd(), CTFTemplate::crd(), CTFInstance::crd()];
    for crd in crds {
        println!("{}---", generate_crd("yaml", crd)?);
    }
    Ok(())
}

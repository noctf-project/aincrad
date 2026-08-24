use cardinal::Error;
use k8s_common::crd::{CTFTemplate, generate_crd};
use kube::CustomResourceExt;

fn main() -> Result<(), Error> {
    let manifest = generate_crd("yaml", CTFTemplate::crd())?;
    print!("{manifest}");
    Ok(())
}

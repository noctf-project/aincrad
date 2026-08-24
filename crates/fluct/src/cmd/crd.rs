use fluct::Error;
use k8s_common::crd::{self, route::CTFRoute};
use kube::CustomResourceExt;

pub fn run(format: &str) -> Result<(), Error> {
    let manifest = crd::generate_crd(format, CTFRoute::crd())?;
    print!("{manifest}");
    Ok(())
}

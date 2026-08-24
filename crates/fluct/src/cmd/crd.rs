use fluct::Error;

use crate::crd;

pub fn run(format: &str) -> Result<(), Error> {
    let manifest = crd::generate_crd(format)?;
    print!("{manifest}");
    Ok(())
}

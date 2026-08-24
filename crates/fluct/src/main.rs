use fluct::Error;

use crate::cmd::cli;

mod clients;
mod cmd;
mod config;
mod crd;
mod crypto;
mod logger;
mod proxy;
mod services;
mod store;
mod util;


fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let action = cli::parse_config()?;

    match action {
        cli::ServiceAction::PrintCrd { format } => {
            cmd::crd::run(&format)?;
        }
        cli::ServiceAction::Run(config) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd::run::run(config))?;
        }
    }

    Ok(())
}

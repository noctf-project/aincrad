use cardinal::Error;
use cardinal::cli::Opts;
use clap::Parser;
use kube::Client;
use kube_lease_manager::LeaseManagerBuilder;
use tokio_rustls::rustls;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    if let Err(err) = opts.validate() {
        error!(error = %err, "Invalid configuration");
        return Err(Error::Custom(err));
    }

    let kube_client = Client::try_default().await?;
    let system_namespace = opts
        .system_namespace
        .clone()
        .unwrap_or_else(|| kube_client.default_namespace().to_string());
    let manager = LeaseManagerBuilder::new(kube_client.clone(), "cardinal-leader")
        .with_duration(15)
        .with_namespace(&system_namespace)
        .build()
        .await?;

    let (mut channel, _task) = manager.watch().await;

    tokio::select! {        _ = wait_for_shutdown_signal() => {
            info!("Received shutdown signal, terminating cardinal...");
            Ok(())
        }
        res = async {
            loop {
                if channel.changed().await.is_err() {
                    warn!("Lease channel closed");
                    break Ok(());
                }

                let is_leader = *channel.borrow_and_update();
                if is_leader {
                    info!("Acquired leader lease! Starting controller loop.");

                    let mut watch_loss = channel.clone();
                    tokio::select! {
                        _ = async move {
                            while watch_loss.changed().await.is_ok() {
                                if !*watch_loss.borrow_and_update() {
                                    warn!("Lost leader lease! Stopping controller loop.");
                                    break;
                                }
                            }
                        } => {}
                        res = cardinal::controller::run(
                            kube_client.clone(),
                            opts.clone(),
                        ) => {
                            if let Err(err) = res {
                                error!("atal controller error: {err}");
                                return Err(err);
                            }
                            info!("Controller loop finished.");
                        }
                    }
                }
            }
        } => res,
    }
}

async fn wait_for_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

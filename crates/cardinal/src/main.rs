use std::time::Duration;

use cardinal::Error;
use k8s_common::KubernetesClient;
use kube::Client;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let k8s_client = KubernetesClient::new().await?;
    let kube_client = Client::try_default().await?;

    info!("Starting cardinal controller");

    let manager = k8s_client
        .get_lease_manager("cardinal-leader", Duration::from_secs(15))
        .await?;

    let (mut channel, _task) = manager.watch().await;

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            info!("Received shutdown signal, terminating cardinal...");
        }
        _ = async {
            loop {
                if channel.changed().await.is_err() {
                    warn!("Lease channel closed");
                    break;
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
                        _ = cardinal::controller::run(kube_client.clone()) => {
                            info!("Controller loop finished.");
                        }
                    }
                }
            }
        } => {}
    }

    Ok(())
}

async fn wait_for_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

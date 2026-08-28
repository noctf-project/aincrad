use std::sync::Arc;

use cardinal::Error;
use cardinal::routing::{PortsStore, RouteAllocator};
use clap::Parser;
use k8s_common::{PortRange, parse_port_range};
use kube::Client;
use kube_lease_manager::LeaseManagerBuilder;
use tokio_rustls::rustls;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "cardinal", about = "Control plane controller for Aincrad CTF")]
pub struct Opts {
    #[arg(
        long,
        env = "RESERVED_PORTS",
        default_value = "20000-29999",
        value_parser = parse_port_range
    )]
    pub reserved_ports: PortRange,

    #[arg(
        long,
        env = "AUTO_PORTS",
        default_value = "30000-32767",
        value_parser = parse_port_range
    )]
    pub auto_ports: PortRange,

    #[arg(long, env = "ROUTE_SEED", default_value = "link-start")]
    pub route_seed: String,

    #[arg(long, env = "HOSTNAME_SUFFIX", default_value = "c.noctf.dev")]
    pub hostname_suffix: String,

    #[arg(long, env = "TLS_PORT", default_value = "4433")]
    pub tls_port: u16,

    #[arg(long, env = "SYSTEM_NAMESPACE")]
    pub system_namespace: Option<String>,

    #[arg(long, env = "CLUSTER_DOMAIN", default_value = "cluster.local")]
    pub cluster_domain: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    let kube_client = Client::try_default().await?;

    let system_namespace = opts
        .system_namespace
        .unwrap_or_else(|| kube_client.default_namespace().to_string());

    info!(
        system_namespace = %system_namespace,
        reserved_ports = ?opts.reserved_ports,
        auto_ports = ?opts.auto_ports,
        "Starting cardinal controller"
    );

    let ports_store = Arc::new(PortsStore::new(opts.reserved_ports, opts.auto_ports));
    let allocator = Arc::new(RouteAllocator::new(
        ports_store,
        opts.route_seed,
        opts.hostname_suffix,
        opts.tls_port,
    ));

    let manager = LeaseManagerBuilder::new(kube_client.clone(), "cardinal-leader")
        .with_duration(15)
        .with_namespace(&system_namespace)
        .build()
        .await?;

    let (mut channel, _task) = manager.watch().await;

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
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
                            allocator.clone(),
                            system_namespace.clone(),
                            opts.cluster_domain.clone(),
                        ) => {
                            if let Err(err) = res {
                                error!("fatal controller error: {err}");
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

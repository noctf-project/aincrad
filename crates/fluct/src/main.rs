use std::sync::Arc;

use fluct::Error;
use kube::Client;
use tokio::try_join;
use tokio_rustls::rustls::crypto::ring;
use tokio_util::sync::CancellationToken;

mod config;
mod hash;
mod netfilter;
mod proxy;
mod services;
mod store;

use crate::{
    config::{ServiceConfig, ServiceContext},
    services::routes::RoutesService,
    store::resolver::{Resolver, ResolverExpiryPolicy},
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let config = config::parse_config()?;

    run(config).await
}

pub async fn run(config: ServiceConfig) -> Result<(), Error> {
    let _ = ring::default_provider().install_default();

    let shutdown = CancellationToken::new();

    let kube_client = Client::try_default().await?;

    let routes_service = RoutesService::new(
        kube_client,
        config.port_ranges.clone(),
        config.system_namespace.clone(),
    );

    let (tls_tx, tls_rx) = if let Some(port) = config.tproxy_port {
        let mut ranges: Vec<std::ops::RangeInclusive<u16>> =
            config.port_ranges.iter().map(|r| r.0.clone()).collect();
        ranges.push(config.tls_port..=config.tls_port);

        netfilter::configure_netfilter(port, &ranges)
            .map_err(|e| format!("unable to configure netfilter {}", e))?;

        let (tx, rx) = tokio::sync::mpsc::channel(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let service_context = Arc::new(ServiceContext {
        config,
        resolver: Resolver::new(1000, ResolverExpiryPolicy::default()),
        routes_service,
        shutdown: shutdown.clone(),
    });

    try_join!(
        wrap_err(
            "services::signal::run",
            services::signal::run(shutdown.clone())
        ),
        wrap_err(
            "services::proxy::run",
            services::proxy::run(service_context.clone(), tls_tx)
        ),
        wrap_err(
            "services::tlsproxy::run",
            services::tlsproxy::run(service_context.clone(), tls_rx)
        ),
        wrap_err(
            "challenges_store.run",
            service_context.routes_service.run(service_context.clone())
        ),
    )?;
    Ok(())
}

async fn wrap_err<F, T, E>(label: &str, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    fut.await.map_err(|e| format!("{label}: {e}"))
}

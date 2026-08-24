use std::sync::Arc;

use clients::KubernetesClient;
use config::ServiceContext;
use fluct::Error;
use tokio::try_join;
use tokio_rustls::rustls::crypto::ring;
use tokio_util::sync::CancellationToken;

use crate::{services::routes::RoutesService, store::secrets::SecretsStore};
mod clients;
mod config;
mod crd;
mod crypto;
mod logger;
mod proxy;
mod services;
mod store;
mod util;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let _ = ring::default_provider().install_default();

    let config = config::parse_config()?;

    let shutdown = CancellationToken::new();

    let kubernetes_client = KubernetesClient::new().await?;

    let routes_service = RoutesService::new(
        kubernetes_client.clone(),
        &config.challenge_domain,
        config.tls_port,
        config.reserved_ports.clone(),
        config.auto_ports.clone(),
    );
    let secrets_store = SecretsStore::new(kubernetes_client.clone(), &config.secret_root);

    let (tls_tx, tls_rx) = if let Some(port) = config.tproxy_port {
        util::netfilter::configure_netfilter(
            port,
            &[
                config.auto_ports.0.clone(),
                config.reserved_ports.0.clone(),
                config.tls_port..=config.tls_port,
            ],
        )
        .map_err(|e| format!("unable to configure netfilter {}", e))?;

        let (tx, rx) = tokio::sync::mpsc::channel(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let service_context = Arc::new(ServiceContext {
        config,
        routes_service,
        secrets_store,
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
            "services::api::run",
            services::api::run(service_context.clone())
        ),
        wrap_err(
            "services::tlsproxy::run",
            services::tlsproxy::run(service_context.clone(), tls_rx)
        ),
        wrap_err(
            "challenges_store.run",
            service_context.routes_service.run(service_context.clone())
        ),
        wrap_err(
            "secrets_store.run",
            service_context.secrets_store.run(shutdown.clone())
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

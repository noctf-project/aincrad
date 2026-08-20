use std::sync::Arc;

use clap::Parser;
use clients::KubernetesClient;
use config::{ServiceConfig, ServiceContext};
use fluct::Error;
use store::{ChallengesStore, SecretsStore};
use tokio::join;
use tokio_rustls::rustls::crypto::ring;
use tokio_util::sync::CancellationToken;
use tracing::error;
mod clients;
mod config;
mod crd;
mod crypto;
mod logger;
mod proxy;
mod services;
mod store;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let _ = ring::default_provider().install_default();

    let config = ServiceConfig::parse();
    let shutdown = CancellationToken::new();

    let kubernetes_client = KubernetesClient::new().await?;

    let challenges_store = ChallengesStore::new(kubernetes_client.clone(), &config.hostname_suffix);
    let secrets_store = SecretsStore::new(kubernetes_client.clone(), &config.secret_root);

    let service_context = Arc::new(ServiceContext {
        config,
        challenges_store,
        secrets_store,
        shutdown: shutdown.clone(),
    });

    let _ = join!(
        log_if_err(
            "services::signal::run",
            services::signal::run(shutdown.clone())
        ),
        log_if_err(
            "services::proxy::run",
            services::proxy::run(service_context.clone())
        ),
        log_if_err(
            "services::api::run",
            services::api::run(service_context.clone())
        ),
        log_if_err(
            "services::tlsproxy::run",
            services::tlsproxy::run(service_context.clone())
        ),
        log_if_err(
            "challenges_store.run",
            service_context
                .challenges_store
                .run(service_context.clone())
        ),
        log_if_err(
            "secrets_store.run",
            service_context.secrets_store.run(shutdown.clone())
        ),
    );
    Ok(())
}
async fn log_if_err<F, T, E>(label: &'static str, fut: F)
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    if let Err(e) = fut.await {
        error!("{label} failed: {e}");
    }
}

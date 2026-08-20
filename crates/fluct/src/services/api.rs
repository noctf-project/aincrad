use std::sync::Arc;

use axum::Router;
use fluct::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::ServiceContext;

pub async fn run(service: Arc<ServiceContext>) -> Result<(), Error> {
    let config = &service.config;
    let app = Router::new().with_state(service.clone());

    let spec = format!("{}:{}", config.host, config.http_port);
    let listener = TcpListener::bind(&spec).await?;
    info!("Binding API to {}", spec);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(service.shutdown.clone()))
        .await?;

    info!("API stopped");

    Ok(())
}

async fn shutdown_signal(shutdown: CancellationToken) {
    shutdown.cancelled().await;
}

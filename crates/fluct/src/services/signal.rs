use fluct::Error;
use tokio::{
    select,
    signal::unix::{SignalKind, signal},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub async fn run(shutdown: CancellationToken) -> Result<(), Error> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }

    warn!("Gracefully shutting down application");
    shutdown.cancel();
    Ok(())
}

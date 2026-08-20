use fluct::Error;
use tokio::{
    select,
    signal::unix::{SignalKind, signal},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub async fn run(shutdown: CancellationToken) -> Result<(), Error> {
    let mut sigterm = signal(SignalKind::terminate())?;
    select! {
      Some(()) = sigterm.recv() => {},
    }
    warn!("Gracefully shutting down application");
    shutdown.cancel();
    Ok(())
}

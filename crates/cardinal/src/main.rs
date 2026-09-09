use cardinal::Error;
use cardinal::cli::Opts;
use cardinal::config::CardinalConfig;
use kube::Client;
use kube_lease_manager::LeaseManagerBuilder;
use notify::{Event, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio_rustls::rustls;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt::init();

    let opts = Opts::parse_args();
    let (config, loaded_path) = match CardinalConfig::load_or_default(opts.config.as_deref()) {
        Ok(res) => res,
        Err(err) => {
            error!(error = %err, "Failed to load configuration");
            return Err(Error::Custom(err));
        }
    };

    if let Some(ref path) = loaded_path {
        info!(path = ?path, "Loaded configuration");
    } else {
        info!("No configuration file found; using defaults");
    }

    let kube_client = Client::try_default().await?;
    let system_namespace = config
        .system_namespace
        .clone()
        .unwrap_or_else(|| kube_client.default_namespace().to_string());
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

                if *channel.borrow_and_update() {
                    info!("Acquired leader lease! Starting controller loop.");
                    run_as_leader(
                        kube_client.clone(),
                        config.clone(),
                        loaded_path.clone(),
                        channel.clone(),
                    )
                    .await?;
                }
            }
        } => res,
    }
}

async fn run_as_leader(
    kube_client: Client,
    mut active_config: CardinalConfig,
    loaded_path: Option<std::path::PathBuf>,
    mut lease_channel: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    let (config_changed_tx, mut config_changed_rx) = mpsc::channel::<CardinalConfig>(4);
    let mut _watcher = None;

    if let Some(path) = loaded_path {
        let (raw_event_tx, mut raw_event_rx) = mpsc::channel::<()>(16);
        match setup_config_watcher(&path, raw_event_tx) {
            Ok(w) => {
                _watcher = Some(w);
                let path_clone = path.clone();
                let initial_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                let mut current_config = active_config.clone();

                tokio::spawn(async move {
                    let mut last_mtime = initial_mtime;
                    while raw_event_rx.recv().await.is_some() {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        while raw_event_rx.try_recv().is_ok() {}

                        let current_mtime = std::fs::metadata(&path_clone)
                            .and_then(|m| m.modified())
                            .ok();
                        if current_mtime.is_some() && current_mtime == last_mtime {
                            continue;
                        }

                        if let Ok((new_cfg, _)) = CardinalConfig::load_or_default(Some(&path_clone))
                        {
                            last_mtime = current_mtime;
                            if new_cfg != current_config {
                                info!(
                                    "Configuration changed on disk; signalling controller restart..."
                                );
                                current_config = new_cfg.clone();
                                if config_changed_tx.send(new_cfg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => warn!(error = %e, "Failed to watch config file"),
        }
    }

    loop {
        tokio::select! {
            _ = async {
                while lease_channel.changed().await.is_ok() {
                    if !*lease_channel.borrow_and_update() {
                        warn!("Lost leader lease! Stopping controller loop.");
                        break;
                    }
                }
            } => break Ok(()),
            Some(new_cfg) = config_changed_rx.recv() => {
                info!("Restarting controller loop with updated configuration...");
                active_config = new_cfg;
            }
            res = cardinal::controller::run(kube_client.clone(), active_config.clone()) => {
                if let Err(err) = res {
                    error!("Fatal controller error: {err}");
                    return Err(err);
                }
                info!("Controller loop finished.");
                break Ok(());
            }
        }
    }
}

fn setup_config_watcher(
    path: &std::path::Path,
    tx: mpsc::Sender<()>,
) -> notify::Result<notify::RecommendedWatcher> {
    let watch_target = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(path);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res
            && (event.kind.is_modify() || event.kind.is_create())
        {
            let _ = tx.try_send(());
        }
    })?;

    watcher.watch(watch_target, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

async fn wait_for_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

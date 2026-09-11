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

    let shared_api_config = std::sync::Arc::new(parking_lot::RwLock::new(std::sync::Arc::new(
        config.api.clone(),
    )));

    let (controller_changed_tx, controller_changed_rx) =
        tokio::sync::watch::channel(config.controller.clone());
    let _watcher = loaded_path.as_deref().and_then(|path| {
        spawn_config_reloader(
            path,
            config.clone(),
            shared_api_config.clone(),
            controller_changed_tx,
        )
    });

    let listen_addr = opts
        .listen_addr
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 8000)));

    let api_client = kube_client.clone();
    let api_cfg = shared_api_config.clone();
    tokio::spawn(async move {
        if let Err(err) = cardinal::api::start_server(api_client, api_cfg, listen_addr).await {
            tracing::error!(target: "cardinal::api", error = %err, "API server stopped with error");
        }
    });

    let system_namespace = config
        .controller
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
            while channel.changed().await.is_ok() {
                if *channel.borrow_and_update() {
                    info!("Acquired leader lease! Starting controller loop.");
                    run_as_leader(kube_client.clone(), controller_changed_rx.clone(), channel.clone()).await?;
                }
            }
            warn!("Lease channel closed");
            Ok(())
        } => res,
    }
}

fn spawn_config_reloader(
    path: &std::path::Path,
    mut current_config: CardinalConfig,
    shared_api: std::sync::Arc<parking_lot::RwLock<std::sync::Arc<cardinal::config::ApiConfig>>>,
    controller_tx: tokio::sync::watch::Sender<cardinal::config::ControllerConfig>,
) -> Option<notify::RecommendedWatcher> {
    let (raw_event_tx, mut raw_event_rx) = mpsc::channel::<()>(16);
    let watcher = setup_config_watcher(path, raw_event_tx)
        .map_err(|e| {
            warn!(error = %e, "Failed to watch config file");
        })
        .ok()?;

    let path = path.to_path_buf();
    let initial_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();

    tokio::spawn(async move {
        let mut last_mtime = initial_mtime;
        while raw_event_rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            while raw_event_rx.try_recv().is_ok() {}

            let current_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            if current_mtime.is_some() && current_mtime == last_mtime {
                continue;
            }

            let (new_cfg, _) = match CardinalConfig::load_or_default(Some(&path)) {
                Ok(cfg) => cfg,
                Err(err) => {
                    error!(error = %err, "Failed to reload configuration from disk; keeping existing configuration");
                    continue;
                }
            };

            last_mtime = current_mtime;
            if new_cfg.api != current_config.api {
                info!("API configuration changed on disk; updating API state...");
                *shared_api.write() = std::sync::Arc::new(new_cfg.api.clone());
            }
            if new_cfg.controller != current_config.controller {
                info!("Controller configuration changed on disk; signalling controller restart...");
                let _ = controller_tx.send(new_cfg.controller.clone());
            }
            current_config = new_cfg;
        }
    });

    Some(watcher)
}

async fn run_as_leader(
    kube_client: Client,
    mut config_rx: tokio::sync::watch::Receiver<cardinal::config::ControllerConfig>,
    mut lease_channel: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut active_config = config_rx.borrow_and_update().clone();

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
            Ok(()) = config_rx.changed() => {
                info!("Restarting controller loop with updated configuration...");
                active_config = config_rx.borrow_and_update().clone();
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

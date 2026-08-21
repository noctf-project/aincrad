use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use fluct::Error;
use tokio::{
    join,
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc,
    task::JoinHandle,
    time::sleep,
};
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, trace, warn};

use crate::{config::ServiceContext, proxy::Handler};

type ConnectionHandle = (u16, TcpStream, SocketAddr);

pub async fn run(service: Arc<ServiceContext>) -> Result<(), Error> {
    let (tx, rx) = mpsc::channel::<ConnectionHandle>(128);
    join!(
        thread_listeners(service.clone(), tx),
        tokio::spawn(thread_accept(service.clone(), rx))
    )
    .0
}

async fn thread_listeners(
    service: Arc<ServiceContext>,
    acceptor: mpsc::Sender<ConnectionHandle>,
) -> Result<(), Error> {
    let shutdown = service.shutdown.clone();
    let mut listeners: HashMap<u16, JoinHandle<Result<(), Error>>> = HashMap::new();
    let (unbind_tx, mut unbind_rx) = mpsc::channel(128);
    let config = &service.config;

    loop {
        select! {
          _ = sleep(Duration::from_secs(2)) => {
            let intended = service.routes_service.get_active_ports();
            let mut all = intended.clone();
            all.extend(listeners.keys().copied());
            for port in all {
              if port == service.config.tls_port {
                warn!("cannot bind on port used for tls challenges :{}", port);
                continue;
              }
              if intended.contains(&port) && !listeners.contains_key(&port) {
                listeners.insert(port, tokio::spawn(thread_listen(acceptor.clone(), unbind_tx.clone(), config.host.clone(), port)));
              } else if !intended.contains(&port) && listeners.contains_key(&port) {
                unbind_tx.send(port).await?;
              }
            }
          },
          Some(port) = unbind_rx.recv() => {
            if let Some(handle) = listeners.remove(&port) {
              info!("Removing listener on {}:{}", config.host, port);
              handle.abort();
            }
          },
          _ = shutdown.cancelled() => {
            for (port, handle) in listeners {
              handle.abort();
              info!("Removing listener for port {}", port);
            }
            break Ok(());
          }
        }
    }
}

async fn thread_accept(
    service: Arc<ServiceContext>,
    mut rx: mpsc::Receiver<ConnectionHandle>,
) -> Result<(), Error> {
    let tracker = TaskTracker::new();
    let shutdown = service.shutdown.clone();
    loop {
        // TODO: add graceful shutdown
        select! {
          Some((port, socket, addr)) = rx.recv() => {
            if let Some(pair) = service.routes_service.get_route_from_port(port) {
              let service = service.clone();
              trace!("Accepting connection {} on port {}", addr, port);
              let mut handler = Handler::new(service, pair, addr);
              tracker.spawn(async move {
                if let Err(err) = handler.handle_socket(socket).await {
                  debug!("Error while processing connection {} due to: {}", addr, err);
                }
                trace!("Closing connection {}", addr);
              });
            }
          },
          _ = shutdown.cancelled() => {
            break;
          }
        }
    }
    tracker.close();
    tracker.wait().await;
    Ok(())
}

async fn thread_listen(
    acceptor: mpsc::Sender<ConnectionHandle>,
    unbinder: mpsc::Sender<u16>,
    host: String,
    port: u16,
) -> Result<(), Error> {
    let spec = format!("{}:{}", host, port);
    let listener = match TcpListener::bind(&spec).await {
        Ok(l) => {
            info!("Bound listener on {}", spec);
            l
        }
        Err(e) => {
            error!("Unable to bind on {}", spec);
            let _ = unbinder.send(port).await;
            return Err(Box::new(e));
        }
    };
    loop {
        select! {
          Ok((socket, addr)) = listener.accept() => {
            if let Err(err) = acceptor.send((port, socket, addr)).await {
              info!("Error sending connection {} to acceptor thread {}", addr, err);
            }
          }
        }
    }
}

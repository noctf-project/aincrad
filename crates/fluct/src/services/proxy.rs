use std::{collections::HashMap, net::SocketAddr, os::fd::AsRawFd, sync::Arc, time::Duration};

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

pub async fn run(
    service: Arc<ServiceContext>,
    tls_tx: Option<mpsc::Sender<(TcpStream, SocketAddr)>>,
) -> Result<(), Error> {
    if service.config.tproxy_port.is_some() {
        let tls_tx = tls_tx.ok_or_else(|| "tls_tx channel missing for tproxy".to_string())?;
        run_tproxy_listener(service, tls_tx).await
    } else {
        let (tx, rx) = mpsc::channel::<ConnectionHandle>(128);
        join!(
            thread_listeners(service.clone(), tx),
            tokio::spawn(thread_accept(service.clone(), rx))
        )
        .0
    }
}

fn accept_connection(
    service: Arc<ServiceContext>,
    tracker: &TaskTracker,
    port: u16,
    socket: TcpStream,
    addr: SocketAddr,
) -> Option<()> {
    let pair = service.routes_service.get_route_from_port(port)?;
    trace!("Accepting connection from {} (route {})", addr, pair.0);
    let mut handler = Handler::new(service, pair, addr);
    tracker.spawn(async move {
        if let Err(err) = handler.handle_socket(socket).await {
            debug!("Error while processing connection {} due to: {}", addr, err);
        }
        trace!("Closing connection {}", addr);
    });
    Some(())
}

async fn run_tproxy_listener(
    service: Arc<ServiceContext>,
    tls_tx: mpsc::Sender<(TcpStream, SocketAddr)>,
) -> Result<(), Error> {
    let port = service
        .config
        .tproxy_port
        .ok_or_else(|| "tproxy port not configured in ServiceConfig".to_string())?;

    let spec = format!("{}:{}", service.config.host, port);
    let socket_addr: SocketAddr = spec
        .parse()
        .map_err(|e| format!("Invalid listener address {spec}: {e}"))?;

    let socket = if socket_addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    crate::util::netfilter::set_ip_transparent(socket.as_raw_fd())?;
    socket.set_reuseaddr(true)?;
    socket.bind(socket_addr)?;

    let listener = match socket.listen(1024) {
        Ok(l) => {
            info!("Bound TPROXY listener on {}", spec);
            l
        }
        Err(e) => {
            error!("Unable to bind TPROXY listener on {}: {}", spec, e);
            return Err(Box::new(e));
        }
    };

    let tracker = TaskTracker::new();
    let shutdown = service.shutdown.clone();

    loop {
        select! {
            res = listener.accept() => {
                let (socket, addr) = match res {
                    Ok(conn) => conn,
                    Err(err) => {
                        error!("Error accepting connection on tproxy listener: {}", err);
                        continue;
                    }
                };

                let local_addr = match socket.local_addr() {
                    Ok(l) => l,
                    Err(err) => {
                        warn!("Failed to get local_addr for connection {}: {}", addr, err);
                        continue;
                    }
                };
                let port = local_addr.port();
                if port == service.config.tls_port {
                    if let Err(err) = tls_tx.send((socket, addr)).await {
                        warn!("Failed to send stream to tlsproxy channel: {}", err);
                    }
                } else {
                    accept_connection(service.clone(), &tracker, port, socket, addr)
                      .unwrap_or_else(|| debug!("{addr} connected to unknown service at port {port}"));
                }
            }
            _ = shutdown.cancelled() => {
                info!("Shutting down tproxy listeners");
                break;
            }
        }
    }

    tracker.close();
    tracker.wait().await;
    Ok(())
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
        select! {
          Some((port, socket, addr)) = rx.recv() => {
            accept_connection(service.clone(), &tracker, port, socket, addr)
              .unwrap_or_else(|| debug!("{addr} connected to unknown service at port {port}"));
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

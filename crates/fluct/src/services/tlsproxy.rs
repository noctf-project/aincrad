use std::{
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use crate::config::ServiceContext;
use crate::proxy::Handler;
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};
use tracing::{info, trace, warn};

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot find private key"))
}

enum IncomingSource {
    Listener(TcpListener),
    Channel(mpsc::Receiver<(TcpStream, SocketAddr)>),
}

impl IncomingSource {
    async fn accept(&mut self) -> Result<(TcpStream, SocketAddr), ()> {
        match self {
            IncomingSource::Listener(listener) => match listener.accept().await {
                Ok(conn) => Ok(conn),
                Err(_) => Err(()),
            },
            IncomingSource::Channel(rx) => rx.recv().await.ok_or(()),
        }
    }
}

pub async fn run(
    service: Arc<ServiceContext>,
    tls_rx: Option<mpsc::Receiver<(TcpStream, SocketAddr)>>,
) -> Result<(), fluct::Error> {
    let certs = load_certs(&service.config.tls_cert)?;
    let key = load_keys(&service.config.tls_key)?;
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let mut source = match tls_rx {
        Some(rx) => {
            info!("tlsproxy listening on tproxy channel");
            IncomingSource::Channel(rx)
        }
        None => {
            let spec = format!("[::]:{}", service.config.tls_port);
            let listener = TcpListener::bind(&spec).await?;
            info!("Binding TLS listener to {}", spec);
            IncomingSource::Listener(listener)
        }
    };

    loop {
        select! {
          res = source.accept() => {
            let (stream, addr) = match res {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let fut = handle_connection(acceptor.clone(), service.clone(), stream, addr);
            tokio::spawn(async move {
              if let Err(err) = fut.await {
                warn!("TLS connection error for {}: {}", addr, err);
              }
            });
          },
          _ = service.shutdown.cancelled() => {
            break;
          }
        }
    }
    Ok(())
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    service: Arc<ServiceContext>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), fluct::Error> {
    let stream = acceptor.accept(stream).await?;
    let (_, connection) = stream.get_ref();
    let hostname = match connection.server_name() {
        Some(hostname) => hostname,
        None => return Ok(()),
    }
    .to_lowercase();

    if let Some(pair) = service.routes_service.get_tls_route(&hostname) {
        trace!("client {} connected to TLS challenge {}", addr, pair.0);
        let (c_rx, c_tx) = tokio::io::split(stream);
        let mut handler = Handler::new(service, pair, addr);
        handler.handle(c_rx, c_tx).await?;
    }

    Ok(())
}

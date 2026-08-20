use std::{io::Write, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use chrono::{Timelike, Utc};
use fluct::{Error, Session};
use tokio::{
    fs::OpenOptions,
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    join,
    net::TcpStream,
    select,
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::{
    config::ServiceContext,
    crd::CTFRouteSpecPair,
    logger::FileLogger,
    proxy::{
        challenge::{Challenge, ChallengeSolveState},
        flag::{FlagGenerator, V1FlagGenerator},
        get_line,
    },
};

pub struct Handler {
    service: Arc<ServiceContext>,
    route: Arc<CTFRouteSpecPair>,
    session: Session,
    flag: String,
}

const DEFAULT_SECRET: &[u8] = b"notsecret";
const BUF_SIZE: usize = 16 * 1024;
const MAX_UID_SIZE: usize = 64;
const MAX_INPUT_TIME_UID: Duration = Duration::from_secs(30);

type LogMessage = (u8, Vec<u8>);

impl Handler {
    pub fn new(
        service: Arc<ServiceContext>,
        route: Arc<CTFRouteSpecPair>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            service,
            route,
            session: Session {
                uid: b"".to_vec(),
                addr: addr.ip(),
                timestamp: Utc::now(),
            },
            flag: String::new(),
        }
    }

    pub async fn handle_socket(&mut self, mut socket: TcpStream) -> Result<(), Error> {
        let (c_rx, c_tx) = socket.split();
        self.handle(c_rx, c_tx).await
    }

    pub async fn handle<R, W>(&mut self, c_rx: R, mut c_tx: W) -> Result<(), Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut c_rx = BufReader::with_capacity(BUF_SIZE, c_rx);
        let name = &self.route.0;
        let spec = &self.route.1;

        let secret_name = match &spec.secret {
            Some(secret) => secret,
            None => "default",
        };

        let mut request_pow: Option<ChallengeSolveState> = None;
        let pow = spec.pow.as_ref();
        if let Some(available_at) = spec.available_at
            && available_at > self.session.timestamp {
                c_tx.write_all(b"== info: This challenge is not currently available ==\n")
                    .await?;
                if let Some(pow) = pow
                    && pow.enable_admin_bypass
                {
                    request_pow = Some(ChallengeSolveState::Bypassed);
                } else {
                    return Ok(());
                }
            }

        if request_pow.is_none()
            && let Some(pow) = pow
            && pow.difficulty > 0
        {
            request_pow = Some(ChallengeSolveState::Solved);
        }

        if let Some(request_challenge) = request_pow {
            let secret = self
                .service
                .secrets_store
                .derive_key(secret_name, name, "challenge")
                .await
                .unwrap_or_else(|| DEFAULT_SECRET.to_vec());

            match Challenge::solve(
                pow.map(|x| x.difficulty).unwrap_or(0),
                &secret,
                &mut c_rx,
                &mut c_tx,
            )
            .await
            {
                Some(state) => {
                    if state < request_challenge {
                        debug!(
                            "Challenge solve state {:?} is less than required state {:?}",
                            state, request_challenge
                        );
                        return Ok(());
                    }
                }
                None => return Ok(()),
            }
        }

        if spec.request_uid {
            c_tx.write_all(b"== input: competitor id (max 64 chars) ==\n")
                .await?;
            self.session.uid = get_line(&mut c_rx, MAX_UID_SIZE, MAX_INPUT_TIME_UID).await?;
        }

        let secret = self
            .service
            .secrets_store
            .derive_key(secret_name, name, "flag")
            .await
            .unwrap_or_else(|| DEFAULT_SECRET.to_vec());

        if let Some(ref flag_prefix) = spec.flag {
            self.flag = V1FlagGenerator::generate(
                &self.service.config.flag_prefix,
                flag_prefix,
                &secret,
                &self.session,
            );
        }

        debug!("Connecting to backend {}", spec.backend);
        let mut socket = TcpStream::connect(&spec.backend).await?;
        let (b_rx, mut b_tx) = socket.split();
        let mut b_rx = BufReader::with_capacity(BUF_SIZE, b_rx);
        if spec.flag.is_some() {
            let mut buf = Vec::<u8>::with_capacity(self.flag.len() + 1);
            writeln!(buf, "{}", self.flag)?;
            b_tx.write_all(&buf).await?;
        }

        if spec.logs {
            let cancel = CancellationToken::new();
            let (tx, rx) = mpsc::channel(64);
            join!(
                self.pipe(cancel.clone(), tx.clone(), 0, c_rx, b_tx),
                self.pipe(cancel, tx, 1, b_rx, c_tx),
                self.log(Some(rx))
            )
            .0?;
        } else {
            let _ = join!(
                tokio::io::copy(&mut c_rx, &mut b_tx),
                tokio::io::copy(&mut b_rx, &mut c_tx)
            );
        }

        Ok(())
    }

    // TODO: this is shit, too many heap allocations
    async fn pipe<R, W>(
        &self,
        cancel: CancellationToken,
        log: mpsc::Sender<LogMessage>,
        stream: u8,
        mut rx: R,
        mut tx: W,
    ) -> Result<(), Error>
    where
        R: AsyncBufReadExt + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            select! {
              r = rx.fill_buf() => {
                match r {
                  Ok(n) => {
                    let l = n.len();
                    if l == 0 {
                      cancel.cancel();
                      break Ok(());
                    }
                    let _ = log.try_send((stream, n.to_vec()));
                    if tx.write_all(n).await.is_err() {
                      cancel.cancel();
                      break Ok(());
                    }
                    rx.consume(l);
                  },
                  Err(_) => {
                    cancel.cancel();
                    break Ok(());
                  }
                }
              },
              _ = cancel.cancelled() => {
                break Ok(());
              }
            }
        }
    }

    async fn log(&self, chan: Option<mpsc::Receiver<LogMessage>>) -> Result<(), Error> {
        let mut log = match chan {
            Some(log) => log,
            None => return Ok(()),
        };

        let mut logger = FileLogger::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(Path::new(&self.service.config.logs_dir).join(self.get_log_filename()))
                .await?,
        );

        while let Some((stream, message)) = log.recv().await {
            trace!("stream {}: wrote {} bytes", stream, message.len());
            if let Err(err) = logger.write(stream, &message).await {
                trace!("Error writing to log file: {}", err);
            }
        }
        logger.flush().await?;
        Ok(())
    }

    fn get_log_filename(&self) -> String {
        let timestamp_nanos = (self.session.timestamp.timestamp() as u64) * 1_000_000_000
            + (self.session.timestamp.nanosecond() as u64);
        format!("{}:{}", self.route.0, timestamp_nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::KubernetesClient;
    use crate::config::{PortRange, ServiceConfig};
    use crate::crd::{CTFRouteSpec, CTFRouteSpecPOW};
    use crate::store::{RoutesStore, SecretsStore};
    use chrono::{Duration as ChronoDuration, Utc};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;

    fn create_test_service_context() -> Arc<ServiceContext> {
        let client = KubernetesClient::new_dummy_for_tests();
        Arc::new(ServiceContext {
            config: ServiceConfig {
                host: "[::]".into(),
                secret_root: "root".into(),
                http_port: 8000,
                tls_port: 4433,
                tls_cert: "cert.pem".into(),
                tls_key: "key.pem".into(),
                hostname_suffix: "".into(),
                flag_prefix: "CTF".into(),
                logs_dir: "./data/".into(),
                reserved_ports: PortRange(20000..=20999),
                auto_ports: PortRange(30000..=30999),
            },
            challenges_store: RoutesStore::new(
                client.clone(),
                "",
                PortRange(20000..=20999),
                PortRange(30000..=30999),
            ),
            secrets_store: SecretsStore::new(client, "root"),
            shutdown: CancellationToken::new(),
        })
    }

    #[tokio::test]
    async fn test_handler_get_log_filename() {
        let ctx = create_test_service_context();
        let spec = CTFRouteSpec {
            flag: Some("test_flag".into()),
            backend: "127.0.0.1:8080".into(),
            ..Default::default()
        };
        let challenge = Arc::new(("my-chal".to_string(), spec));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut handler = Handler::new(ctx, challenge, addr);
        handler.flag = "CTF{test_flag|secret_payload}".into();

        let filename = handler.get_log_filename();
        assert!(filename.starts_with("my-chal:"));
    }

    #[tokio::test]
    async fn test_handler_pipe() {
        let ctx = create_test_service_context();
        let spec = CTFRouteSpec::default();
        let challenge = Arc::new(("my-chal".to_string(), spec));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let handler = Handler::new(ctx, challenge, addr);

        let (client_tx, server_rx) = tokio::io::duplex(64);
        let (server_tx, mut client_rx) = tokio::io::duplex(64);

        let cancel = CancellationToken::new();
        let (log_tx, mut log_rx) = mpsc::channel(64);

        let rx = BufReader::new(server_rx);
        let pipe_handle =
            tokio::spawn(async move { handler.pipe(cancel, log_tx, 0, rx, server_tx).await });

        // Write payload to client_tx
        tokio::spawn(async move {
            let mut tx = client_tx;
            tx.write_all(b"hello pipe").await.unwrap();
        });

        let mut buf = vec![0u8; 10];
        client_rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello pipe");

        let log_msg = log_rx.recv().await.unwrap();
        assert_eq!(log_msg.0, 0);
        assert_eq!(log_msg.1, b"hello pipe");

        pipe_handle.abort();
    }

    #[tokio::test]
    async fn test_handler_unavailable_challenge() {
        let ctx = create_test_service_context();
        let future_time = Utc::now() + ChronoDuration::hours(24);
        let spec = CTFRouteSpec {
            available_at: Some(future_time.into()),
            pow: Some(CTFRouteSpecPOW {
                difficulty: 0,
                enable_admin_bypass: false,
            }),
            ..Default::default()
        };
        let challenge = Arc::new(("my-chal".to_string(), spec));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut handler = Handler::new(ctx, challenge, addr);

        let (client_rx, client_tx) = tokio::io::duplex(64);
        let (mut server_rx, server_tx) = tokio::io::duplex(64);

        let handle = tokio::spawn(async move { handler.handle(client_rx, server_tx).await });

        let mut output = vec![0u8; 54];
        server_rx.read_exact(&mut output).await.unwrap();
        assert_eq!(
            &output,
            b"== info: This challenge is not currently available ==\n"
        );

        drop(client_tx);
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_handler_unavailable_challenge_admin_bypass() {
        let ctx = create_test_service_context();
        let future_time = Utc::now() + ChronoDuration::hours(24);
        let spec = CTFRouteSpec {
            available_at: Some(future_time.into()),
            pow: Some(CTFRouteSpecPOW {
                difficulty: 0,
                enable_admin_bypass: true,
            }),
            ..Default::default()
        };
        let challenge = Arc::new(("my-chal".to_string(), spec));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut handler = Handler::new(ctx, challenge, addr);

        let (client_rx, mut client_tx) = tokio::io::duplex(1024);
        let (server_rx, server_tx) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move { handler.handle(client_rx, server_tx).await });

        let mut reader = BufReader::new(server_rx);
        let mut line1 = String::new();
        reader.read_line(&mut line1).await.unwrap();
        assert_eq!(
            line1,
            "== info: This challenge is not currently available ==\n"
        );

        let mut line2 = String::new();
        reader.read_line(&mut line2).await.unwrap();
        assert!(line2.starts_with("== proof of work:"));

        client_tx.write_all(b"invalid_token\n").await.unwrap();

        assert!(handle.await.unwrap().is_ok());
    }
}

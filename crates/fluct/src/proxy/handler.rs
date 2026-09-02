use std::{io::Write, net::SocketAddr, os::fd::AsRawFd, sync::Arc, time::Duration};

use chrono::Utc;
use fluct::{Error, Session};
use k8s_common::crd::CTFProxyRoute;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tracing::debug;

use crate::{
    config::ServiceContext,
    hash::derive_key,
    proxy::{
        challenge::{Challenge, ChallengeSolveState},
        flag::{FlagGenerator, V1FlagGenerator},
        util::{IdleTimeoutReader, copy_bidirectional, get_line, set_tcp_keepalive},
    },
};

pub struct Handler {
    service: Arc<ServiceContext>,
    route: Arc<CTFProxyRoute>,
    session: Session,
    flag: String,
}

const BUF_SIZE: usize = 16 * 1024;
const MAX_UID_SIZE: usize = 64;
const MAX_INPUT_TIME_UID: Duration = Duration::from_secs(30);

impl Handler {
    pub fn new(service: Arc<ServiceContext>, route: Arc<CTFProxyRoute>, addr: SocketAddr) -> Self {
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

    pub async fn handle<R, W>(&mut self, c_rx: R, mut c_tx: W) -> Result<(), Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut c_rx = BufReader::with_capacity(BUF_SIZE, c_rx);
        let spec = &self.route.spec;

        let secret = spec.policy.secret.as_deref().unwrap_or("notsecret");

        let mut request_pow: Option<ChallengeSolveState> = None;
        let pow = spec.policy.pow.as_ref();
        if let Some(available_at) = spec.policy.available_at
            && available_at > self.session.timestamp
        {
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
            let secret = derive_key("challenge", secret);

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

        if spec.policy.request_uid {
            c_tx.write_all(b"== input: competitor id (max 64 chars) ==\n")
                .await?;
            self.session.uid = get_line(&mut c_rx, MAX_UID_SIZE, MAX_INPUT_TIME_UID).await?;
        }

        let secret = derive_key("flag", secret);

        if let Some(ref flag_prefix) = spec.policy.flag {
            self.flag = V1FlagGenerator::generate(
                &self.service.config.flag_prefix,
                flag_prefix,
                &secret,
                &self.session,
            );
        }

        let backend_addr = &spec.backend;
        debug!("Connecting to backend {}", backend_addr);
        let addr = self.service.resolver.resolve(backend_addr).await?;
        let mut socket = TcpStream::connect(addr).await?;
        let _ = set_tcp_keepalive(socket.as_raw_fd());
        let (b_rx, mut b_tx) = socket.split();
        if spec.policy.flag.is_some() {
            let mut buf = Vec::<u8>::with_capacity(self.flag.len() + 1);
            writeln!(buf, "{}", self.flag)?;
            b_tx.write_all(&buf).await?;
        }

        let max_idle = self.service.config.max_idle_timeout;
        let idle_secs = match (max_idle, spec.policy.idle_timeout) {
            (0, t) => t.unwrap_or(0),
            (admin_max, None) => admin_max,
            (admin_max, Some(0)) => admin_max,
            (admin_max, Some(t)) => t.min(admin_max),
        };

        if idle_secs == 0 {
            copy_bidirectional(c_rx, b_tx, b_rx, c_tx).await
        } else {
            let idle_duration = Duration::from_secs(idle_secs as u64);
            let c_rx = IdleTimeoutReader::new(c_rx, idle_duration);
            let b_rx = IdleTimeoutReader::new(b_rx, idle_duration);
            copy_bidirectional(c_rx, b_tx, b_rx, c_tx).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortRange, ServiceConfig};
    use crate::services::routes::RoutesService;
    use crate::store::resolver::{Resolver, ResolverExpiryPolicy};
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::crd::{CTFProxyRouteSpec, RoutePolicySpec, RouteSpecPOW};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    use tokio_util::sync::CancellationToken;

    fn create_test_service_context() -> Arc<ServiceContext> {
        let client = crate::services::routes::create_dummy_kube_client();
        Arc::new(ServiceContext {
            config: ServiceConfig {
                host: "[::]".into(),
                tls_port: 4433,
                tls_cert: "cert.pem".into(),
                tls_key: "key.pem".into(),
                flag_prefix: "CTF".into(),
                port_ranges: vec![PortRange(20000..=20999), PortRange(30000..=30999)],
                system_namespace: None,
                tproxy_port: None,
                netfilter_priority: -150,
                netfilter_mark: 0x0a17c4ad,
                max_idle_timeout: 300,
            },
            resolver: Resolver::new(1000, ResolverExpiryPolicy::default()),
            routes_service: RoutesService::new(
                client.clone(),
                vec![PortRange(20000..=20999), PortRange(30000..=30999)],
                None,
                None,
            ),
            shutdown: CancellationToken::new(),
        })
    }

    #[tokio::test]
    async fn test_handler_unavailable_challenge() {
        let ctx = create_test_service_context();
        let future_time = Utc::now() + ChronoDuration::hours(24);
        let spec = CTFProxyRouteSpec {
            policy: RoutePolicySpec {
                available_at: Some(future_time),
                pow: Some(RouteSpecPOW {
                    difficulty: 0,
                    enable_admin_bypass: false,
                }),
                ..Default::default()
            },
            backend: "127.0.0.1:8080".into(),
        };
        let challenge = Arc::new(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20001".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec,
        });
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
        let spec = CTFProxyRouteSpec {
            policy: RoutePolicySpec {
                available_at: Some(future_time),
                pow: Some(RouteSpecPOW {
                    difficulty: 0,
                    enable_admin_bypass: true,
                }),
                ..Default::default()
            },
            backend: "127.0.0.1:8080".into(),
        };
        let challenge = Arc::new(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20001".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec,
        });
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

    #[tokio::test]
    async fn test_handler_request_uid_and_backend_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();

        let ctx = create_test_service_context();
        let spec = CTFProxyRouteSpec {
            policy: RoutePolicySpec {
                request_uid: true,
                flag: Some("FLAG_SECRET".into()),
                ..Default::default()
            },
            backend: backend_addr.to_string(),
        };
        let challenge = Arc::new(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20001".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec,
        });
        let client_ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut handler = Handler::new(ctx, challenge, client_ip);

        // Spawn mock backend server
        let backend_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(&mut socket);
            let mut received_flag = String::new();
            reader.read_line(&mut received_flag).await.unwrap();
            socket.write_all(b"hello from backend\n").await.unwrap();
            received_flag
        });

        let (client_rx, mut client_tx) = tokio::io::duplex(1024);
        let (server_rx, server_tx) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move { handler.handle(client_rx, server_tx).await });

        let mut reader = BufReader::new(server_rx);
        let mut prompt = String::new();
        reader.read_line(&mut prompt).await.unwrap();
        assert_eq!(prompt, "== input: competitor id (max 64 chars) ==\n");

        // Send competitor UID
        client_tx.write_all(b"team-42\n").await.unwrap();

        // Read backend response forwarded to client
        let mut backend_msg = String::new();
        reader.read_line(&mut backend_msg).await.unwrap();
        assert_eq!(backend_msg, "hello from backend\n");

        drop(client_tx);
        let flag = backend_task.await.unwrap();
        assert!(flag.starts_with("CTF{"));
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_handler_idle_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();

        let ctx = create_test_service_context();
        let spec = CTFProxyRouteSpec {
            policy: RoutePolicySpec {
                idle_timeout: Some(1),
                ..Default::default()
            },
            backend: backend_addr.to_string(),
        };
        let challenge = Arc::new(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20002".into()),
                ..Default::default()
            },
            spec,
        });
        let client_ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut handler = Handler::new(ctx, challenge, client_ip);

        let _backend_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = socket.write_all(b"too late\n").await;
        });

        let (client_rx, _client_tx) = tokio::io::duplex(1024);
        let (_server_rx, server_tx) = tokio::io::duplex(1024);

        let res = handler.handle(client_rx, server_tx).await;
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("idle timeout") || err_str.contains("timed out"));
    }
}

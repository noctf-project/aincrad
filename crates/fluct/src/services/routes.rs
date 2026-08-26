use std::{sync::Arc, time::Duration};

use crate::{
    config::{PortRange, ServiceContext},
    store::{
        ports::{self, PortAllocation, PortsStore},
        routes::{CTFRouteStatusPair, MetadataAndSpec, RoutesStore},
    },
    util::slice::*,
};
use fluct::Error;
use futures::StreamExt;
use k8s_common::{
    KubernetesClient,
    crd::{CTFRoute, CTFRouteEndpoints, CTFRouteStatus, EndpointTarget},
};
use kube::runtime::watcher::Event;
use tokio::{select, sync::mpsc, try_join};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct RoutesService {
    client: KubernetesClient,
    hostname_suffix: String,
    tls_port: u16,
    routes: RoutesStore,
    ports: PortsStore,
}

const ROUTE_BUF_SIZE: usize = 32;
const STATUS_UPDATE_CONCURRENCY: usize = 8;
const RESYNC_INTERVAL: Duration = Duration::from_secs(15);

impl RoutesService {
    pub fn new(
        client: KubernetesClient,
        hostname_suffix: &str,
        tls_port: u16,
        range_reserved: PortRange,
        range_auto: PortRange,
        route_seed: &str,
    ) -> Self {
        Self {
            client,
            hostname_suffix: hostname_suffix.to_owned(),
            tls_port,
            routes: RoutesStore::new(route_seed),
            ports: PortsStore::new(range_reserved, range_auto),
        }
    }

    pub fn get_tls_route(&self, hostname: &str) -> Option<Arc<MetadataAndSpec>> {
        self.routes.get_tls_route(hostname)
    }

    fn format_tls_host(&self, key: &str) -> Option<String> {
        let base = self.routes.get_hostname(key)?;
        if self.hostname_suffix.is_empty() {
            Some(base)
        } else if self.hostname_suffix.starts_with('.') {
            Some(format!("{base}{}", self.hostname_suffix))
        } else {
            Some(format!("{base}.{}", self.hostname_suffix))
        }
    }

    fn desired_status(&self, generation: i64, route: &Arc<MetadataAndSpec>) -> CTFRouteStatusPair {
        let mut conditions = Vec::new();
        let namespaced_name = route.namespaced_name();
        let tcp_reserve = self.ports.reserve(&namespaced_name, route.spec.port);

        let tcp_endpoint = match tcp_reserve {
            Ok(Some(r)) => {
                let port = match r {
                    PortAllocation::Intended(p) => p,
                    PortAllocation::Pending { next, .. } => next,
                };
                conditions.push(k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                    type_: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "Ready".to_string(),
                    message: "Route endpoints ready".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ),
                    observed_generation: Some(generation),
                });
                Some(EndpointTarget {
                    host: self.hostname_suffix.clone(),
                    port,
                })
            }
            Ok(None) => {
                conditions.push(k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                    type_: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "Ready".to_string(),
                    message: "Route endpoints ready".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ),
                    observed_generation: Some(generation),
                });
                None
            }
            Err(e) => {
                error!("{}", e);
                let (reason, message) = match &e {
                    ports::PortError::Occupied(port, owner) => (
                        "PortOccupied".to_string(),
                        format!("port {port} is already occupied by route '{owner}'"),
                    ),
                    ports::PortError::OutOfRange(port) => (
                        "PortOutOfRange".to_string(),
                        format!("port {port} is outside reserved range"),
                    ),
                    ports::PortError::Exhausted => (
                        "PortExhausted".to_string(),
                        "auto port pool is exhausted".to_string(),
                    ),
                };

                conditions.push(k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                    type_: "Ready".to_string(),
                    status: "False".to_string(),
                    reason,
                    message,
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ),
                    observed_generation: Some(generation),
                });
                None
            }
        };
        (
            namespaced_name.clone(),
            CTFRouteStatus {
                observed_generation: Some(generation),
                endpoints: Some(CTFRouteEndpoints {
                    tls: route.spec.tls.as_ref().and_then(|_| {
                        let host = self.format_tls_host(&namespaced_name)?;
                        Some(EndpointTarget {
                            host,
                            port: self.tls_port,
                        })
                    }),
                    tcp: tcp_endpoint,
                }),
                conditions,
            },
        )
    }

    fn handle_route_event(&self, event: Event<CTFRoute>) -> Option<Arc<MetadataAndSpec>> {
        match event {
            Event::Init => {
                self.routes.clear();
                self.ports.clear();
                None
            }
            Event::Apply(data) | Event::InitApply(data) => {
                let name = data.metadata.name?;
                let uid = match data.metadata.uid {
                    Some(uid) => uid,
                    None => {
                        warn!("Dropping CTFRoute {name}: missing metadata.uid");
                        return None;
                    }
                };
                let generation = match data.metadata.generation {
                    Some(g) => g,
                    None => {
                        warn!("Dropping CTFRoute {name}: missing metadata.generation");
                        return None;
                    }
                };
                let namespace = data.metadata.namespace.unwrap_or_else(|| "default".into());

                let entry = Arc::new(MetadataAndSpec {
                    name,
                    namespace,
                    uid,
                    generation,
                    observed_generation: data.status.as_ref().and_then(|x| x.observed_generation),
                    spec: data.spec,
                });
                let namespaced_name = entry.namespaced_name();
                let prev = self.routes.insert(entry.clone());

                let port = data
                    .status
                    .as_ref()
                    .and_then(|status| status.endpoints.as_ref())
                    .and_then(|endpoints| endpoints.tcp.as_ref())
                    .map(|tcp| tcp.port);
                self.ports.insert(&namespaced_name, port);

                if let Some(prev) = prev
                    && prev.generation == generation
                {
                    return None;
                }

                Some(entry)
            }
            Event::Delete(data) => {
                let name = data.metadata.name?;
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_name = format!("{}:{}", namespace, name);

                self.routes.remove(&namespaced_name);
                self.ports.insert(&namespaced_name, None);
                info!("Removed route {}", namespaced_name);
                None
            }
            _ => None,
        }
    }

    async fn run_watch_routes(
        &self,
        cancel: CancellationToken,
        mut receiver: mpsc::Receiver<Event<CTFRoute>>,
        updater: Option<mpsc::Sender<Arc<MetadataAndSpec>>>,
    ) {
        let mut buffer = Vec::with_capacity(ROUTE_BUF_SIZE);
        loop {
            select! {
              _ = receiver.recv_many(&mut buffer, ROUTE_BUF_SIZE) => {
                for event in buffer.drain(..).dedup_last() {
                    if let Some(status) = self.handle_route_event(event)
                        && let Some(ref updater) = updater {
                        let _ = updater.send(status).await
                            .map_err(|err| warn!("error queueing status {:?}", err));
                    }
                }
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
    }

    async fn update_status(&self, full: &str, status: CTFRouteStatus) -> Result<(), Error> {
        let mut parts = full.split(":");
        let namespace = parts.next().unwrap_or("default");
        let name = parts.next().unwrap_or("");
        self.client
            .update_object_status::<CTFRoute, _>(name, namespace, status)
            .await?;
        Ok(())
    }

    async fn ship_unsynced(&self) {
        let unsynced = self.routes.unsynced_routes();
        if unsynced.is_empty() {
            return;
        }
        info!("Shipping {} unsynced route status updates", unsynced.len());
        let resync_updates = unsynced.into_iter().map(|route| {
            let (full, status) = self.desired_status(route.generation, &route);
            async move {
                self.update_status(&full, status)
                    .await
                    .inspect(|_| info!("successfully updated status for {}", full))
                    .unwrap_or_else(|e| error!("failed to update status: {}", e));
            }
        });
        futures::stream::iter(resync_updates)
            .buffer_unordered(STATUS_UPDATE_CONCURRENCY)
            .count()
            .await;
    }

    async fn run_updates(
        &self,
        cancel: CancellationToken,
        mut rx: mpsc::Receiver<Arc<MetadataAndSpec>>,
    ) -> Result<(), Error> {
        info!("started route status updater");
        let manager = self
            .client
            .get_lease_manager("fluct-leader", Duration::from_secs(15))
            .await
            .inspect_err(|e| error!("error setting lease manager: {:?}", e))?;

        let (mut channel, task) = manager.watch().await;
        let mut locked = false;
        let mut buffer = Vec::with_capacity(ROUTE_BUF_SIZE);
        let mut resync_interval = tokio::time::interval(RESYNC_INTERVAL);
        resync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                _ = channel.changed() => {
                    let lock_state = *channel.borrow_and_update();

                    if lock_state {
                        if locked {
                            continue;
                        }
                        locked = true;
                        info!("Gained route status leader");
                        self.ports.clear_pending();
                        self.ship_unsynced().await;
                    } else {
                        info!("Lost route status leader");
                        locked = false;
                    }
                }
                _ = resync_interval.tick() => {
                    if locked {
                        self.ship_unsynced().await;
                    }
                }
                _ = rx.recv_many(&mut buffer, ROUTE_BUF_SIZE) => {
                    // discard if not locked
                    if !locked {
                        buffer.clear();
                        continue;
                    }
                    let status_updates = buffer.drain(..).dedup_last().filter_map(|arc| {
                        let metadata = self.routes.get_route(&arc.namespaced_name())?;
                        let (full, status) = self.desired_status(metadata.generation, &metadata);
                        Some(async move {
                            self.update_status(&full, status)
                                .await
                                .inspect(|_| info!("successfully updated status for {}", full))
                                .unwrap_or_else(|e| error!("failed to update status: {}", e));
                        })
                    });
                    futures::stream::iter(status_updates)
                        .buffer_unordered(STATUS_UPDATE_CONCURRENCY)
                        .count()
                        .await;
                },
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }

        drop(channel);

        // Wait for the finish of the manager and get it back
        let _manager = tokio::join!(task).0.unwrap()?;
        info!("stopped route status updater");

        Ok(())
    }

    pub fn get_active_ports(&self) -> Vec<u16> {
        self.ports.active_ports()
    }

    pub fn get_route_from_port(&self, port: u16) -> Option<Arc<MetadataAndSpec>> {
        let port = self.ports.active_route(port)?;
        self.routes.get_route(&port)
    }

    pub async fn run(&self, ctx: Arc<ServiceContext>) -> Result<(), Error> {
        let cancel = &ctx.shutdown;
        let (route_tx, route_rx) = mpsc::channel(128);
        let (update_tx, update_rx) = mpsc::channel(128);
        try_join!(
            log_job(
                "kube CTFRoute watcher",
                self.client.watch(cancel.clone(), route_tx, None)
            ),
            log_job(
                "kube CTFRoute processor",
                self.run_watch_routes(cancel.clone(), route_rx, Some(update_tx))
            ),
            self.run_updates(cancel.clone(), update_rx),
        )?;
        Ok(())
    }
}

pub async fn log_job<F, R>(name: &str, task: F) -> Result<R, Error>
where
    F: Future<Output = R>,
{
    info!("started {}", name);
    let r = task.await;
    info!("stopped {}", name);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFRouteBackend, CTFRouteSpec, CTFRouteSpecTLS, CTFRouteStatus};
    use kube::core::ObjectMeta;

    fn make_store(suffix: &str) -> RoutesService {
        RoutesService::new(
            KubernetesClient::new_dummy_for_tests(),
            suffix,
            443,
            PortRange(20000..=20010),
            PortRange(30000..=30010),
            "link-start",
        )
    }

    #[tokio::test]
    async fn test_challenges_store_port_lookup() {
        let store = make_store("");

        let spec = CTFRouteSpec {
            port: Some(20001),
            flag: Some("test_flag".into()),
            backend: CTFRouteBackend {
                service: "127.0.0.1".into(),
                port: 1337,
            },
            ..Default::default()
        };
        store.routes.insert(Arc::new(MetadataAndSpec {
            name: "my-chal".into(),
            namespace: "default".into(),
            uid: "uid-port-lookup".into(),
            generation: 1,
            observed_generation: None,
            spec,
        }));
        store.ports.insert("default:my-chal", Some(20001));

        let active_ports = store.get_active_ports();
        assert!(active_ports.contains(&20001));

        let found = store.get_route_from_port(20001);
        assert!(found.is_some());
        assert_eq!(found.unwrap().namespaced_name(), "default:my-chal");

        assert!(store.get_route_from_port(20002).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_event_lifecycle() {
        let store = make_store("");
        let chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("test-chal".into()),
                namespace: Some("default".into()),
                uid: Some("uid-lifecycle".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "backend-service".into(),
                    port: 80,
                },
                tls: Some(CTFRouteSpecTLS {
                    prefix: Some("web".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        };

        // Apply event
        store.handle_route_event(Event::Apply(chal.clone()));
        let derived_host = store.format_tls_host("default:test-chal").unwrap();
        let fetched_chal = store.get_tls_route(&derived_host);
        assert!(fetched_chal.is_some());
        assert_eq!(
            fetched_chal.as_ref().unwrap().namespaced_name(),
            "default:test-chal"
        );
        assert_eq!(
            fetched_chal.as_ref().unwrap().spec.backend,
            CTFRouteBackend {
                service: "backend-service".into(),
                port: 80,
            }
        );

        // Delete event
        store.handle_route_event(Event::Delete(chal));
        assert!(store.get_tls_route(&derived_host).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_event_update_tag() {
        let store = make_store("");
        let mut chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("test-chal".into()),
                namespace: Some("default".into()),
                uid: Some("uid-update-tag".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "backend-service".into(),
                    port: 80,
                },
                tls: Some(CTFRouteSpecTLS {
                    prefix: Some("web".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        };

        store.handle_route_event(Event::Apply(chal.clone()));
        let host_v1 = store.format_tls_host("default:test-chal").unwrap();
        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().spec.backend,
            CTFRouteBackend {
                service: "backend-service".into(),
                port: 80,
            }
        );

        // Apply update with SAME tag (should not deregister)
        chal.metadata.generation = Some(2);
        chal.spec.backend = CTFRouteBackend {
            service: "backend-service".into(),
            port: 8080,
        };
        store.handle_route_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().spec.backend,
            CTFRouteBackend {
                service: "backend-service".into(),
                port: 8080,
            }
        );

        // Apply update with NEW tag (should register new first, then deregister old)
        chal.metadata.generation = Some(3);
        chal.spec.tls = Some(CTFRouteSpecTLS {
            prefix: Some("web2".to_string()),
            ..Default::default()
        });
        store.handle_route_event(Event::Apply(chal.clone()));
        let host_v2 = store.format_tls_host("default:test-chal").unwrap();
        assert_eq!(
            store.get_tls_route(&host_v2).unwrap().spec.backend,
            CTFRouteBackend {
                service: "backend-service".into(),
                port: 8080,
            }
        );
        assert!(store.get_tls_route(&host_v1).is_none());

        // Apply update with NO tag (should deregister old tag)
        chal.metadata.generation = Some(4);
        chal.spec.tls = None;
        store.handle_route_event(Event::Apply(chal.clone()));
        assert!(store.get_tls_route(&host_v2).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_observed_generation() {
        let store = make_store("");
        let chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("status-chal".into()),
                namespace: Some("default".into()),
                uid: Some("uid-observed-gen".into()),
                generation: Some(42),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "backend-service".into(),
                    port: 80,
                },
                ..Default::default()
            },
            status: Some(CTFRouteStatus {
                observed_generation: Some(42),
                endpoints: None,
                conditions: Vec::new(),
            }),
        };

        store.handle_route_event(Event::Apply(chal.clone()));
        let observed_gen = store
            .routes
            .get_route("default:status-chal")
            .and_then(|r| r.observed_generation);
        assert_eq!(observed_gen, Some(42));

        store.handle_route_event(Event::Delete(chal));
        assert!(store.routes.get_route("default:status-chal").is_none());
    }

    #[tokio::test]
    async fn test_prepare_desired_status() {
        let store = make_store(".example.com");
        let spec = CTFRouteSpec {
            port: Some(20001),
            backend: CTFRouteBackend {
                service: "backend".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let route = Arc::new(MetadataAndSpec {
            name: "my-challenge".into(),
            namespace: "prod".into(),
            uid: "uid-desired-status".into(),
            generation: 5,
            observed_generation: None,
            spec,
        });
        store.routes.insert(route.clone());

        let (full, status) = store.desired_status(5, &route);
        assert_eq!(full, "prod:my-challenge");
        assert_eq!(status.observed_generation, Some(5));

        let expected_hostname = store.format_tls_host("prod:my-challenge").unwrap();
        let endpoints = status.endpoints.unwrap();
        assert_eq!(endpoints.tls.unwrap().host, expected_hostname);
        assert_eq!(endpoints.tcp.unwrap().port, 20001);

        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].type_, "Ready");
        assert_eq!(status.conditions[0].status, "True");
        assert_eq!(status.conditions[0].reason, "Ready");
    }

    #[tokio::test]
    async fn test_desired_status_port_occupied_error() {
        let store = make_store(".example.com");
        store.ports.reserve("prod:r1", Some(20001)).unwrap();

        let spec = CTFRouteSpec {
            port: Some(20001),
            backend: CTFRouteBackend {
                service: "backend".into(),
                port: 80,
            },
            ..Default::default()
        };
        let route = Arc::new(MetadataAndSpec {
            name: "r2".into(),
            namespace: "prod".into(),
            uid: "uid-r2".into(),
            generation: 1,
            observed_generation: None,
            spec,
        });

        let (_, status) = store.desired_status(1, &route);
        assert!(status.endpoints.as_ref().unwrap().tcp.is_none());

        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].type_, "Ready");
        assert_eq!(status.conditions[0].status, "False");
        assert_eq!(status.conditions[0].reason, "PortOccupied");
        assert!(status.conditions[0].message.contains("20001"));
    }

    #[tokio::test]
    async fn test_desired_status_port_out_of_range_error() {
        let store = make_store("example.com");

        let spec = CTFRouteSpec {
            port: Some(10000),
            backend: CTFRouteBackend {
                service: "backend".into(),
                port: 80,
            },
            ..Default::default()
        };
        let route = Arc::new(MetadataAndSpec {
            name: "r1".into(),
            namespace: "prod".into(),
            uid: "uid-r1".into(),
            generation: 1,
            observed_generation: None,
            spec,
        });

        let (_, status) = store.desired_status(1, &route);
        assert!(status.endpoints.as_ref().unwrap().tcp.is_none());

        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].type_, "Ready");
        assert_eq!(status.conditions[0].status, "False");
        assert_eq!(status.conditions[0].reason, "PortOutOfRange");
    }

    #[tokio::test]
    async fn test_desired_status_hostname_suffix_formatting() {
        let store = make_store("c.noctf.dev");
        let spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "backend".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let route = Arc::new(MetadataAndSpec {
            name: "test-web-route".into(),
            namespace: "default".into(),
            uid: "uid-suffix-fmt".into(),
            generation: 1,
            observed_generation: None,
            spec,
        });
        store.routes.insert(route.clone());

        let (_, status) = store.desired_status(1, &route);
        let tls_host = status.endpoints.unwrap().tls.unwrap().host;

        let expected_host = store.format_tls_host("default:test-web-route").unwrap();
        assert_eq!(tls_host, expected_host);
        assert!(tls_host.ends_with(".c.noctf.dev"));
    }

    #[tokio::test]
    async fn test_desired_status_empty_hostname_suffix() {
        let store = make_store("");
        let spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                service: "backend".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let route = Arc::new(MetadataAndSpec {
            name: "test-web-route".into(),
            namespace: "default".into(),
            uid: "uid-empty-suffix".into(),
            generation: 1,
            observed_generation: None,
            spec,
        });
        store.routes.insert(route.clone());

        let (_, status) = store.desired_status(1, &route);
        let tls_host = status.endpoints.unwrap().tls.unwrap().host;

        let expected_host = store.format_tls_host("default:test-web-route").unwrap();
        assert_eq!(tls_host, expected_host);
    }
}

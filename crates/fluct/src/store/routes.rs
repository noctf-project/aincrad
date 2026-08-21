use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use fluct::Error;
use kube::runtime::watcher::Event;
use tokio::{select, sync::mpsc, try_join};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    clients::KubernetesClient,
    config::{PortRange, ServiceContext},
    crd::{CTFRoute, CTFRouteEndpoints, CTFRouteSpecPair, CTFRouteStatus, EndpointTarget},
    crypto::hash::sha256,
    store::{PortAllocation, PortManager, PortSyncResult},
};

const HOSTNAME_ID_LEN: usize = 16;
pub type CTFRouteStatusPair = (String, CTFRouteStatus);

fn derive_hostname(namespaced_id: &str, namespace: &str, tls_tag: Option<&str>) -> String {
    let mut prefix = namespaced_id;
    let tls_tag = if let Some(tag) = tls_tag {
        tag
    } else if let Some((left, right)) = namespaced_id.rsplit_once('-') {
        prefix = left;
        right
    } else {
        prefix = "";
        namespaced_id
    };
    let input = format!("aincrad:hostname:{}:{}", namespace, tls_tag);
    let hash = sha256(input.as_bytes());
    let mut id = base32::encode(base32::Alphabet::Crockford, &hash).to_lowercase();
    id.truncate(HOSTNAME_ID_LEN);
    if prefix.is_empty() {
        id
    } else {
        format!("{}-{}", prefix, id)
    }
}

fn extract_sni_hostname(sni: &str) -> &str {
    sni.split('.').next().unwrap_or(sni)
}

struct MetadataAndSpec {
    generation: Option<i64>,
    observed_generation: Option<i64>,
    spec: Arc<CTFRouteSpecPair>,
}

pub struct RoutesStore {
    client: KubernetesClient,
    hostname_suffix: String,
    routes: DashMap<String, MetadataAndSpec>,
    ports: PortManager,
    tls_routes: DashMap<String, Arc<CTFRouteSpecPair>>,
}

impl RoutesStore {
    pub fn new(
        client: KubernetesClient,
        hostname_suffix: &str,
        range_reserved: PortRange,
        range_auto: PortRange,
    ) -> Self {
        Self {
            client,
            hostname_suffix: hostname_suffix.to_owned(),
            routes: DashMap::new(),
            ports: PortManager::new(range_reserved, range_auto),
            tls_routes: DashMap::new(),
        }
    }

    pub fn get_tls_route(&self, hostname: &str) -> Option<Arc<CTFRouteSpecPair>> {
        let clean_host = extract_sni_hostname(hostname);
        Some(self.tls_routes.get(clean_host)?.value().clone())
    }

    #[cfg(test)]
    fn get_observed_generation(&self, namespaced_name: &str) -> Option<i64> {
        self.routes
            .get(namespaced_name)
            .map(|g| g.value().observed_generation)
            .flatten()
    }

    pub fn unsynced_status_updates(&self) -> Vec<CTFRouteStatusPair> {
        self.routes
            .iter()
            .filter(|x| x.generation > x.observed_generation)
            .map(|x| self.desired_status(x.value().generation, &x.value().spec))
            .collect()
    }

    fn desired_status(
        &self,
        generation: Option<i64>,
        spec: &CTFRouteSpecPair,
    ) -> CTFRouteStatusPair {
        let mut parts = spec.0.split(":");
        let namespace = parts.next().unwrap_or("default");
        let name = parts.next().unwrap_or("");
        (
            spec.0.to_string(),
            CTFRouteStatus {
                observed_generation: generation,
                endpoints: Some(CTFRouteEndpoints {
                    tls: spec.1.tls.as_ref().map(|x| EndpointTarget {
                        host: format!(
                            "{}{}",
                            derive_hostname(name, namespace, x.key.as_deref()),
                            self.hostname_suffix
                        ),
                        port: 0,
                    }),
                    tcp: self
                        .ports
                        .reserve(&spec.0, spec.1.port)
                        .inspect_err(|e| error!("{}", e))
                        .unwrap_or(None)
                        .map(|r| EndpointTarget {
                            host: self.hostname_suffix.clone(),
                            port: match r {
                                PortAllocation::Intended(p) => p,
                                PortAllocation::Pending { next, .. } => next,
                            },
                        }),
                }),
            },
        )
    }

    fn handle_route_event(&self, event: Event<CTFRoute>) -> Option<Arc<CTFRouteSpecPair>> {
        match event {
            Event::Apply(data) | Event::InitApply(data) => {
                let name = data.metadata.name?;
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_name = format!("{}:{}", namespace, name);

                let spec = Arc::new((namespaced_name.clone(), data.spec));
                let prev = self.routes.insert(
                    namespaced_name.clone(),
                    MetadataAndSpec {
                        generation: data.metadata.generation,
                        observed_generation: data.status.and_then(|x| x.observed_generation),
                        spec: spec.clone(),
                    },
                );

                let mut hostname_changed = true;
                if let Some(prev) = prev {
                    if prev.generation == data.metadata.generation {
                        return None;
                    }
                    
                    hostname_changed = false;
                    // deregister old hostname if tls changed
                    if let Some(prev_tls) = &prev.spec.1.tls
                        && prev.spec.1.tls != spec.1.tls
                    {
                        hostname_changed = true;
                        let host = derive_hostname(&name, namespace, prev_tls.key.as_deref());
                        info!("Deregistering route {} hostname: {}", namespaced_name, host);
                        self.tls_routes.remove(&host);
                    }
                }
                if let Some(tls) = spec.1.tls.as_ref() {
                    let host = derive_hostname(&name, namespace, tls.key.as_deref());
                    if hostname_changed {
                        info!("Registering route {} hostname: {}", namespaced_name, host);
                    }
                    self.tls_routes.insert(host, spec.clone());
                }
                match self.ports.sync(&namespaced_name, spec.1.port) {
                    PortSyncResult::Added(p) => {
                        info!("route {namespaced_name} bound port {p}",)
                    }
                    PortSyncResult::Changed { old, new } => {
                        info!("route {namespaced_name} swapped from {old} -> {new}")
                    }
                    PortSyncResult::Removed(p) => {
                        info!("route {namespaced_name} unbound port {p}")
                    }
                    _ => (),
                }

                Some(spec.clone())
            }
            Event::Delete(data) => {
                let name = data.metadata.name?;
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_name = format!("{}:{}", namespace, name);
                if let Some((_, prev)) = self.routes.remove(&namespaced_name)
                    && let Some(tls) = &prev.spec.1.tls
                {
                    let host = derive_hostname(&name, namespace, tls.key.as_deref());
                    info!("Deregistering route {} hostname: {}", namespaced_name, host);
                    self.tls_routes.remove(&host);
                }
                if let PortSyncResult::Removed(p) = self.ports.sync(&namespaced_name, None) {
                    info!("route {namespaced_name} unbound port {p}")
                }
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
        update_tx: mpsc::Sender<Arc<CTFRouteSpecPair>>,
    ) {
        loop {
            select! {
              Some(event) = receiver.recv() => {
                if let Some(status) = self.handle_route_event(event) {
                    let _ = update_tx.send(status).await
                        .map_err(|err| warn!("error queueing status {:?}", err));
                }
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
    }

    async fn update_status(&self, full: &str, status: CTFRouteStatus) {
        let mut parts = full.split(":");
        let namespace = parts.next().unwrap_or("default");
        let name = parts.next().unwrap_or("");
        match self
            .client
            .update_object_status::<CTFRoute, _>(name, namespace, status)
            .await
        {
            Ok(()) => info!("updated status for {}", full),
            Err(e) => error!("could not update status: {}", e),
        }
    }

    async fn run_updates(
        &self,
        cancel: CancellationToken,
        mut rx: mpsc::Receiver<Arc<CTFRouteSpecPair>>,
    ) -> Result<(), Error> {
        info!("started route status updater");
        let manager = self
            .client
            .get_lease_manager("fluct-routes", Duration::from_secs(15))
            .await
            .inspect_err(|e| error!("error setting lease manager: {:?}", e))?;

        let (mut channel, task) = manager.watch().await;
        let mut locked = false;
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
                        for (full, status) in self.unsynced_status_updates() {
                            self.update_status(&full, status).await;
                        }
                    } else {
                        info!("Lost route status leader");
                        locked = false;
                    }
                }
                Some(arc) = rx.recv() => {
                    // discard if not locked
                    if !locked {
                        continue;
                    }
                    let (full, status) = &*arc;
                    let mut parts = full.split(":");
                    let namespace = parts.next().unwrap_or("default");
                    let name = parts.next().unwrap_or("");
                    match self.client
                        .update_object_status::<CTFRoute, _>(name, namespace, status).await {
                        Ok(()) => info!("updated status for {}", full),
                        Err(e) => error!("could not update status: {}", e)
                    }
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

    pub fn get_route_from_port(&self, port: u16) -> Option<Arc<CTFRouteSpecPair>> {
        let port = self.ports.active_route(port)?;
        let route = self.routes.get(&port)?;
        Some(route.value().spec.clone())
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
                self.run_watch_routes(cancel.clone(), route_rx, update_tx)
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
    use crate::crd::{CTFRouteSpec, CTFRouteSpecTLS, CTFRouteStatus};
    use kube::core::ObjectMeta;

    fn make_store(suffix: &str) -> RoutesStore {
        RoutesStore::new(
            KubernetesClient::new_dummy_for_tests(),
            suffix,
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        )
    }

    #[test]
    fn test_derive_hostname_empty_and_tag() {
        let host1 = derive_hostname("my-chal", "default", Some(""));
        let host2 = derive_hostname("my-chal", "default", Some("web"));
        let host3 = derive_hostname("my-chal", "other-ns", Some(""));
        let host4 = derive_hostname("my-chal", "other-ns", None);
        let host5 = derive_hostname("chal", "other-ns", None);

        assert!(host1.starts_with("my-chal-"));
        assert!(host2.starts_with("my-chal-"));
        assert!(host3.starts_with("my-chal-"));

        // host4 takes entropy from first dash
        assert!(host4.starts_with("my-"));
        assert!(!host4.starts_with("my-chal-"));
        assert!(host4.len() == 3 + HOSTNAME_ID_LEN);

        // host5 gets overridden completely
        assert!(host5.len() == HOSTNAME_ID_LEN);
        assert!(!host5.starts_with("chal-"));

        // Hostnames must be distinct when tag or namespace differs
        assert_ne!(host1, host2);
        assert_ne!(host1, host3);
        // Verify length of hash prefix is HASH_SLICE_LEN chars (+ 1 hyphen + len of "my-chal")
        assert_eq!(host1.len(), "my-chal-".len() + HOSTNAME_ID_LEN);
    }

    #[test]
    fn test_extract_sni_hostname() {
        assert_eq!(
            extract_sni_hostname("my-chal-12345.c.sk8.dog"),
            "my-chal-12345"
        );
        assert_eq!(extract_sni_hostname("my-chal-12345"), "my-chal-12345");
        assert_eq!(extract_sni_hostname(""), "");
    }

    #[tokio::test]
    async fn test_challenges_store_port_lookup() {
        let store = make_store("");

        let spec = CTFRouteSpec {
            port: Some(20001),
            flag: Some("test_flag".into()),
            backend: "127.0.0.1:1337".into(),
            ..Default::default()
        };
        store.routes.insert(
            "default:my-chal".into(),
            MetadataAndSpec {
                generation: None,
                observed_generation: None,
                spec: Arc::new(("default:my-chal".to_string(), spec)),
            },
        );
        store.ports.sync("default:my-chal", Some(20001));

        let active_ports = store.get_active_ports();
        assert!(active_ports.contains(&20001));

        let found = store.get_route_from_port(20001);
        assert!(found.is_some());
        assert_eq!(found.unwrap().0, "default:my-chal");

        assert!(store.get_route_from_port(20002).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_event_lifecycle() {
        let store = make_store("");
        let chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("test-chal".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: "backend-service:80".into(),
                tls: Some(CTFRouteSpecTLS {
                    key: Some("web".to_string()),
                }),
                ..Default::default()
            },
            status: None,
        };

        let derived_host = derive_hostname("test-chal", "default", Some("web"));

        // Apply event
        store.handle_route_event(Event::Apply(chal.clone()));
        let fetched_chal = store.get_tls_route(&derived_host);
        assert!(fetched_chal.is_some());
        assert_eq!(fetched_chal.as_ref().unwrap().0, "default:test-chal");
        assert_eq!(
            fetched_chal.as_ref().unwrap().1.backend,
            "backend-service:80"
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
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: "backend-service:80".into(),
                tls: Some(CTFRouteSpecTLS {
                    key: Some("web".to_string()),
                }),
                ..Default::default()
            },
            status: None,
        };

        let host_v1 = derive_hostname("test-chal", "default", Some("web"));
        store.handle_route_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().1.backend,
            "backend-service:80"
        );

        // Apply update with SAME tag (should not deregister)
        chal.metadata.generation = Some(2);
        chal.spec.backend = "backend-service:8080".into();
        store.handle_route_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().1.backend,
            "backend-service:8080"
        );

        // Apply update with NEW tag (should register new first, then deregister old)
        chal.metadata.generation = Some(3);
        chal.spec.tls = Some(CTFRouteSpecTLS {
            key: Some("web2".to_string()),
        });
        let host_v2 = derive_hostname("test-chal", "default", Some("web2"));
        store.handle_route_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_route(&host_v2).unwrap().1.backend,
            "backend-service:8080"
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
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: "backend-service:80".into(),
                ..Default::default()
            },
            status: Some(CTFRouteStatus {
                observed_generation: Some(42),
                endpoints: None,
            }),
        };

        store.handle_route_event(Event::Apply(chal.clone()));
        let observed_gen = store.get_observed_generation("default:status-chal");
        assert_eq!(observed_gen, Some(42));

        store.handle_route_event(Event::Delete(chal));
        assert!(
            store
                .get_observed_generation("default:status-chal")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_prepare_desired_status() {
        let store = make_store(".example.com");
        let spec = CTFRouteSpec {
            port: Some(20001),
            backend: "backend:80".into(),
            tls: Some(CTFRouteSpecTLS {
                key: Some("web".to_string()),
            }),
            ..Default::default()
        };
        let pair = ("prod:my-challenge".to_string(), spec);

        let (full, status) = store.desired_status(Some(5), &pair);
        assert_eq!(full, "prod:my-challenge");
        assert_eq!(status.observed_generation, Some(5));

        let expected_hostname = format!(
            "{}.example.com",
            derive_hostname("my-challenge", "prod", Some("web"))
        );
        let endpoints = status.endpoints.unwrap();
        assert_eq!(endpoints.tls.unwrap().host, expected_hostname);
        assert_eq!(endpoints.tcp.unwrap().port, 20001);
    }
}

use std::{sync::Arc, time::Duration};

use dashmap::{DashMap, DashSet};
use fluct::Error;
use kube::runtime::watcher::Event;
use tokio::{join, select, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    clients::KubernetesClient,
    config::ServiceContext,
    crd::{CTFPort, CTFRoute, CTFRouteSpecPair, CTFRouteStatus},
    crypto::hash::sha256,
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
    if prefix == "" {
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

pub struct ChallengesStore {
    client: KubernetesClient,
    hostname_suffix: String,
    challenges: DashMap<String, MetadataAndSpec>,
    ports: DashMap<u16, String>,
    tls_hostnames: DashMap<String, Arc<CTFRouteSpecPair>>,
}

impl ChallengesStore {
    pub fn new(client: KubernetesClient, hostname_suffix: &str) -> Self {
        Self {
            client,
            hostname_suffix: hostname_suffix.to_owned(),
            challenges: DashMap::new(),
            ports: DashMap::new(),
            tls_hostnames: DashMap::new(),
        }
    }

    pub fn get_tls_challenge(&self, hostname: &str) -> Option<Arc<CTFRouteSpecPair>> {
        let clean_host = extract_sni_hostname(hostname);
        Some(self.tls_hostnames.get(clean_host)?.value().clone())
    }

    #[cfg(test)]
    fn get_observed_generation(&self, namespaced_name: &str) -> Option<i64> {
        self.challenges
            .get(namespaced_name)
            .map(|g| g.value().observed_generation)
            .flatten()
    }

    pub fn unsynced_status_updates(&self) -> Vec<CTFRouteStatusPair> {
        self.challenges
            .iter()
            .filter(|x| x.generation > x.observed_generation)
            .map(|x| self.get_desired_status(x.value().generation, &x.value().spec))
            .collect()
    }

    fn get_desired_status(
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
                tls_hostname: spec.1.tls.as_ref().map(|x| {
                    format!(
                        "{}{}",
                        derive_hostname(name, namespace, x.as_deref()),
                        self.hostname_suffix
                    )
                }),
            },
        )
    }

    pub fn handle_challenge_event(&self, event: Event<CTFRoute>) -> Option<CTFRouteStatusPair> {
        match event {
            Event::Apply(data) | Event::InitApply(data) => {
                let Some(name) = data.metadata.name else {
                    return None;
                };
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_name = format!("{}:{}", namespace, name);

                let spec = Arc::new((namespaced_name.clone(), data.spec));
                let prev = self.challenges.insert(
                    namespaced_name.clone(),
                    MetadataAndSpec {
                        generation: data.metadata.generation,
                        observed_generation: data.status.map(|x| x.observed_generation).flatten(),
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
                        let host = derive_hostname(&name, namespace, prev_tls.as_deref());
                        info!(
                            "Deregistering challenge {} hostname: {}",
                            namespaced_name, host
                        );
                        self.tls_hostnames.remove(&host);
                    }
                }
                if let Some(tls) = spec.1.tls.as_ref() {
                    let host = derive_hostname(&name, namespace, tls.as_deref());
                    if hostname_changed {
                        info!(
                            "Registering challenge {} hostname: {}",
                            namespaced_name, host
                        );
                    }
                    self.tls_hostnames.insert(host, spec.clone());
                }
                Some(self.get_desired_status(data.metadata.generation, &spec))
            }
            Event::Delete(data) => {
                let Some(name) = data.metadata.name else {
                    return None;
                };
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_name = format!("{}:{}", namespace, name);

                if let Some((_, prev)) = self.challenges.remove(&namespaced_name) {
                    if let Some(tls) = &prev.spec.1.tls {
                        let host = derive_hostname(&name, namespace, tls.as_deref());
                        info!(
                            "Deregistering challenge {} hostname: {}",
                            namespaced_name, host
                        );
                        self.tls_hostnames.remove(&host);
                    }
                }
                info!("Removed challenge {}", namespaced_name);
                None
            }
            _ => None,
        }
    }

    pub fn handle_port_event(&self, event: Event<CTFPort>) {
        match event {
            Event::Apply(data) | Event::InitApply(data) => {
                let Some(port) = get_port_from_metadata(&data.metadata.name) else {
                    warn!("Port {:?} is not a port", data.metadata.name);
                    return;
                };
                let namespace = data.metadata.namespace.as_deref().unwrap_or("default");
                let namespaced_challenge = format!("{}:{}", namespace, data.spec.route);
                info!(
                    "Binding port {} to challenge {}",
                    port, namespaced_challenge
                );
                self.ports.insert(port, namespaced_challenge);
            }
            Event::Delete(data) => {
                let Some(port) = get_port_from_metadata(&data.metadata.name) else {
                    warn!("Port {:?} is not a port", data.metadata.name);
                    return;
                };
                info!("Removing port {}", port);
                self.ports.remove(&port);
            }
            _ => (),
        }
    }

    async fn watch_challenges(
        &self,
        cancel: CancellationToken,
        mut receiver: mpsc::Receiver<Event<CTFRoute>>,
        status_tx: mpsc::Sender<CTFRouteStatusPair>,
    ) {
        loop {
            select! {
              Some(event) = receiver.recv() => {
                if let Some(status) = self.handle_challenge_event(event) {
                    let _ = status_tx.send(status).await
                        .map_err(|err| warn!("error queueing status {:?}", err));
                }
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
        info!("Stopped watching challenges");
    }

    async fn watch_ports(
        &self,
        cancel: CancellationToken,
        mut receiver: mpsc::Receiver<Event<CTFPort>>,
    ) {
        loop {
            select! {
              Some(event) = receiver.recv() => {
                self.handle_port_event(event);
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
        info!("Stopped watching ports");
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
        mut rx: mpsc::Receiver<CTFRouteStatusPair>,
    ) -> Result<(), Error> {
        info!("Started challenge status updater");
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
                        info!("Gained challenge status leader");
                        for (full, status) in self.unsynced_status_updates() {
                            self.update_status(&full, status).await;
                        }
                    } else {
                        info!("Lost challenge status leader");
                        locked = false;
                    }
                }
                Some((full, status)) = rx.recv() => {
                    // discard if not locked
                    if !locked {
                        continue;
                    }
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
        info!("Stopped challenge status updater");

        Ok(())
    }

    pub fn get_active_ports(&self) -> DashSet<u16> {
        self.ports
            .iter()
            .map(|e| *e.key())
            .collect::<DashSet<u16>>()
    }

    pub fn get_challenge_from_port(&self, port: u16) -> Option<Arc<CTFRouteSpecPair>> {
        let port = self.ports.get(&port)?;
        let challenge = self.challenges.get(port.value())?;
        Some(challenge.value().spec.clone())
    }

    pub async fn run(&self, ctx: Arc<ServiceContext>) -> Result<(), Error> {
        let cancel = &ctx.shutdown;
        let namespace = &ctx.config.tcp_namespace;
        let (ports_tx, ports_rx) = mpsc::channel(128);
        let (challenges_tx, challenges_rx) = mpsc::channel(128);
        let (status_tx, status_rx) = mpsc::channel(128);
        join!(
            self.client
                .watch(cancel.clone(), ports_tx, namespace.clone()),
            self.client.watch(cancel.clone(), challenges_tx, None),
            self.watch_ports(cancel.clone(), ports_rx),
            self.watch_challenges(cancel.clone(), challenges_rx, status_tx),
            self.run_updates(cancel.clone(), status_rx),
        )
        .0;
        Ok(())
    }
}

fn get_port_from_metadata(name: &Option<String>) -> Option<u16> {
    match name {
        Some(name) => name.parse().ok(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{CTFPortSpec, CTFRouteSpec, CTFRouteStatus};
    use kube::core::ObjectMeta;

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

    #[test]
    fn test_get_port_from_metadata() {
        assert_eq!(get_port_from_metadata(&Some("30000".into())), Some(30000));
        assert_eq!(get_port_from_metadata(&Some("invalid".into())), None);
        assert_eq!(get_port_from_metadata(&None), None);
    }

    #[tokio::test]
    async fn test_challenges_store_port_lookup() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), "");

        let spec = CTFRouteSpec {
            flag: Some("test_flag".into()),
            backend: "127.0.0.1:1337".into(),
            ..Default::default()
        };
        store.challenges.insert(
            "default:my-chal".into(),
            MetadataAndSpec {
                generation: None,
                observed_generation: None,
                spec: Arc::new(("default:my-chal".to_string(), spec)),
            },
        );
        store.ports.insert(30000, "default:my-chal".into());

        let active_ports = store.get_active_ports();
        assert!(active_ports.contains(&30000));

        let found = store.get_challenge_from_port(30000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().0, "default:my-chal");

        assert!(store.get_challenge_from_port(30001).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_event_lifecycle() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), "");
        let chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("test-chal".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: "backend-service:80".into(),
                tls: Some(Some("web".into())),
                ..Default::default()
            },
            status: None,
        };

        let derived_host = derive_hostname("test-chal", "default", Some("web"));

        // Apply event
        store.handle_challenge_event(Event::Apply(chal.clone()));
        let fetched_chal = store.get_tls_challenge(&derived_host);
        assert!(fetched_chal.is_some());
        assert_eq!(fetched_chal.as_ref().unwrap().0, "default:test-chal");
        assert_eq!(
            fetched_chal.as_ref().unwrap().1.backend,
            "backend-service:80"
        );

        // Delete event
        store.handle_challenge_event(Event::Delete(chal));
        assert!(store.get_tls_challenge(&derived_host).is_none());
    }

    #[tokio::test]
    async fn test_handle_port_event_lifecycle() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), "");
        let port_chal = CTFPort {
            metadata: ObjectMeta {
                name: Some("30005".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFPortSpec {
                route: "pwn-chal".into(),
            },
        };

        store.handle_port_event(Event::Apply(port_chal.clone()));
        assert!(store.get_active_ports().contains(&30005));

        store.handle_port_event(Event::Delete(port_chal));
        assert!(!store.get_active_ports().contains(&30005));
    }

    #[tokio::test]
    async fn test_handle_challenge_event_update_tag() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), "");
        let mut chal = CTFRoute {
            metadata: ObjectMeta {
                name: Some("test-chal".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFRouteSpec {
                backend: "backend-service:80".into(),
                tls: Some(Some("web".into())),
                ..Default::default()
            },
            status: None,
        };

        let host_v1 = derive_hostname("test-chal", "default", Some("web"));
        store.handle_challenge_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_challenge(&host_v1).unwrap().1.backend,
            "backend-service:80"
        );

        // Apply update with SAME tag (should not deregister)
        chal.metadata.generation = Some(2);
        chal.spec.backend = "backend-service:8080".into();
        store.handle_challenge_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_challenge(&host_v1).unwrap().1.backend,
            "backend-service:8080"
        );

        // Apply update with NEW tag (should register new first, then deregister old)
        chal.metadata.generation = Some(3);
        chal.spec.tls = Some(Some("web2".into()));
        let host_v2 = derive_hostname("test-chal", "default", Some("web2"));
        store.handle_challenge_event(Event::Apply(chal.clone()));
        assert_eq!(
            store.get_tls_challenge(&host_v2).unwrap().1.backend,
            "backend-service:8080"
        );
        assert!(store.get_tls_challenge(&host_v1).is_none());

        // Apply update with NO tag (should deregister old tag)
        chal.metadata.generation = Some(4);
        chal.spec.tls = None;
        store.handle_challenge_event(Event::Apply(chal.clone()));
        assert!(store.get_tls_challenge(&host_v2).is_none());
    }

    #[tokio::test]
    async fn test_handle_challenge_observed_generation() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), "");
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
                tls_hostname: Some("status-chal.example.com".into()),
            }),
        };

        store.handle_challenge_event(Event::Apply(chal.clone()));
        let observed_gen = store.get_observed_generation("default:status-chal");
        assert_eq!(observed_gen, Some(42));

        store.handle_challenge_event(Event::Delete(chal));
        assert!(
            store
                .get_observed_generation("default:status-chal")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_get_desired_status() {
        let store = ChallengesStore::new(KubernetesClient::new_dummy_for_tests(), ".example.com");
        let spec = CTFRouteSpec {
            backend: "backend:80".into(),
            tls: Some(Some("web".into())),
            ..Default::default()
        };
        let pair = ("prod:my-challenge".to_string(), spec);

        let (full, status) = store.get_desired_status(Some(5), &pair);
        assert_eq!(full, "prod:my-challenge");
        assert_eq!(status.observed_generation, Some(5));

        let expected_hostname = format!(
            "{}.example.com",
            derive_hostname("my-challenge", "prod", Some("web"))
        );
        assert_eq!(status.tls_hostname, Some(expected_hostname));
    }
}

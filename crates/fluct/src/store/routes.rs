use std::sync::Arc;

use k8s_common::crd::{CTFProxyRoute, ProxyRouteKey};
use parking_lot::RwLock;

use crate::config::PortRange;

const MAX_PORTS: usize = 65536;

#[derive(Default)]
struct StoreInner {
    ports: Vec<Option<Arc<CTFProxyRoute>>>,
    routes: hashbrown::HashMap<String, Arc<CTFProxyRoute>>,
}

pub struct ProxyStore {
    port_ranges: Vec<PortRange>,
    inner: RwLock<StoreInner>,
}

impl ProxyStore {
    pub fn new(port_ranges: Vec<PortRange>) -> Self {
        Self {
            port_ranges,
            inner: RwLock::new(StoreInner {
                ports: vec![None; MAX_PORTS],
                routes: hashbrown::HashMap::new(),
            }),
        }
    }

    /// Checks if a port is within the configured port ranges.
    pub fn is_valid_port(&self, port: u16) -> bool {
        port != 0
            && (self.port_ranges.is_empty() || self.port_ranges.iter().any(|r| r.contains(port)))
    }

    /// Inserts or updates a `CTFProxyRoute` in the in-memory store.
    pub fn insert(&self, route: CTFProxyRoute) {
        if let Ok(key) = route.route_key() {
            let entry = Arc::new(route);
            let mut inner = self.inner.write();
            match key {
                ProxyRouteKey::Tcp(port) => {
                    if self.is_valid_port(port) {
                        inner.ports[port as usize] = Some(entry);
                    }
                }
                ProxyRouteKey::Route(name) => {
                    inner.routes.insert(name, entry);
                }
            }
        }
    }

    /// Removes a route identified by its metadata name (e.g. `p30005` or `rwhoami`).
    pub fn remove(&self, name: &str) {
        if let Ok(key) = std::str::FromStr::from_str(name) {
            let mut inner = self.inner.write();
            match key {
                ProxyRouteKey::Tcp(port) => {
                    inner.ports[port as usize] = None;
                }
                ProxyRouteKey::Route(route_name) => {
                    inner.routes.remove(&route_name);
                }
            }
        }
    }

    /// Retrieves an active TCP route by listening port number via direct O(1) array indexing.
    pub fn get_tcp_route(&self, port: u16) -> Option<Arc<CTFProxyRoute>> {
        let inner = self.inner.read();
        inner.ports.get(port as usize).and_then(|opt| opt.clone())
    }

    /// Retrieves an active named/SNI route by hostname.
    pub fn get_named_route(&self, hostname: &str) -> Option<Arc<CTFProxyRoute>> {
        let clean_name = hostname.split('.').next().unwrap_or(hostname);
        let inner = self.inner.read();
        inner.routes.get(clean_name).cloned()
    }

    /// Returns a list of all active TCP ports with bound routes.
    pub fn active_tcp_ports(&self) -> Vec<u16> {
        let inner = self.inner.read();
        inner
            .ports
            .iter()
            .enumerate()
            .filter_map(|(port, opt)| opt.as_ref().map(|_| port as u16))
            .collect()
    }

    /// Clears all routes from the store.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.ports.fill(None);
        inner.routes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::CTFProxyRouteSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_store() -> ProxyStore {
        ProxyStore::new(vec![PortRange(20000..=29999), PortRange(30000..=32767)])
    }

    #[test]
    fn test_proxy_store_tcp_lifecycle() {
        let store = make_store();
        let route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20001".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        };

        store.insert(route);
        assert_eq!(store.active_tcp_ports(), vec![20001]);

        let found = store.get_tcp_route(20001).unwrap();
        assert_eq!(found.spec.backend, "127.0.0.1:8080");

        assert!(store.get_tcp_route(20002).is_none());

        store.remove("p20001");
        assert!(store.get_tcp_route(20001).is_none());
        assert!(store.active_tcp_ports().is_empty());
    }

    #[test]
    fn test_proxy_store_named_route_lifecycle() {
        let store = make_store();
        let route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami-x8k2".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "whoami-service:80".into(),
                ..Default::default()
            },
        };

        store.insert(route);

        // Exact match
        let found = store.get_named_route("whoami-x8k2").unwrap();
        assert_eq!(found.spec.backend, "whoami-service:80");

        // SNI with domain suffix
        let found_sni = store.get_named_route("whoami-x8k2.c.noctf.dev").unwrap();
        assert_eq!(found_sni.spec.backend, "whoami-service:80");

        assert!(store.get_named_route("nonexistent").is_none());

        store.remove("rwhoami-x8k2");
        assert!(store.get_named_route("whoami-x8k2").is_none());
    }

    #[test]
    fn test_proxy_store_port_out_of_range_filtered() {
        let store = make_store();
        let route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p10000".into()), // outside 20000-29999 and 30000-32767
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        };

        store.insert(route);
        assert!(store.get_tcp_route(10000).is_none());
        assert!(store.active_tcp_ports().is_empty());
    }

    #[test]
    fn test_proxy_store_clear() {
        let store = make_store();
        store.insert(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20001".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        });
        store.insert(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        });

        assert_eq!(store.active_tcp_ports().len(), 1);
        assert!(store.get_named_route("whoami").is_some());

        store.clear();

        assert!(store.active_tcp_ports().is_empty());
        assert!(store.get_tcp_route(20001).is_none());
        assert!(store.get_named_route("whoami").is_none());
    }

    #[test]
    fn test_is_valid_port() {
        let store = ProxyStore::new(vec![PortRange(20000..=29999), PortRange(30000..=32767)]);
        assert!(store.is_valid_port(20000));
        assert!(store.is_valid_port(25000));
        assert!(store.is_valid_port(29999));
        assert!(store.is_valid_port(30000));
        assert!(store.is_valid_port(32767));

        assert!(!store.is_valid_port(0));
        assert!(!store.is_valid_port(19999));
        assert!(!store.is_valid_port(32768));
        assert!(!store.is_valid_port(4433));

        let unconstrained = ProxyStore::new(vec![]);
        assert!(!unconstrained.is_valid_port(0));
        assert!(unconstrained.is_valid_port(80));
        assert!(unconstrained.is_valid_port(4433));
    }
}

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use k8s_common::crd::{CTFInstanceStatusEndpoint, CTFRoute};
use kube::runtime::reflector::Store;

use crate::utils::labels::{INSTANCE_LABEL, POD_LABEL};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub namespace: String,
    pub instance: String,
    pub route: String,
}

#[derive(Clone)]
pub struct RouteCache {
    store: Store<CTFRoute>,
    index: Arc<Mutex<BTreeMap<RouteKey, Arc<CTFRoute>>>>,
}

impl RouteCache {
    pub fn new(store: Store<CTFRoute>) -> Self {
        Self {
            store,
            index: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn store(&self) -> &Store<CTFRoute> {
        &self.store
    }

    pub fn update(&self, route: &CTFRoute) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let instance = route
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(INSTANCE_LABEL))
            .cloned()
            .or_else(|| {
                route.metadata.owner_references.as_ref().and_then(|refs| {
                    refs.iter()
                        .find(|r| r.kind == "CTFInstance")
                        .map(|r| r.name.clone())
                })
            });

        let route_name = route
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(POD_LABEL))
            .cloned()
            .unwrap_or_else(|| route.metadata.name.clone().unwrap_or_default());

        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(inst_name) = instance {
            let key = RouteKey {
                namespace: ns.to_string(),
                instance: inst_name,
                route: route_name,
            };
            if route.metadata.deletion_timestamp.is_none() {
                lock.insert(key, Arc::new(route.clone()));
            } else {
                lock.remove(&key);
            }
        }
    }

    pub fn remove(&self, route: &CTFRoute) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let instance = route
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(INSTANCE_LABEL))
            .cloned()
            .or_else(|| {
                route.metadata.owner_references.as_ref().and_then(|refs| {
                    refs.iter()
                        .find(|r| r.kind == "CTFInstance")
                        .map(|r| r.name.clone())
                })
            });

        let route_name = route
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(POD_LABEL))
            .cloned()
            .unwrap_or_else(|| route.metadata.name.clone().unwrap_or_default());

        if let Some(inst_name) = instance {
            let key = RouteKey {
                namespace: ns.to_string(),
                instance: inst_name,
                route: route_name,
            };
            let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
            lock.remove(&key);
        }
    }

    pub fn clear(&self) {
        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.clear();
    }

    pub fn find_instance_routes(&self, namespace: &str, instance_name: &str) -> Vec<Arc<CTFRoute>> {
        let start_key = RouteKey {
            namespace: namespace.to_string(),
            instance: instance_name.to_string(),
            route: String::new(),
        };

        let lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.range(start_key..)
            .take_while(|(k, _)| k.namespace == namespace && k.instance == instance_name)
            .map(|(_, route)| route.clone())
            .collect()
    }

    pub fn find_instance_endpoints(
        &self,
        namespace: &str,
        instance_name: &str,
    ) -> Vec<CTFInstanceStatusEndpoint> {
        let start_key = RouteKey {
            namespace: namespace.to_string(),
            instance: instance_name.to_string(),
            route: String::new(),
        };

        let lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        let mut endpoints = Vec::new();

        for (k, route) in lock
            .range(start_key..)
            .take_while(|(k, _)| k.namespace == namespace && k.instance == instance_name)
        {
            if let Some(status) = &route.status
                && let Some(route_endpoints) = &status.endpoints
            {
                if let Some(tls) = &route_endpoints.tls {
                    endpoints.push(CTFInstanceStatusEndpoint {
                        name: k.route.clone(),
                        type_: "tls".to_string(),
                        target: tls.clone(),
                    });
                }
                if let Some(tcp) = &route_endpoints.tcp {
                    endpoints.push(CTFInstanceStatusEndpoint {
                        name: k.route.clone(),
                        type_: "tcp".to_string(),
                        target: tcp.clone(),
                    });
                }
            }
        }

        endpoints.sort_by(|a, b| (&a.name, &a.type_).cmp(&(&b.name, &b.type_)));
        endpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btreemap;
    use k8s_common::crd::{CTFRouteEndpoints, CTFRouteSpec, CTFRouteStatus, EndpointTarget};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::store;

    #[test]
    fn test_route_cache_find_instance_endpoints() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-1-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 20001,
                    }),
                }),
                ..Default::default()
            }),
        };

        cache.update(&route);

        let endpoints = cache.find_instance_endpoints("default", "chal-1");
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].type_, "tcp");
        assert_eq!(endpoints[1].type_, "tls");

        // Non-matching instance query returns empty vector
        let empty = cache.find_instance_endpoints("default", "non-existent");
        assert!(empty.is_empty());

        // Removal purges cache index entry
        cache.remove(&route);
        assert!(
            cache
                .find_instance_endpoints("default", "chal-1")
                .is_empty()
        );
    }

    #[test]
    fn test_route_cache_owner_ref_fallback() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-owner-c-pwn".into()),
                namespace: Some("ctf".into()),
                labels: Some(btreemap! {
                    POD_LABEL => "pwn",
                }),
                owner_references: Some(vec![
                    k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                        api_version: "aincrad.noctf.dev/v1".into(),
                        kind: "CTFInstance".into(),
                        name: "chal-owner".into(),
                        uid: "uid-123".into(),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tcp: Some(EndpointTarget {
                        host: "pwn.c.noctf.dev".into(),
                        port: 20002,
                    }),
                    tls: None,
                }),
                ..Default::default()
            }),
        };

        cache.update(&route);

        let endpoints = cache.find_instance_endpoints("ctf", "chal-owner");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "pwn");
        assert_eq!(endpoints[0].type_, "tcp");
        assert_eq!(endpoints[0].target.port, 20002);
    }

    #[test]
    fn test_route_cache_deletion_timestamp_pruning() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let mut route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-del-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-del",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        cache.update(&route);
        assert_eq!(
            cache.find_instance_endpoints("default", "chal-del").len(),
            1
        );

        // Mark for deletion -> updating should prune the entry from the index
        route.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        cache.update(&route);
        assert!(
            cache
                .find_instance_endpoints("default", "chal-del")
                .is_empty()
        );
    }

    #[test]
    fn test_route_cache_multiple_routes_and_sorting() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let route_web = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-multi-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-multi",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "web.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        let route_admin = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-multi-c-admin".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-multi",
                    POD_LABEL => "admin",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "admin.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        cache.update(&route_web);
        cache.update(&route_admin);

        let endpoints = cache.find_instance_endpoints("default", "chal-multi");
        assert_eq!(endpoints.len(), 2);
        // "admin" comes before "web" alphabetically
        assert_eq!(endpoints[0].name, "admin");
        assert_eq!(endpoints[1].name, "web");
    }

    #[test]
    fn test_route_cache_update_overwrites_existing() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let mut route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-upd-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-upd",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };

        cache.update(&route);
        assert!(
            cache
                .find_instance_endpoints("default", "chal-upd")
                .is_empty()
        );

        // Update status with endpoints
        route.status = Some(CTFRouteStatus {
            endpoints: Some(CTFRouteEndpoints {
                tls: Some(EndpointTarget {
                    host: "updated.c.noctf.dev".into(),
                    port: 443,
                }),
                tcp: None,
            }),
            ..Default::default()
        });
        cache.update(&route);

        let endpoints = cache.find_instance_endpoints("default", "chal-upd");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].target.host, "updated.c.noctf.dev");
    }

    #[test]
    fn test_route_cache_namespace_isolation() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let route_ns1 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-same-c-web".into()),
                namespace: Some("ns-1".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-same",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "ns1.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        let route_ns2 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-same-c-web".into()),
                namespace: Some("ns-2".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-same",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "ns2.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        cache.update(&route_ns1);
        cache.update(&route_ns2);

        let ep1 = cache.find_instance_endpoints("ns-1", "chal-same");
        assert_eq!(ep1.len(), 1);
        assert_eq!(ep1[0].target.host, "ns1.c.noctf.dev");

        let ep2 = cache.find_instance_endpoints("ns-2", "chal-same");
        assert_eq!(ep2.len(), 1);
        assert_eq!(ep2[0].target.host, "ns2.c.noctf.dev");
    }

    #[test]
    fn test_route_cache_clear() {
        let (store, _writer) = store();
        let cache = RouteCache::new(store);

        let route = CTFRoute {
            metadata: ObjectMeta {
                name: Some("chal-clr-c-web".into()),
                namespace: Some("default".into()),
                labels: Some(btreemap! {
                    INSTANCE_LABEL => "chal-clr",
                    POD_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: Some(CTFRouteStatus {
                endpoints: Some(CTFRouteEndpoints {
                    tls: Some(EndpointTarget {
                        host: "clr.c.noctf.dev".into(),
                        port: 443,
                    }),
                    tcp: None,
                }),
                ..Default::default()
            }),
        };

        cache.update(&route);
        assert_eq!(
            cache.find_instance_endpoints("default", "chal-clr").len(),
            1
        );

        cache.clear();
        assert!(
            cache
                .find_instance_endpoints("default", "chal-clr")
                .is_empty()
        );

        let _ = cache.store();
    }
}

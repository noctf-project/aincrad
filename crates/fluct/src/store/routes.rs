use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use tracing::info;

use crate::{
    crd::{CTFRouteSpecPair, CTFRouteStatus},
    crypto::hash::sha256,
};

pub const HOSTNAME_ID_LEN: usize = 16;
pub type CTFRouteStatusPair = (String, CTFRouteStatus);

pub fn derive_hostname(name: &str, namespace: &str, tls_tag: Option<&str>) -> String {
    let mut prefix = name;
    let tls_tag = if let Some(tag) = tls_tag {
        tag
    } else if let Some((left, right)) = name.rsplit_once('-') {
        prefix = left;
        right
    } else {
        prefix = "";
        name
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

pub fn extract_sni_hostname(sni: &str) -> &str {
    sni.split('.').next().unwrap_or(sni)
}

fn parse_namespaced_name(key: &str) -> (&str, &str) {
    let mut parts = key.split(':');
    let namespace = parts.next().unwrap_or("default");
    let name = parts.next().unwrap_or("");
    (namespace, name)
}

#[derive(Clone, Debug)]
pub struct MetadataAndSpec {
    pub generation: Option<i64>,
    pub observed_generation: Option<i64>,
    pub spec: Arc<CTFRouteSpecPair>,
}

#[derive(Default)]
struct StoreInner {
    routes: HashMap<String, MetadataAndSpec>,
    tls: HashMap<String, Arc<CTFRouteSpecPair>>,
}

impl StoreInner {
    fn insert(&mut self, entry: MetadataAndSpec) -> Option<MetadataAndSpec> {
        let key = entry.spec.0.clone();
        let (namespace, name) = parse_namespaced_name(&key);

        let prev = self.routes.insert(key.clone(), entry.clone());

        let prev_tls = prev.as_ref().and_then(|p| p.spec.1.tls.as_ref());
        let new_tls = entry.spec.1.tls.as_ref();

        if let Some(old_tls) = prev_tls
            && prev_tls != new_tls
        {
            let old_host = derive_hostname(name, namespace, old_tls.key.as_deref());
            info!("Deregistering route {key} hostname: {old_host}");
            self.tls.remove(&old_host);
        }

        if let Some(tls) = new_tls {
            let host = derive_hostname(name, namespace, tls.key.as_deref());
            info!("Registering route {key} hostname: {host}");
            self.tls.insert(host, entry.spec.clone());
        }

        prev
    }

    fn remove(&mut self, key: &str) -> Option<MetadataAndSpec> {
        let (namespace, name) = parse_namespaced_name(key);

        let prev = self.routes.remove(key);
        if let Some(ref prev_entry) = prev
            && let Some(tls) = &prev_entry.spec.1.tls
        {
            let host = derive_hostname(name, namespace, tls.key.as_deref());
            info!("Deregistering route {key} hostname: {host}");
            self.tls.remove(&host);
        }

        prev
    }

    fn get_tls_route(&self, hostname: &str) -> Option<Arc<CTFRouteSpecPair>> {
        let clean_host = extract_sni_hostname(hostname);
        self.tls.get(clean_host).cloned()
    }

    fn get_route(&self, key: &str) -> Option<MetadataAndSpec> {
        self.routes.get(key).cloned()
    }

    pub fn unsynced_routes(&self) -> Vec<MetadataAndSpec> {
        self.routes
            .values()
            .filter(|v| v.generation > v.observed_generation)
            .cloned()
            .collect()
    }
}

pub const LOCK_POISONED_ERROR: &str = "RoutesStore lock poisoned";

pub struct RoutesStore {
    inner: RwLock<StoreInner>,
}

impl RoutesStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(StoreInner::default()),
        }
    }

    pub fn insert(&self, entry: MetadataAndSpec) -> Option<MetadataAndSpec> {
        let mut inner = self.inner.write().expect(LOCK_POISONED_ERROR);
        inner.insert(entry)
    }

    pub fn remove(&self, key: &str) -> Option<MetadataAndSpec> {
        let mut inner = self.inner.write().expect(LOCK_POISONED_ERROR);
        inner.remove(key)
    }

    pub fn get_tls_route(&self, hostname: &str) -> Option<Arc<CTFRouteSpecPair>> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.get_tls_route(hostname)
    }

    pub fn get_route(&self, key: &str) -> Option<MetadataAndSpec> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.get_route(key)
    }

    pub fn unsynced_routes(&self) -> Vec<MetadataAndSpec> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.unsynced_routes()
    }

    pub fn get_hostname(&self, key: &str) -> Option<String> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        let route = inner.get_route(key)?;
        let tls = route.spec.1.tls.as_ref()?;
        let (namespace, name) = parse_namespaced_name(key);
        Some(derive_hostname(name, namespace, tls.key.as_deref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{CTFRouteSpec, CTFRouteSpecTLS};

    #[test]
    fn test_routes_store_lifecycle() {
        let store = RoutesStore::new();

        let spec = CTFRouteSpec {
            backend: "backend-service:80".into(),
            tls: Some(CTFRouteSpecTLS {
                key: Some("web".to_string()),
            }),
            ..Default::default()
        };
        let namespaced_name = "default:test-chal".to_string();
        let pair = Arc::new((namespaced_name.clone(), spec));

        let entry = MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: pair.clone(),
        };

        // Insert
        let prev = store.insert(entry);
        assert!(prev.is_none());

        let host = derive_hostname("test-chal", "default", Some("web"));
        let tls_found = store.get_tls_route(&host);
        assert!(tls_found.is_some());
        assert_eq!(tls_found.unwrap().0, namespaced_name);

        let route_found = store.get_route(&namespaced_name);
        assert!(route_found.is_some());
        assert_eq!(route_found.unwrap().generation, Some(1));

        // Unsynced routes check
        let unsynced = store.unsynced_routes();
        assert_eq!(unsynced.len(), 1);
        assert_eq!(unsynced[0].spec.0, namespaced_name);

        // Remove
        let removed = store.remove(&namespaced_name);
        assert!(removed.is_some());
        assert!(store.get_tls_route(&host).is_none());
        assert!(store.get_route(&namespaced_name).is_none());
    }

    #[test]
    fn test_tls_tag_update_and_removal_lifecycle() {
        let store = RoutesStore::new();
        let key = "default:chal-web".to_string();

        let mut spec = CTFRouteSpec {
            backend: "service:80".into(),
            tls: Some(CTFRouteSpecTLS {
                key: Some("v1".to_string()),
            }),
            ..Default::default()
        };

        let host_v1 = derive_hostname("chal-web", "default", Some("v1"));

        // Initial insert with tag "v1"
        store.insert(MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: Arc::new((key.clone(), spec.clone())),
        });

        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().1.backend,
            "service:80"
        );
        assert_eq!(store.get_hostname(&key), Some(host_v1.clone()));

        // Update with same tag (v1), backend changed
        spec.backend = "service:8080".into();
        store.insert(MetadataAndSpec {
            generation: Some(2),
            observed_generation: Some(1),
            spec: Arc::new((key.clone(), spec.clone())),
        });

        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().1.backend,
            "service:8080"
        );

        // Update with new tag "v2" -> host_v1 should be deregistered, host_v2 registered
        let host_v2 = derive_hostname("chal-web", "default", Some("v2"));
        spec.tls = Some(CTFRouteSpecTLS {
            key: Some("v2".to_string()),
        });
        store.insert(MetadataAndSpec {
            generation: Some(3),
            observed_generation: Some(2),
            spec: Arc::new((key.clone(), spec.clone())),
        });

        assert!(store.get_tls_route(&host_v1).is_none());
        assert_eq!(
            store.get_tls_route(&host_v2).unwrap().1.backend,
            "service:8080"
        );
        assert_eq!(store.get_hostname(&key), Some(host_v2.clone()));

        // Update with TLS disabled (tls = None) -> host_v2 should be deregistered
        spec.tls = None;
        store.insert(MetadataAndSpec {
            generation: Some(4),
            observed_generation: Some(3),
            spec: Arc::new((key.clone(), spec.clone())),
        });

        assert!(store.get_tls_route(&host_v2).is_none());
        assert_eq!(store.get_hostname(&key), None);
    }

    #[test]
    fn test_generation_edge_cases_and_unsynced_filtering() {
        let store = RoutesStore::new();

        // Edge Case: None vs None -> not unsynced
        let key1 = "default:r1".to_string();
        store.insert(MetadataAndSpec {
            generation: None,
            observed_generation: None,
            spec: Arc::new((key1.clone(), CTFRouteSpec::default())),
        });

        // Edge Case: Some(1) vs None -> unsynced (Some(1) > None in Rust)
        let key2 = "default:r2".to_string();
        store.insert(MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: Arc::new((key2.clone(), CTFRouteSpec::default())),
        });

        // Edge Case: Some(2) vs Some(1) -> unsynced (generation > observed_generation)
        let key3 = "default:r3".to_string();
        store.insert(MetadataAndSpec {
            generation: Some(2),
            observed_generation: Some(1),
            spec: Arc::new((key3.clone(), CTFRouteSpec::default())),
        });

        // Edge Case: Some(3) vs Some(3) -> synced (generation == observed_generation)
        let key4 = "default:r4".to_string();
        store.insert(MetadataAndSpec {
            generation: Some(3),
            observed_generation: Some(3),
            spec: Arc::new((key4.clone(), CTFRouteSpec::default())),
        });

        // Edge Case: None vs Some(1) -> not unsynced (None > Some(1) is false)
        let key5 = "default:r5".to_string();
        store.insert(MetadataAndSpec {
            generation: None,
            observed_generation: Some(1),
            spec: Arc::new((key5.clone(), CTFRouteSpec::default())),
        });

        let unsynced = store.unsynced_routes();
        let unsynced_keys: Vec<String> = unsynced.into_iter().map(|m| m.spec.0.clone()).collect();

        assert_eq!(unsynced_keys.len(), 2);
        assert!(unsynced_keys.contains(&key2));
        assert!(unsynced_keys.contains(&key3));

        // Advance observed_generation for r3 to match generation -> r3 becomes synced
        store.insert(MetadataAndSpec {
            generation: Some(2),
            observed_generation: Some(2),
            spec: Arc::new((key3.clone(), CTFRouteSpec::default())),
        });

        let updated_unsynced = store.unsynced_routes();
        assert_eq!(updated_unsynced.len(), 1);
        assert_eq!(updated_unsynced[0].spec.0, key2);
    }

    #[test]
    fn test_sni_subdomain_extraction_and_nonexistent_routes() {
        let store = RoutesStore::new();

        // Non-existent route lookups
        assert!(store.get_route("nonexistent:key").is_none());
        assert!(store.get_tls_route("nonexistent.domain.com").is_none());
        assert!(store.get_hostname("nonexistent:key").is_none());
        assert!(store.remove("nonexistent:key").is_none());

        // Insert route with TLS
        let key = "prod:chal-sni".to_string();
        let spec = CTFRouteSpec {
            backend: "backend:443".into(),
            tls: Some(CTFRouteSpecTLS {
                key: Some("web".to_string()),
            }),
            ..Default::default()
        };
        let host = derive_hostname("chal-sni", "prod", Some("web"));

        store.insert(MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: Arc::new((key.clone(), spec)),
        });

        // Lookup with exact host prefix
        assert!(store.get_tls_route(&host).is_some());

        // Lookup with domain suffix attached (e.g. SNI: chal-sni-xxx.c.sk8.dog)
        let full_fqdn = format!("{host}.c.sk8.dog");
        assert!(store.get_tls_route(&full_fqdn).is_some());
    }

    #[test]
    fn test_tls_transition_none_to_some() {
        let store = RoutesStore::new();
        let key = "default:chal-none-to-some".to_string();

        // Initial insert with NO TLS (prev_tls = None)
        let mut spec = CTFRouteSpec {
            backend: "service:80".into(),
            tls: None,
            ..Default::default()
        };
        store.insert(MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: Arc::new((key.clone(), spec.clone())),
        });
        assert_eq!(store.get_hostname(&key), None);

        // Transition from None -> Some(tls)
        spec.tls = Some(CTFRouteSpecTLS {
            key: Some("web".to_string()),
        });
        store.insert(MetadataAndSpec {
            generation: Some(2),
            observed_generation: Some(1),
            spec: Arc::new((key.clone(), spec.clone())),
        });

        let host = derive_hostname("chal-none-to-some", "default", Some("web"));
        assert_eq!(store.get_hostname(&key), Some(host.clone()));
        assert!(store.get_tls_route(&host).is_some());
    }

    #[test]
    fn test_same_tls_re_registration_logging() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct BufWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for BufWriter {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = BufWriter(buf.clone());
        let _ = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::INFO)
            .try_init();

        let store = RoutesStore::new();
        let key = "default:chal-relog".to_string();

        let mut spec = CTFRouteSpec {
            backend: "service:80".into(),
            tls: Some(CTFRouteSpecTLS {
                key: Some("web".to_string()),
            }),
            ..Default::default()
        };

        // Initial insert
        store.insert(MetadataAndSpec {
            generation: Some(1),
            observed_generation: None,
            spec: Arc::new((key.clone(), spec.clone())),
        });

        // Clear log buffer and insert update with SAME TLS tag, updated backend
        buf.lock().unwrap().clear();
        spec.backend = "service:8080".into();
        store.insert(MetadataAndSpec {
            generation: Some(2),
            observed_generation: Some(1),
            spec: Arc::new((key.clone(), spec.clone())),
        });

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("Registering route default:chal-relog"),
            "Expected 'Registering route' log on same-TLS re-registration, but got: '{output}'"
        );
    }
}
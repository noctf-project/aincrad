use regex::Regex;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};

use tracing::info;

use crate::{
    crd::{CTFRouteSpec, CTFRouteStatus},
    crypto::hash::sha256,
};

const HOSTNAME_ID_LEN: usize = 14;
pub type CTFRouteStatusPair = (String, CTFRouteStatus);

fn sanitize_prefix(input: &str) -> String {
    static RE_INVALID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9-]+").unwrap());
    const MAX_PREFIX_LEN: usize = 63 - HOSTNAME_ID_LEN - 1; // 48

    let lowered = input.to_lowercase();
    let replaced = RE_INVALID.replace_all(&lowered, "-");

    let truncated = if replaced.len() > MAX_PREFIX_LEN {
        &replaced[..MAX_PREFIX_LEN]
    } else {
        &replaced
    };

    let trimmed = truncated.trim_matches('-');

    if trimmed.is_empty() {
        "chal".to_string()
    } else {
        trimmed.to_string()
    }
}

fn derive_hostname(prefix: &str, uid: &str) -> String {
    let clean_prefix = sanitize_prefix(prefix);
    let input = format!("aincrad:route:tls:{}", uid);
    let hash = sha256(input.as_bytes());
    let mut id = base32::encode(base32::Alphabet::Crockford, &hash).to_lowercase();
    id.truncate(HOSTNAME_ID_LEN);
    format!("{}-{}", clean_prefix, id)
}

fn extract_sni_hostname(sni: &str) -> &str {
    sni.split('.').next().unwrap_or(sni)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataAndSpec {
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub generation: i64,
    pub observed_generation: Option<i64>,
    pub spec: CTFRouteSpec,
}

impl MetadataAndSpec {
    pub fn namespaced_name(&self) -> String {
        format!("{}:{}", self.namespace, self.name)
    }
}

#[derive(Default)]
struct StoreInner {
    routes: HashMap<String, Arc<MetadataAndSpec>>,
    tls: HashMap<String, Arc<MetadataAndSpec>>,
}

impl StoreInner {
    fn insert(&mut self, entry: Arc<MetadataAndSpec>) -> Option<Arc<MetadataAndSpec>> {
        let key = entry.namespaced_name();

        let prev = self.routes.insert(key.clone(), entry.clone());

        let prev_tls = prev.as_ref().and_then(|p| p.spec.tls.as_ref());
        let new_tls = entry.spec.tls.as_ref();

        if let Some(old_tls) = prev_tls
            && prev_tls != new_tls
            && let Some(prev_entry) = &prev
        {
            let old_prefix = old_tls
                .prefix
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&prev_entry.name);
            let old_host = derive_hostname(old_prefix, &prev_entry.uid);
            info!("Deregistering route {key} hostname: {old_host}");
            self.tls.remove(&old_host);
        }

        if let Some(tls) = new_tls {
            let prefix = tls
                .prefix
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&entry.name);
            let host = derive_hostname(prefix, &entry.uid);
            info!("Registering route {key} hostname: {host}");
            self.tls.insert(host, entry.clone());
        }

        prev
    }

    fn remove(&mut self, key: &str) -> Option<Arc<MetadataAndSpec>> {
        let prev = self.routes.remove(key);
        if let Some(ref prev_entry) = prev
            && let Some(tls) = &prev_entry.spec.tls
        {
            let prefix = tls
                .prefix
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&prev_entry.name);
            let host = derive_hostname(prefix, &prev_entry.uid);
            info!("Deregistering route {key} hostname: {host}");
            self.tls.remove(&host);
        }

        prev
    }

    fn get_tls_route(&self, hostname: &str) -> Option<Arc<MetadataAndSpec>> {
        let clean_host = extract_sni_hostname(hostname);
        self.tls.get(clean_host).cloned()
    }

    fn get_route(&self, key: &str) -> Option<Arc<MetadataAndSpec>> {
        self.routes.get(key).cloned()
    }

    pub fn unsynced_routes(&self) -> Vec<Arc<MetadataAndSpec>> {
        self.routes
            .values()
            .filter(|v| v.observed_generation.is_none_or(|obs| v.generation > obs))
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

    pub fn insert(&self, entry: Arc<MetadataAndSpec>) -> Option<Arc<MetadataAndSpec>> {
        let mut inner = self.inner.write().expect(LOCK_POISONED_ERROR);
        inner.insert(entry)
    }

    pub fn remove(&self, key: &str) -> Option<Arc<MetadataAndSpec>> {
        let mut inner = self.inner.write().expect(LOCK_POISONED_ERROR);
        inner.remove(key)
    }

    pub fn get_tls_route(&self, hostname: &str) -> Option<Arc<MetadataAndSpec>> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.get_tls_route(hostname)
    }

    pub fn get_route(&self, key: &str) -> Option<Arc<MetadataAndSpec>> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.get_route(key)
    }

    pub fn unsynced_routes(&self) -> Vec<Arc<MetadataAndSpec>> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        inner.unsynced_routes()
    }

    pub fn get_hostname(&self, key: &str) -> Option<String> {
        let inner = self.inner.read().expect(LOCK_POISONED_ERROR);
        let route = inner.get_route(key)?;
        let tls = route.spec.tls.as_ref()?;
        let prefix = tls
            .prefix
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&route.name);
        Some(derive_hostname(prefix, &route.uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{CTFRouteBackend, CTFRouteSpec, CTFRouteSpecTLS};

    #[test]
    fn test_routes_store_lifecycle() {
        let store = RoutesStore::new();

        let spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                host: "backend-service".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
            }),
            ..Default::default()
        };
        let namespaced_name = "default:test-chal".to_string();

        let entry = Arc::new(MetadataAndSpec {
            name: "test-chal".into(),
            namespace: "default".into(),
            uid: "uid-test".into(),
            generation: 1,
            observed_generation: None,
            spec,
        });

        // Insert
        let prev = store.insert(entry);
        assert!(prev.is_none());

        let host = derive_hostname("web", "uid-test");
        let tls_found = store.get_tls_route(&host);
        assert!(tls_found.is_some());
        assert_eq!(tls_found.unwrap().namespaced_name(), namespaced_name);

        let route_found = store.get_route(&namespaced_name);
        assert!(route_found.is_some());
        assert_eq!(route_found.unwrap().generation, 1);

        // Unsynced routes check
        let unsynced = store.unsynced_routes();
        assert_eq!(unsynced.len(), 1);
        assert_eq!(unsynced[0].namespaced_name(), namespaced_name);

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
            backend: CTFRouteBackend {
                host: "service".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("v1".to_string()),
            }),
            ..Default::default()
        };

        let host_v1 = derive_hostname("v1", "uid-1");

        // Initial insert with tag "v1"
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-web".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 1,
            observed_generation: None,
            spec: spec.clone(),
        }));

        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().spec.backend,
            CTFRouteBackend {
                host: "service".into(),
                port: 80,
            }
        );
        assert_eq!(store.get_hostname(&key), Some(host_v1.clone()));

        // Update with same tag (v1), backend changed
        spec.backend = CTFRouteBackend {
            host: "service".into(),
            port: 8080,
        };
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-web".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 2,
            observed_generation: Some(1),
            spec: spec.clone(),
        }));

        assert_eq!(
            store.get_tls_route(&host_v1).unwrap().spec.backend,
            CTFRouteBackend {
                host: "service".into(),
                port: 8080,
            }
        );

        // Update with new tag "v2" -> host_v1 should be deregistered, host_v2 registered
        let host_v2 = derive_hostname("v2", "uid-1");
        spec.tls = Some(CTFRouteSpecTLS {
            prefix: Some("v2".to_string()),
        });
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-web".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 3,
            observed_generation: Some(2),
            spec: spec.clone(),
        }));

        assert!(store.get_tls_route(&host_v1).is_none());
        assert_eq!(
            store.get_tls_route(&host_v2).unwrap().spec.backend,
            CTFRouteBackend {
                host: "service".into(),
                port: 8080,
            }
        );
        assert_eq!(store.get_hostname(&key), Some(host_v2.clone()));

        // Update with TLS disabled (tls = None) -> host_v2 should be deregistered
        spec.tls = None;
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-web".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 4,
            observed_generation: Some(3),
            spec: spec.clone(),
        }));

        assert!(store.get_tls_route(&host_v2).is_none());
        assert_eq!(store.get_hostname(&key), None);
    }

    #[test]
    fn test_generation_edge_cases_and_unsynced_filtering() {
        let store = RoutesStore::new();

        // Edge Case: 1 vs None -> unsynced
        let key2 = "default:r2".to_string();
        store.insert(Arc::new(MetadataAndSpec {
            name: "r2".into(),
            namespace: "default".into(),
            uid: "uid-r2".into(),
            generation: 1,
            observed_generation: None,
            spec: CTFRouteSpec::default(),
        }));

        // Edge Case: 2 vs Some(1) -> unsynced (generation > observed_generation)
        let key3 = "default:r3".to_string();
        store.insert(Arc::new(MetadataAndSpec {
            name: "r3".into(),
            namespace: "default".into(),
            uid: "uid-r3".into(),
            generation: 2,
            observed_generation: Some(1),
            spec: CTFRouteSpec::default(),
        }));

        // Edge Case: 3 vs Some(3) -> synced (generation == observed_generation)
        let _key4 = "default:r4".to_string();
        store.insert(Arc::new(MetadataAndSpec {
            name: "r4".into(),
            namespace: "default".into(),
            uid: "uid-r4".into(),
            generation: 3,
            observed_generation: Some(3),
            spec: CTFRouteSpec::default(),
        }));

        let unsynced = store.unsynced_routes();
        let unsynced_keys: Vec<String> =
            unsynced.into_iter().map(|m| m.namespaced_name()).collect();

        assert_eq!(unsynced_keys.len(), 2);
        assert!(unsynced_keys.contains(&key2));
        assert!(unsynced_keys.contains(&key3));

        // Advance observed_generation for r3 to match generation -> r3 becomes synced
        store.insert(Arc::new(MetadataAndSpec {
            name: "r3".into(),
            namespace: "default".into(),
            uid: "uid-r3".into(),
            generation: 2,
            observed_generation: Some(2),
            spec: CTFRouteSpec::default(),
        }));

        let updated_unsynced = store.unsynced_routes();
        assert_eq!(updated_unsynced.len(), 1);
        assert_eq!(updated_unsynced[0].namespaced_name(), key2);
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
        let _key = "prod:chal-sni".to_string();
        let spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                host: "backend".into(),
                port: 443,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
            }),
            ..Default::default()
        };
        let host = derive_hostname("web", "uid-sni");

        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-sni".into(),
            namespace: "prod".into(),
            uid: "uid-sni".into(),
            generation: 1,
            observed_generation: None,
            spec,
        }));

        // Lookup with exact host prefix
        assert!(store.get_tls_route(&host).is_some());

        // Lookup with domain suffix attached (e.g. SNI: chal-sni-xxx.c.noctf.dev)
        let full_fqdn = format!("{host}.c.noctf.dev");
        assert!(store.get_tls_route(&full_fqdn).is_some());
    }

    #[test]
    fn test_tls_transition_none_to_some() {
        let store = RoutesStore::new();
        let key = "default:chal-none-to-some".to_string();

        // Initial insert with NO TLS (prev_tls = None)
        let mut spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                host: "service".into(),
                port: 80,
            },
            tls: None,
            ..Default::default()
        };
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-none-to-some".into(),
            namespace: "default".into(),
            uid: "uid-none-to-some".into(),
            generation: 1,
            observed_generation: None,
            spec: spec.clone(),
        }));
        assert_eq!(store.get_hostname(&key), None);

        // Transition from None -> Some(tls)
        spec.tls = Some(CTFRouteSpecTLS {
            prefix: Some("web".to_string()),
        });
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-none-to-some".into(),
            namespace: "default".into(),
            uid: "uid-none-to-some".into(),
            generation: 2,
            observed_generation: Some(1),
            spec: spec.clone(),
        }));

        let host = derive_hostname("web", "uid-none-to-some");
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
        let _key = "default:chal-relog".to_string();

        let mut spec = CTFRouteSpec {
            backend: CTFRouteBackend {
                host: "service".into(),
                port: 80,
            },
            tls: Some(CTFRouteSpecTLS {
                prefix: Some("web".to_string()),
            }),
            ..Default::default()
        };

        // Initial insert
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-relog".into(),
            namespace: "default".into(),
            uid: "uid-relog".into(),
            generation: 1,
            observed_generation: None,
            spec: spec.clone(),
        }));

        // Clear log buffer and insert update with SAME TLS tag, updated backend
        buf.lock().unwrap().clear();
        spec.backend = CTFRouteBackend {
            host: "service".into(),
            port: 8080,
        };
        store.insert(Arc::new(MetadataAndSpec {
            name: "chal-relog".into(),
            namespace: "default".into(),
            uid: "uid-relog".into(),
            generation: 2,
            observed_generation: Some(1),
            spec: spec.clone(),
        }));

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("Registering route default:chal-relog"),
            "Expected 'Registering route' log on same-TLS re-registration, but got: '{output}'"
        );
    }

    #[test]
    fn test_derive_hostname_prefix_and_default() {
        let host1 = derive_hostname("my-chal", "uid-1");
        let host2 = derive_hostname("web", "uid-1");
        let host3 = derive_hostname("my-chal", "uid-2");

        assert!(host1.starts_with("my-chal-"));
        assert!(host2.starts_with("web-"));
        assert!(host3.starts_with("my-chal-"));

        assert_ne!(host1, host2);
        assert_ne!(host1, host3);
        assert_eq!(host1.len(), "my-chal-".len() + HOSTNAME_ID_LEN);
        assert_eq!(host2.len(), "web-".len() + HOSTNAME_ID_LEN);
    }

    #[test]
    fn test_extract_sni_hostname() {
        assert_eq!(
            extract_sni_hostname("my-chal-12345.c.noctf.dev"),
            "my-chal-12345"
        );
        assert_eq!(extract_sni_hostname("my-chal-12345"), "my-chal-12345");
        assert_eq!(extract_sni_hostname(""), "");
    }

    #[test]
    fn test_derive_hostname_collision_prevention() {
        let h1 = derive_hostname("web-chal1-service1-team1", "uid-a");
        let h2 = derive_hostname("web-chal1-service2-team1", "uid-b");
        assert!(h1.starts_with("web-chal1-service1-team1-"));
        assert!(h2.starts_with("web-chal1-service2-team1-"));
        assert_ne!(h1, h2);

        let h_metadata = derive_hostname("web", "uid-c");
        let h_key = derive_hostname("chal-web", "uid-c");
        assert_ne!(h_metadata, h_key);
    }

    #[test]
    fn test_sanitize_prefix() {
        assert_eq!(sanitize_prefix("web"), "web");
        assert_eq!(sanitize_prefix("Web_Chal_1.2"), "web-chal-1-2");
        assert_eq!(sanitize_prefix("---foo---bar---"), "foo---bar");
        assert_eq!(sanitize_prefix(""), "chal");
        assert_eq!(sanitize_prefix("___"), "chal");

        // Truncation at 48 characters (63 - 14 - 1)
        let long_input = "a".repeat(100);
        let sanitized = sanitize_prefix(&long_input);
        assert_eq!(sanitized.len(), 48);
        assert_eq!(sanitized, "a".repeat(48));

        // Truncating trailing hyphens after truncation
        let trailing_dash = format!("{}-something", "a".repeat(48));
        assert_eq!(sanitize_prefix(&trailing_dash), "a".repeat(48));
    }
}

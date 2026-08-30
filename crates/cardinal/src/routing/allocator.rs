use std::sync::{Arc, LazyLock};

use k8s_common::crd::{
    CTFInstanceStatusEndpoint, EndpointTarget, ProxyRouteKey, RouteSpec, RouteTarget,
};
use regex::Regex;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cache::ResourceKey;

use super::ports_store::{PortError, PortsStore};

const HOSTNAME_ID_LEN: usize = 14;
const MAX_PREFIX_LEN: usize = 56 - HOSTNAME_ID_LEN - 1;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RouteError {
    #[error(transparent)]
    Port(#[from] PortError),
    #[error("route must specify either tcp or tls configuration")]
    MissingTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatedRoute {
    pub resource_key: ResourceKey,
    pub proxy_key: ProxyRouteKey,
    pub endpoint: CTFInstanceStatusEndpoint,
}

#[derive(Clone)]
pub struct RouteAllocator {
    ports: Arc<PortsStore>,
    route_seed: String,
    hostname_suffix: String,
    tls_port: u16,
}

impl RouteAllocator {
    pub fn new(
        ports: Arc<PortsStore>,
        route_seed: impl Into<String>,
        hostname_suffix: impl Into<String>,
        tls_port: u16,
    ) -> Self {
        Self {
            ports,
            route_seed: route_seed.into(),
            hostname_suffix: hostname_suffix.into(),
            tls_port,
        }
    }

    pub fn ports(&self) -> &Arc<PortsStore> {
        &self.ports
    }

    /// Allocates an endpoint and proxy route key given a RouteKey and CTFRouteSpec.
    pub fn allocate(
        &self,
        key: &ResourceKey,
        spec: &RouteSpec,
    ) -> Result<AllocatedRoute, RouteError> {
        match spec.target() {
            Some(RouteTarget::Tcp(tcp)) => {
                let port = self.ports.allocate(key, tcp.port.unwrap_or(0))?;
                let endpoint = CTFInstanceStatusEndpoint {
                    name: key.resource.clone(),
                    type_: "tcp".to_string(),
                    target: EndpointTarget {
                        host: self.hostname_suffix.clone(),
                        port,
                    },
                };
                Ok(AllocatedRoute {
                    resource_key: key.clone(),
                    proxy_key: ProxyRouteKey::Tcp(port),
                    endpoint,
                })
            }
            Some(RouteTarget::Tls(tls)) => {
                let hostname = self.derive_hostname(key, tls.prefix.as_deref());
                let fqdn = self.format_tls_host(&hostname);
                let endpoint = CTFInstanceStatusEndpoint {
                    name: key.resource.clone(),
                    type_: "tls".to_string(),
                    target: EndpointTarget {
                        host: fqdn,
                        port: self.tls_port,
                    },
                };
                Ok(AllocatedRoute {
                    resource_key: key.clone(),
                    proxy_key: ProxyRouteKey::Route(hostname),
                    endpoint,
                })
            }
            None => Err(RouteError::MissingTarget),
        }
    }

    /// Releases any port allocated for the given RouteKey.
    pub fn release(&self, key: &ResourceKey) -> Option<u16> {
        self.ports.release(key)
    }

    /// Releases all ports allocated to any route belonging to the given namespace and instance.
    pub fn release_instance(&self, namespace: &str, instance: &str) -> Vec<u16> {
        self.ports.release_instance(namespace, instance)
    }

    /// Releases the port only if it is currently mapped to this exact port for the given RouteKey.
    pub fn release_if_bound(&self, key: &ResourceKey, port: u16) -> bool {
        self.ports.release_if_bound(key, port)
    }

    /// Clears all active port allocations.
    pub fn clear(&self) {
        self.ports.clear();
    }

    /// Synchronizes an authoritative port assignment observed from external resources.
    pub fn sync(&self, key: &ResourceKey, port: u16) {
        self.ports.sync(key, port);
    }

    /// Synchronizes multiple port assignments from an initial list or batch.
    pub fn sync_all(&self, routes: impl IntoIterator<Item = (ResourceKey, u16)>) {
        for (key, port) in routes {
            self.ports.sync(&key, port);
        }
    }

    /// Derives the base hostname label (`{prefix}-{hash14}`).
    pub fn derive_hostname(&self, key: &ResourceKey, prefix: Option<&str>) -> String {
        let raw_prefix = prefix.filter(|s| !s.is_empty()).unwrap_or(&key.resource);
        let clean_prefix = sanitize_prefix(raw_prefix);

        let seed_tag = format!("aincrad:route:v1:{}:{}", self.route_seed, key);
        let mut hasher = Sha256::new();
        hasher.update(seed_tag.as_bytes());
        let hash = hasher.finalize();

        let mut id = base32::encode(base32::Alphabet::Crockford, &hash).to_lowercase();
        id.truncate(HOSTNAME_ID_LEN);
        format!("{clean_prefix}-{id}")
    }

    /// Formats a base hostname into an FQDN with `hostname_suffix`.
    pub fn format_tls_host(&self, base: &str) -> String {
        if self.hostname_suffix.is_empty() {
            base.to_string()
        } else if self.hostname_suffix.starts_with('.') {
            format!("{base}{}", self.hostname_suffix)
        } else {
            format!("{base}.{}", self.hostname_suffix)
        }
    }
}

fn sanitize_prefix(input: &str) -> String {
    static RE_INVALID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9-]+").unwrap());

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

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::PortRange;
    use k8s_common::crd::{RouteBackend, RouteSpec, RouteSpecTCP};

    fn make_allocator() -> RouteAllocator {
        let ports = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30010),
        ));
        RouteAllocator::new(ports, "link-start", "c.sk8.dog", 4433)
    }

    #[test]
    fn test_allocate_tcp_auto_and_fixed() {
        let allocator = make_allocator();
        let key_auto = ResourceKey::new("default", "chal-1", "pwn");
        let spec_auto = RouteSpec {
            backend: RouteBackend {
                service: "pwn".into(),
                port: 1337,
            },
            tcp: Some(RouteSpecTCP { port: Some(0) }),
            ..Default::default()
        };

        let res_auto = allocator.allocate(&key_auto, &spec_auto).unwrap();
        assert_eq!(res_auto.resource_key, key_auto);
        assert_eq!(res_auto.endpoint.name, "pwn");
        assert_eq!(res_auto.endpoint.type_, "tcp");
        assert_eq!(res_auto.endpoint.target.host, "c.sk8.dog");
        assert!((30000..=30010).contains(&res_auto.endpoint.target.port));

        match res_auto.proxy_key {
            ProxyRouteKey::Tcp(port) => assert_eq!(port, res_auto.endpoint.target.port),
            _ => panic!("expected ProxyRouteKey::Tcp"),
        }

        let key_fixed = ResourceKey::new("default", "chal-1", "admin");
        let spec_fixed = RouteSpec {
            backend: k8s_common::crd::RouteBackend {
                service: "admin".into(),
                port: 8080,
            },
            tcp: Some(k8s_common::crd::RouteSpecTCP { port: Some(20001) }),
            ..Default::default()
        };

        let res_fixed = allocator.allocate(&key_fixed, &spec_fixed).unwrap();
        assert_eq!(res_fixed.endpoint.target.port, 20001);
        assert_eq!(res_fixed.proxy_key, ProxyRouteKey::Tcp(20001));

        // Release frees the port
        assert_eq!(allocator.release(&key_fixed), Some(20001));
    }

    #[test]
    fn test_allocate_tls_endpoint() {
        let allocator = make_allocator();
        let key = ResourceKey::new("default", "chal-1", "web");
        let spec = RouteSpec {
            backend: k8s_common::crd::RouteBackend {
                service: "web".into(),
                port: 80,
            },
            tls: Some(k8s_common::crd::RouteSpecTLS {
                prefix: Some("whoami".into()),
            }),
            ..Default::default()
        };

        let res = allocator.allocate(&key, &spec).unwrap();
        assert_eq!(res.resource_key, key);
        assert_eq!(res.endpoint.name, "web");
        assert_eq!(res.endpoint.type_, "tls");
        assert_eq!(res.endpoint.target.port, 4433);
        assert!(res.endpoint.target.host.starts_with("whoami-"));
        assert!(res.endpoint.target.host.ends_with(".c.sk8.dog"));

        match res.proxy_key {
            ProxyRouteKey::Route(hostname) => {
                assert!(hostname.starts_with("whoami-"));
                assert_eq!(res.endpoint.target.host, format!("{hostname}.c.sk8.dog"));
            }
            _ => panic!("expected ProxyRouteKey::Route"),
        }
    }

    #[test]
    fn test_allocate_missing_target() {
        let allocator = make_allocator();
        let key = ResourceKey::new("default", "chal-1", "empty");
        let spec = RouteSpec {
            backend: k8s_common::crd::RouteBackend {
                service: "empty".into(),
                port: 80,
            },
            ..Default::default()
        };

        assert_eq!(
            allocator.allocate(&key, &spec),
            Err(RouteError::MissingTarget)
        );
    }

    #[test]
    fn test_sanitize_prefix() {
        assert_eq!(sanitize_prefix("web"), "web");
        assert_eq!(sanitize_prefix("Web_Chal_1.2"), "web-chal-1-2");
        assert_eq!(sanitize_prefix("---foo---bar---"), "foo---bar");
        assert_eq!(sanitize_prefix(""), "chal");
        assert_eq!(sanitize_prefix("___"), "chal");

        let long_input = "a".repeat(100);
        let sanitized = sanitize_prefix(&long_input);
        assert_eq!(sanitized.len(), MAX_PREFIX_LEN);
        assert_eq!(sanitized, "a".repeat(MAX_PREFIX_LEN));
    }
}

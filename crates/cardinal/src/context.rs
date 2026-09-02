use std::collections::BTreeMap;
use std::sync::Arc;

use kube::Client;

use crate::btreemap;
use crate::cache::Caches;
use crate::routing::PortMap;

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub caches: Caches,
    pub port_map: Option<Arc<PortMap>>,
    pub route_seed: String,
    pub hostname_suffix: String,
    pub tls_port: u16,
    pub system_namespace: String,
    pub cluster_domain: String,
    pub image_aliases: BTreeMap<String, String>,
}

impl Context {
    pub fn to_config(&self) -> BTreeMap<String, String> {
        btreemap! {
            "hostname_suffix" => self.hostname_suffix.to_string(),
            "cluster_domain" => self.cluster_domain.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use kube::Client;

    use crate::{Context, cache::Caches, routing::PortMap};
    impl Context {
        pub fn new_stub(client: Client) -> Self {
            let system_ns = client.default_namespace().to_string();
            Self {
                client,
                caches: Caches::default(),
                port_map: None,
                route_seed: "seed".to_string(),
                hostname_suffix: "c.sk8.dog".to_string(),
                tls_port: 4433,
                system_namespace: system_ns,
                cluster_domain: "cluster.local".to_string(),
                image_aliases: BTreeMap::new(),
            }
        }

        pub fn new_stub_with_port_map(
            client: Client,
            port_map: Arc<PortMap>,
            route_seed: impl Into<String>,
            hostname_suffix: impl Into<String>,
            tls_port: u16,
            system_namespace: impl Into<String>,
            cluster_domain: impl Into<String>,
            image_aliases: BTreeMap<String, String>,
        ) -> Self {
            Self {
                client,
                caches: Caches::default(),
                port_map: Some(port_map),
                route_seed: route_seed.into(),
                hostname_suffix: hostname_suffix.into(),
                tls_port,
                system_namespace: system_namespace.into(),
                cluster_domain: cluster_domain.into(),
                image_aliases,
            }
        }
    }
}

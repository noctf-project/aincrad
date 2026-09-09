use std::collections::BTreeMap;
use std::sync::Arc;

use kube::Client;

use crate::btreemap;
use crate::cache::Caches;
use crate::config::CardinalConfig;
use crate::routing::PortMap;

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub caches: Caches,
    pub port_map: Option<Arc<PortMap>>,
    pub config: CardinalConfig,
}

impl Context {
    pub fn route_seed(&self) -> &str {
        &self.config.routing.seed
    }

    pub fn hostname_suffix(&self) -> &str {
        &self.config.routing.hostname_suffix
    }

    pub fn tls_port(&self) -> u16 {
        self.config.routing.tls_port
    }

    pub fn system_namespace(&self) -> &str {
        self.config
            .system_namespace
            .as_deref()
            .unwrap_or_else(|| self.client.default_namespace())
    }

    pub fn image_aliases(&self) -> &BTreeMap<String, String> {
        &self.config.image_aliases
    }

    pub fn load_balancer_ip(&self) -> Option<&str> {
        self.config.routing.load_balancer_ip.as_deref()
    }

    pub fn to_config(&self) -> BTreeMap<String, String> {
        btreemap! {
            "hostname_suffix" => self.hostname_suffix().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use kube::Client;

    use crate::config::{CardinalConfig, RoutingConfig};
    use crate::{Context, cache::Caches, routing::PortMap};

    impl Context {
        pub fn new_stub(client: Client) -> Self {
            let system_ns = client.default_namespace().to_string();
            let config = CardinalConfig {
                system_namespace: Some(system_ns),
                routing: RoutingConfig {
                    hostname_suffix: "c.sk8.dog".to_string(),
                    tls_port: 4433,
                    seed: "seed".to_string(),
                    load_balancer_ip: None,
                },
                ..Default::default()
            };
            Self {
                client,
                caches: Caches::default(),
                port_map: None,
                config,
            }
        }

        pub fn new_stub_with_port_map(
            client: Client,
            port_map: Arc<PortMap>,
            route_seed: impl Into<String>,
            hostname_suffix: impl Into<String>,
            tls_port: u16,
            system_namespace: impl Into<String>,
            image_aliases: BTreeMap<String, String>,
        ) -> Self {
            let config = CardinalConfig {
                system_namespace: Some(system_namespace.into()),
                routing: RoutingConfig {
                    hostname_suffix: hostname_suffix.into(),
                    tls_port,
                    seed: route_seed.into(),
                    load_balancer_ip: None,
                },
                image_aliases,
                ..Default::default()
            };
            Self {
                client,
                caches: Caches::default(),
                port_map: Some(port_map),
                config,
            }
        }
    }
}

use std::collections::BTreeMap;
use std::sync::Arc;

use kube::Client;

use crate::cache::{InstanceCache, TemplateCache};
use crate::routing::RouteAllocator;

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub template_cache: Option<TemplateCache>,
    pub instance_cache: Option<InstanceCache>,
    pub route_allocator: Option<Arc<RouteAllocator>>,
    pub system_namespace: String,
    pub cluster_domain: String,
    pub image_aliases: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use kube::Client;

    use crate::{Context, cache::TemplateCache, routing::RouteAllocator};
    impl Context {
        pub fn new_stub(client: Client) -> Self {
            let system_ns = client.default_namespace().to_string();
            Self {
                client,
                template_cache: None,
                instance_cache: None,
                route_allocator: None,
                system_namespace: system_ns,
                cluster_domain: "cluster.local".to_string(),
                image_aliases: BTreeMap::new(),
            }
        }

        pub fn new_stub_with_allocator(
            client: Client,
            allocator: Arc<RouteAllocator>,
            system_namespace: impl Into<String>,
            cluster_domain: impl Into<String>,
            image_aliases: BTreeMap<String, String>,
        ) -> Self {
            let template_cache = TemplateCache::new();
            Self {
                client,
                template_cache: Some(template_cache),
                instance_cache: None,
                route_allocator: Some(allocator),
                system_namespace: system_namespace.into(),
                cluster_domain: cluster_domain.into(),
                image_aliases,
            }
        }
    }
}

use std::sync::Arc;

use k8s_common::crd::CTFTemplate;
use kube::Client;
use kube::runtime::reflector::Store;

use crate::cache::{InstanceCache, TemplateCache};
use crate::routing::RouteAllocator;

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub template_store: Option<Store<CTFTemplate>>,
    pub template_cache: Option<TemplateCache>,
    pub instance_cache: Option<InstanceCache>,
    pub route_allocator: Option<Arc<RouteAllocator>>,
    pub system_namespace: String,
    pub cluster_domain: String,
}

impl Context {
    /// Creates a Context with client and default configuration.
    pub fn new(client: Client) -> Self {
        let system_ns = client.default_namespace().to_string();
        Self {
            client,
            template_store: None,
            template_cache: None,
            instance_cache: None,
            route_allocator: None,
            system_namespace: system_ns,
            cluster_domain: "cluster.local".to_string(),
        }
    }

    /// Creates a Context with in-memory template store and route allocator.
    pub fn with_allocator(
        client: Client,
        template_store: Store<CTFTemplate>,
        allocator: Arc<RouteAllocator>,
        system_namespace: impl Into<String>,
        cluster_domain: impl Into<String>,
    ) -> Self {
        let template_cache = TemplateCache::new(template_store.clone());
        Self {
            client,
            template_store: Some(template_store),
            template_cache: Some(template_cache),
            instance_cache: None,
            route_allocator: Some(allocator),
            system_namespace: system_namespace.into(),
            cluster_domain: cluster_domain.into(),
        }
    }

    /// Backward-compatible constructor for template store only.
    pub fn with_template_store(client: Client, template_store: Store<CTFTemplate>) -> Self {
        let template_cache = TemplateCache::new(template_store.clone());
        let system_ns = client.default_namespace().to_string();
        Self {
            client,
            template_store: Some(template_store),
            template_cache: Some(template_cache),
            instance_cache: None,
            route_allocator: None,
            system_namespace: system_ns,
            cluster_domain: "cluster.local".to_string(),
        }
    }
}

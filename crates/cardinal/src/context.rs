use k8s_common::crd::{CTFRoute, CTFTemplate};
use kube::Client;
use kube::runtime::reflector::Store;

use crate::cache::{InstanceCache, RouteCache, TemplateCache};

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub template_store: Option<Store<CTFTemplate>>,
    pub template_cache: Option<TemplateCache>,
    pub instance_cache: Option<InstanceCache>,
    pub route_store: Option<Store<CTFRoute>>,
    pub route_cache: Option<RouteCache>,
}

impl Context {
    /// Creates a Context with client only.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            template_store: None,
            template_cache: None,
            instance_cache: None,
            route_store: None,
            route_cache: None,
        }
    }

    /// Creates a Context with in-memory template and route store caches.
    pub fn with_stores(
        client: Client,
        template_store: Store<CTFTemplate>,
        route_store: Store<CTFRoute>,
    ) -> Self {
        let template_cache = TemplateCache::new(template_store.clone());
        let route_cache = RouteCache::new(route_store.clone());
        Self {
            client,
            template_store: Some(template_store),
            template_cache: Some(template_cache),
            instance_cache: None,
            route_store: Some(route_store),
            route_cache: Some(route_cache),
        }
    }

    /// Backward-compatible constructor for template store only.
    pub fn with_template_store(client: Client, template_store: Store<CTFTemplate>) -> Self {
        let template_cache = TemplateCache::new(template_store.clone());
        Self {
            client,
            template_store: Some(template_store),
            template_cache: Some(template_cache),
            instance_cache: None,
            route_store: None,
            route_cache: None,
        }
    }
}

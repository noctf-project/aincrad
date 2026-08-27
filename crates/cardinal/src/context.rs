use k8s_common::crd::{CTFRoute, CTFTemplate};
use kube::Client;
use kube::runtime::reflector::Store;

use crate::cache::{RouteCache, TemplateCache};

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub template_store: Option<Store<CTFTemplate>>,
    pub route_store: Option<Store<CTFRoute>>,
    pub route_cache: Option<RouteCache>,
    pub template_cache: TemplateCache,
}

impl Context {
    /// Creates a Context with client only (stores will fall back to API calls).
    pub fn new(client: Client) -> Self {
        Self {
            client,
            template_store: None,
            route_store: None,
            route_cache: None,
            template_cache: TemplateCache::new(),
        }
    }

    /// Creates a Context with in-memory template and route store caches.
    pub fn with_stores(
        client: Client,
        template_store: Store<CTFTemplate>,
        route_store: Store<CTFRoute>,
    ) -> Self {
        let route_cache = RouteCache::new(route_store.clone());
        Self {
            client,
            template_store: Some(template_store),
            route_store: Some(route_store),
            route_cache: Some(route_cache),
            template_cache: TemplateCache::new(),
        }
    }

    /// Backward-compatible constructor for template store only.
    pub fn with_template_store(client: Client, template_store: Store<CTFTemplate>) -> Self {
        Self {
            client,
            template_store: Some(template_store),
            route_store: None,
            route_cache: None,
            template_cache: TemplateCache::new(),
        }
    }
}

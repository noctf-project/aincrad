use k8s_common::crd::CTFTemplate;
use kube::Client;
use kube::runtime::reflector::Store;

use crate::reconcilers::template::TemplateCache;

/// Contextual data shared across controller reconciliation passes.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub template_store: Option<Store<CTFTemplate>>,
    pub template_cache: TemplateCache,
}

impl Context {
    /// Creates a Context with client only (template store will fall back to API GET calls).
    pub fn new(client: Client) -> Self {
        Self {
            client,
            template_store: None,
            template_cache: TemplateCache::new(),
        }
    }

    /// Creates a Context with an in-memory template store cache.
    pub fn with_template_store(client: Client, template_store: Store<CTFTemplate>) -> Self {
        Self {
            client,
            template_store: Some(template_store),
            template_cache: TemplateCache::new(),
        }
    }
}

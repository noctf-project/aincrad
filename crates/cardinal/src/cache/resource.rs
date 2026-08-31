use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::Service;
use k8s_common::crd::CTFProxyRoute;
use kube::Resource;
use kube::runtime::watcher::Event;

use crate::utils::labels::{INSTANCE_LABEL, NAMESPACE_LABEL, RESOURCE_LABEL};

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceKey {
    pub namespace: String,
    pub instance: String,
    pub resource: String,
}

impl ResourceKey {
    pub fn new(
        namespace: impl Into<String>,
        instance: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            instance: instance.into(),
            resource: resource.into(),
        }
    }
}

impl std::fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.namespace, self.instance, self.resource)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    resource: ResourceKey,
    name: String,
}

impl CacheKey {
    fn new(resource: ResourceKey, name: impl Into<String>) -> Self {
        Self {
            resource,
            name: name.into(),
        }
    }
}

pub trait ResourceProjection {
    type Value: Clone;

    fn key(resource: &Self) -> ResourceKey;
    fn name(resource: &Self) -> String;
    fn value(resource: &Self) -> Self::Value;
}

#[derive(Debug, Clone)]
pub struct ResourceEntry<V> {
    pub key: ResourceKey,
    pub name: String,
    pub value: V,
}

struct Inner<T: ResourceProjection> {
    index: BTreeMap<CacheKey, T::Value>,
}

pub struct ResourceCache<T: ResourceProjection> {
    inner: Arc<Mutex<Inner<T>>>,
}

impl<T: ResourceProjection> ResourceCache<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle(&self, event: &Event<T>) {
        match event {
            Event::Apply(resource) | Event::InitApply(resource) => {
                let key = CacheKey::new(T::key(resource), T::name(resource));
                let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                lock.index.insert(key, T::value(resource));
            }
            Event::Delete(resource) => {
                let key = CacheKey::new(T::key(resource), T::name(resource));
                let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                lock.index.remove(&key);
            }
            Event::Init => self.clear(),
            Event::InitDone => {}
        }
    }

    fn clear(&self) {
        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.clear();
    }

    /// Returns every resource owned by `(namespace, instance)`.
    pub fn for_instance(&self, namespace: &str, instance: &str) -> Vec<ResourceEntry<T::Value>> {
        let start = CacheKey::new(ResourceKey::new(namespace, instance, ""), "");
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index
            .range(start..)
            .take_while(|(k, _)| {
                k.resource.namespace == namespace && k.resource.instance == instance
            })
            .map(|(k, v)| ResourceEntry {
                key: k.resource.clone(),
                name: k.name.clone(),
                value: v.clone(),
            })
            .collect()
    }

    /// Returns the concrete object names for every resource owned by
    /// `(namespace, instance)`.
    pub fn names(&self, namespace: &str, instance: &str) -> Vec<String> {
        self.for_instance(namespace, instance)
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    /// Returns the concrete object names of every resource in the cache,
    /// across all namespaces and instances. Used for the startup prune sweep.
    pub fn all_names(&self) -> Vec<String> {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.keys().map(|k| k.name.clone()).collect()
    }

    pub fn len(&self) -> usize {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: ResourceProjection> Default for ResourceCache<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                index: BTreeMap::new(),
            })),
        }
    }
}

impl<T: ResourceProjection> Clone for ResourceCache<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn meta_key<K: Resource<DynamicType = ()>>(
    resource: &K,
    disambig_label: &str,
) -> (ResourceKey, String) {
    let namespace = resource
        .meta()
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_string();
    let instance = resource
        .meta()
        .labels
        .as_ref()
        .and_then(|l| l.get(INSTANCE_LABEL))
        .cloned()
        .unwrap_or_else(|| resource.meta().name.as_deref().unwrap_or("unknown").to_string());
    let disambig = resource
        .meta()
        .labels
        .as_ref()
        .and_then(|l| l.get(disambig_label))
        .cloned()
        .unwrap_or_default();
    let name = resource.meta().name.as_deref().unwrap_or_default().to_string();
    (ResourceKey::new(namespace, instance, disambig), name)
}

impl ResourceProjection for Service {
    type Value = ();

    fn key(resource: &Self) -> ResourceKey {
        meta_key(resource, RESOURCE_LABEL).0
    }

    fn name(resource: &Self) -> String {
        meta_key(resource, RESOURCE_LABEL).1
    }

    fn value(_resource: &Self) -> Self::Value {}
}

impl ResourceProjection for CTFProxyRoute {
    type Value = ();

    fn key(resource: &Self) -> ResourceKey {
        let ns = resource
            .meta()
            .labels
            .as_ref()
            .and_then(|l| l.get(NAMESPACE_LABEL))
            .cloned()
            .unwrap_or_default();
        let instance = resource
            .meta()
            .labels
            .as_ref()
            .and_then(|l| l.get(INSTANCE_LABEL))
            .cloned()
            .unwrap_or_default();
        let disambig = resource
            .meta()
            .labels
            .as_ref()
            .and_then(|l| l.get(RESOURCE_LABEL))
            .cloned()
            .unwrap_or_default();
        ResourceKey::new(ns, instance, disambig)
    }

    fn name(resource: &Self) -> String {
        resource.meta().name.as_deref().unwrap_or_default().to_string()
    }

    fn value(_resource: &Self) -> Self::Value {}
}

impl ResourceProjection for ReplicaSet {
    type Value = k8s_openapi::api::apps::v1::ReplicaSetStatus;

    fn key(resource: &Self) -> ResourceKey {
        meta_key(resource, RESOURCE_LABEL).0
    }

    fn name(resource: &Self) -> String {
        meta_key(resource, RESOURCE_LABEL).1
    }

    fn value(resource: &Self) -> Self::Value {
        resource.status.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct TestResource {
        namespace: String,
        instance: String,
        disambig: String,
        name: String,
        value: String,
    }

    impl TestResource {
        fn new(instance: &str, disambig: &str, name: &str, value: &str) -> Self {
            Self {
                namespace: "default".into(),
                instance: instance.into(),
                disambig: disambig.into(),
                name: name.into(),
                value: value.into(),
            }
        }
    }

    impl ResourceProjection for TestResource {
        type Value = String;

        fn key(resource: &Self) -> ResourceKey {
            ResourceKey::new(&resource.namespace, &resource.instance, &resource.disambig)
        }

        fn name(resource: &Self) -> String {
            resource.name.clone()
        }

        fn value(resource: &Self) -> Self::Value {
            resource.value.clone()
        }
    }

    #[test]
    fn test_handle_apply_delete() {
        let cache = ResourceCache::<TestResource>::new();
        assert!(cache.is_empty());

        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "web", "chal-1-web-abc", "v1",
        )));
        assert_eq!(cache.len(), 1);

        // Object name reallocated, same stable key
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "web", "chal-1-web-def", "v2",
        )));
        assert_eq!(
            cache.len(),
            2,
            "a reallocated object name must not overwrite the previous entry"
        );
        assert_eq!(
            cache.names("default", "chal-1"),
            vec!["chal-1-web-abc".to_string(), "chal-1-web-def".to_string()]
        );

        cache.handle(&Event::Delete(TestResource::new(
            "chal-1", "web", "chal-1-web-def", "v2",
        )));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_handle_init_clears() {
        let cache = ResourceCache::<TestResource>::new();
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "web", "chal-1-web-abc", "v1",
        )));
        cache.handle(&Event::Init);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_for_instance_groups_by_namespace_and_instance() {
        let cache = ResourceCache::<TestResource>::new();
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "web", "chal-1-web-a", "web",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "pwn", "chal-1-pwn-a", "pwn",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-2", "web", "chal-2-web-a", "web-other",
        )));

        let mine = cache.for_instance("default", "chal-1");
        assert_eq!(mine.len(), 2);
    }

    #[test]
    fn test_all_names_across_instances() {
        let cache = ResourceCache::<TestResource>::new();
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "web", "p30001", "web",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1", "pwn", "p30002", "pwn",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-2", "web", "rwhoami", "web-other",
        )));

        let mut names = cache.all_names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "p30001".to_string(),
                "p30002".to_string(),
                "rwhoami".to_string()
            ]
        );
    }
}
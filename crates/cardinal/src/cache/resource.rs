use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kube::runtime::watcher::Event;

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

struct Inner<T> {
    index: BTreeMap<ResourceKey, Arc<T>>,
}

/// A generic in-memory index of child resources, keyed by
/// `(namespace, instance, resource)`.
///
/// The `BTreeMap` key ordering enables cheap prefix scans over everything
/// belonging to a single `CTFInstance`.
pub struct ResourceCache<T> {
    inner: Arc<Mutex<Inner<T>>>,
}

impl<T: Clone> ResourceCache<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a watcher `Event` to the cache entry addressed by `key`.
    /// `Apply`/`InitApply` upsert, `Delete` removes, `Init` clears the whole
    /// cache, and `InitDone` is a no-op.
    pub fn handle(&self, key: ResourceKey, event: &Event<T>) {
        match event {
            Event::Apply(resource) | Event::InitApply(resource) => {
                let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                lock.index.insert(key, Arc::new(resource.clone()));
            }
            Event::Delete(_) => {
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

    pub fn get(&self, key: &ResourceKey) -> Option<Arc<T>> {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.get(key).cloned()
    }

    /// Returns every resource owned by `(namespace, instance)`.
    pub fn for_instance(&self, namespace: &str, instance: &str) -> Vec<Arc<T>> {
        let start = ResourceKey::new(namespace, instance, "");
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index
            .range(start..)
            .take_while(|(k, _)| k.namespace == namespace && k.instance == instance)
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for ResourceCache<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                index: BTreeMap::new(),
            })),
        }
    }
}

impl<T> Clone for ResourceCache<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(resource: &str) -> ResourceKey {
        ResourceKey::new("team-1", "chal-1", resource)
    }

    #[test]
    fn test_handle_apply_get_delete() {
        let cache = ResourceCache::new();
        let k = key("chal-1-web");
        assert!(cache.get(&k).is_none());

        cache.handle(k.clone(), &Event::Apply(42));
        assert_eq!(*cache.get(&k).unwrap(), 42);

        // Re-apply overwrites
        cache.handle(k.clone(), &Event::Apply(43));
        assert_eq!(*cache.get(&k).unwrap(), 43);

        cache.handle(k.clone(), &Event::Delete(43));
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn test_handle_init_clears() {
        let cache = ResourceCache::new();
        let k = key("chal-1-web");
        cache.handle(k.clone(), &Event::Apply(42));
        assert_eq!(cache.len(), 1);

        cache.handle(k.clone(), &Event::Init);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_for_instance_prefix_scan() {
        let cache = ResourceCache::new();
        cache.handle(key("chal-1-web"), &Event::Apply("web"));
        cache.handle(key("chal-1-db"), &Event::Apply("db"));
        cache.handle(
            ResourceKey::new("team-2", "chal-1", "chal-1-web"),
            &Event::Apply("web-other"),
        );
        cache.handle(
            ResourceKey::new("team-1", "chal-2", "chal-1-x"),
            &Event::Apply("x"),
        );

        let items = cache.for_instance("team-1", "chal-1");
        assert_eq!(items.len(), 2);
    }
}

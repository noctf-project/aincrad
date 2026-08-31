use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use futures::{Stream, StreamExt};
use k8s_common::crd::CTFProxyRoute;
use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::runtime::watcher::{self, Config, Event, watcher};
use kube::runtime::WatchStreamExt;
use kube::{Api, Resource};
use serde::de::DeserializeOwned;
use tokio::sync::watch;

use crate::cache::ReadyCache;
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

pub trait ResourceProjection: Send + Sync + 'static {
    type Value: Clone + Send + Sync + 'static;

    fn key(resource: &Self) -> ResourceKey;
    fn name(resource: &Self) -> String;
    fn meta(resource: &Self) -> ObjectMeta;
    fn value(resource: &Self) -> Self::Value;
}

#[derive(Debug, Clone)]
pub struct CachedItem<V> {
    pub meta: ObjectMeta,
    pub value: V,
}

#[derive(Debug, Clone)]
pub struct ResourceEntry<V> {
    pub key: ResourceKey,
    pub name: String,
    pub item: Arc<CachedItem<V>>,
}

impl<V> std::ops::Deref for ResourceEntry<V> {
    type Target = CachedItem<V>;

    fn deref(&self) -> &Self::Target {
        &self.item
    }
}

struct Inner<T: ResourceProjection> {
    index: BTreeMap<CacheKey, Arc<CachedItem<T::Value>>>,
}

pub struct ResourceCache<T: ResourceProjection> {
    inner: Arc<Mutex<Inner<T>>>,
    ready: watch::Sender<bool>,
    ready_rx: watch::Receiver<bool>,
}

impl<T: ResourceProjection> ResourceCache<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a labeled, filtered watcher stream that feeds this cache from
    /// the cluster. The stream only follows objects carrying `INSTANCE_LABEL`.k
    /// The cache is marked ready when the watcher completes its initial sync.
    ///
    /// `observe` runs on every raw watcher event before coalescing, letting
    /// callers react to `Apply`/`Delete` transitions while they are still
    /// distinguishable.
    pub fn watcher_stream(
        &self,
        api: Api<T>,
        observe: impl Fn(&Event<T>) + Send + 'static,
    ) -> impl Stream<Item = Result<T, watcher::Error>> + Send + 'static
    where
        T: Resource + Clone + DeserializeOwned + Debug + Send + 'static,
        T::DynamicType: Default + Eq + Hash + Debug,
    {
        let cache = self.clone();
        watcher(api, Config::default().labels(INSTANCE_LABEL))
            .default_backoff()
            .inspect(move |res| {
                if let Ok(event) = res {
                    observe(event);
                    match event {
                        Event::Init => cache.mark_unready(),
                        Event::InitDone => cache.mark_ready(),
                        _ => {}
                    }
                    cache.handle(event);
                }
            })
            .touched_objects()
    }

    /// Marks the cache as having completed an initial sync.
    pub fn mark_ready(&self) {
        let _ = self.ready.send(true);
    }

    /// Marks the cache as beginning (or restarting) an initial sync.
    pub fn mark_unready(&self) {
        let _ = self.ready.send(false);
    }

    pub fn handle(&self, event: &Event<T>) {
        match event {
            Event::Apply(resource) | Event::InitApply(resource) => {
                let key = CacheKey::new(T::key(resource), T::name(resource));
                let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());

                let incoming_meta = T::meta(resource);
                if let Some(existing) = lock.index.get(&key)
                    && !should_update(&existing.meta, &incoming_meta)
                {
                    return;
                }

                lock.index.insert(
                    key,
                    Arc::new(CachedItem {
                        meta: incoming_meta,
                        value: T::value(resource),
                    }),
                );
            }
            Event::Delete(resource) => {
                let key = CacheKey::new(T::key(resource), T::name(resource));
                let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());

                let incoming_meta = T::meta(resource);
                if let Some(existing) = lock.index.get(&key)
                    && let (Some(incoming_uid), Some(existing_uid)) =
                        (incoming_meta.uid.as_deref(), existing.meta.uid.as_deref())
                    && incoming_uid != existing_uid
                {
                    return;
                }

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
            .map(|(k, item)| ResourceEntry {
                key: k.resource.clone(),
                name: k.name.clone(),
                item: Arc::clone(item),
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

    /// Returns every entry in the cache, across all namespaces and instances.
    pub fn all_entries(&self) -> Vec<ResourceEntry<T::Value>> {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index
            .iter()
            .map(|(k, item)| ResourceEntry {
                key: k.resource.clone(),
                name: k.name.clone(),
                item: Arc::clone(item),
            })
            .collect()
    }

    /// Eagerly removes an entry matching `(namespace, instance, name)`.
    pub fn remove_entry(&self, namespace: &str, instance: &str, name: &str) {
        let start = CacheKey::new(ResourceKey::new(namespace, instance, ""), "");
        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let to_remove: Vec<CacheKey> = lock
            .index
            .range(start..)
            .take_while(|(k, _)| {
                k.resource.namespace == namespace && k.resource.instance == instance
            })
            .filter(|(k, _)| k.name == name)
            .map(|(k, _)| k.clone())
            .collect();

        for key in to_remove {
            lock.index.remove(&key);
        }
    }

    /// Eagerly removes any entry matching `name`.
    pub fn remove_by_name(&self, name: &str) {
        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let to_remove: Vec<CacheKey> = lock
            .index
            .keys()
            .filter(|k| k.name == name)
            .cloned()
            .collect();

        for key in to_remove {
            lock.index.remove(&key);
        }
    }

    pub fn len(&self) -> usize {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Determines whether an incoming object update is newer than the cached metadata.
fn should_update(existing: &ObjectMeta, incoming: &ObjectMeta) -> bool {
    let incoming_uid = incoming.uid.as_deref();
    let existing_uid = existing.uid.as_deref();

    // When UIDs differ, the resource was recreated under the same name.
    if let (Some(inc_uid), Some(cur_uid)) = (incoming_uid, existing_uid)
        && inc_uid != cur_uid
    {
        if let (Some(inc_time), Some(cur_time)) =
            (&incoming.creation_timestamp, &existing.creation_timestamp)
        {
            if inc_time < cur_time {
                return false;
            }
            if inc_time > cur_time {
                return true;
            }
        }

        if let (Some(inc_rv), Some(cur_rv)) = (parse_rv(incoming), parse_rv(existing)) {
            return inc_rv >= cur_rv;
        }

        return true;
    }

    // Same incarnation (or UID absent): check spec generation first.
    let incoming_gen = incoming.generation.unwrap_or(0);
    let existing_gen = existing.generation.unwrap_or(0);

    if incoming_gen < existing_gen {
        return false;
    }

    if incoming_gen == existing_gen
        && let (Some(inc_rv), Some(cur_rv)) = (parse_rv(incoming), parse_rv(existing)) {
            return inc_rv >= cur_rv;
        }

    true
}

fn parse_rv(meta: &ObjectMeta) -> Option<u64> {
    meta.resource_version.as_deref()?.parse::<u64>().ok()
}

impl<T: ResourceProjection> Default for ResourceCache<T> {
    fn default() -> Self {
        let (ready, ready_rx) = watch::channel(false);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                index: BTreeMap::new(),
            })),
            ready,
            ready_rx,
        }
    }
}

impl<T: ResourceProjection> ReadyCache for ResourceCache<T> {
    fn is_ready(&self) -> bool {
        *self.ready_rx.borrow()
    }

    fn watch(&self) -> watch::Receiver<bool> {
        self.ready.subscribe()
    }
}

impl<T: ResourceProjection> Clone for ResourceCache<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            ready: self.ready.clone(),
            ready_rx: self.ready_rx.clone(),
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
        .unwrap_or_else(|| {
            resource
                .meta()
                .name
                .as_deref()
                .unwrap_or("unknown")
                .to_string()
        });
    let disambig = resource
        .meta()
        .labels
        .as_ref()
        .and_then(|l| l.get(disambig_label))
        .cloned()
        .unwrap_or_default();
    let name = resource
        .meta()
        .name
        .as_deref()
        .unwrap_or_default()
        .to_string();
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

    fn meta(resource: &Self) -> ObjectMeta {
        resource.meta().clone()
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
        resource
            .meta()
            .name
            .as_deref()
            .unwrap_or_default()
            .to_string()
    }

    fn meta(resource: &Self) -> ObjectMeta {
        resource.meta().clone()
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

    fn meta(resource: &Self) -> ObjectMeta {
        resource.meta().clone()
    }

    fn value(resource: &Self) -> Self::Value {
        resource.status.clone().unwrap_or_default()
    }
}

impl ResourceProjection for NetworkPolicy {
    type Value = ();

    fn key(resource: &Self) -> ResourceKey {
        meta_key(resource, RESOURCE_LABEL).0
    }

    fn name(resource: &Self) -> String {
        meta_key(resource, RESOURCE_LABEL).1
    }

    fn meta(resource: &Self) -> ObjectMeta {
        resource.meta().clone()
    }

    fn value(_resource: &Self) -> Self::Value {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::CTFProxyRouteSpec;
    use k8s_openapi::api::apps::v1::{ReplicaSetSpec, ReplicaSetStatus};
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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

        fn meta(resource: &Self) -> ObjectMeta {
            ObjectMeta {
                name: Some(resource.name.clone()),
                namespace: Some(resource.namespace.clone()),
                ..Default::default()
            }
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
            "chal-1",
            "web",
            "chal-1-web-abc",
            "v1",
        )));
        assert_eq!(cache.len(), 1);

        // Object name reallocated, same stable key
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1",
            "web",
            "chal-1-web-def",
            "v2",
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
            "chal-1",
            "web",
            "chal-1-web-def",
            "v2",
        )));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_handle_init_clears() {
        let cache = ResourceCache::<TestResource>::new();
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1",
            "web",
            "chal-1-web-abc",
            "v1",
        )));
        cache.handle(&Event::Init);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_for_instance_groups_by_namespace_and_instance() {
        let cache = ResourceCache::<TestResource>::new();
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1",
            "web",
            "chal-1-web-a",
            "web",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-1",
            "pwn",
            "chal-1-pwn-a",
            "pwn",
        )));
        cache.handle(&Event::Apply(TestResource::new(
            "chal-2",
            "web",
            "chal-2-web-a",
            "web-other",
        )));

        let mine = cache.for_instance("default", "chal-1");
        assert_eq!(mine.len(), 2);
    }

    fn svc(name: &str, ns: &str, instance: &str, resource: &str) -> Service {
        let mut labels = std::collections::BTreeMap::new();
        if !instance.is_empty() {
            labels.insert(INSTANCE_LABEL.to_string(), instance.to_string());
        }
        if !resource.is_empty() {
            labels.insert(RESOURCE_LABEL.to_string(), resource.to_string());
        }
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(ServiceSpec::default()),
            ..Default::default()
        }
    }

    fn rs(
        name: &str,
        ns: &str,
        instance: &str,
        resource: &str,
        replicas: i32,
        ready: i32,
    ) -> ReplicaSet {
        ReplicaSet {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => instance,
                    RESOURCE_LABEL => resource,
                }),
                ..Default::default()
            },
            spec: Some(ReplicaSetSpec {
                replicas: Some(replicas),
                ..Default::default()
            }),
            status: Some(ReplicaSetStatus {
                replicas,
                ready_replicas: Some(ready),
                observed_generation: Some(7),
                ..Default::default()
            }),
        }
    }

    fn proxy_route(
        name: &str,
        system_ns: &str,
        instance_ns: &str,
        instance: &str,
        resource: &str,
    ) -> CTFProxyRoute {
        CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(system_ns.to_string()),
                labels: Some(crate::btreemap! {
                    NAMESPACE_LABEL => instance_ns,
                    INSTANCE_LABEL => instance,
                    RESOURCE_LABEL => resource,
                }),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".to_string(),
                policy: Default::default(),
            },
        }
    }

    #[test]
    fn test_service_projection_extracts_key_and_name() {
        let svc = svc("chal-1-web", "team-1", "chal-1", "web");

        assert_eq!(
            Service::key(&svc),
            ResourceKey::new("team-1", "chal-1", "web")
        );
        assert_eq!(Service::name(&svc), "chal-1-web");
        assert_eq!(Service::value(&svc), ());
    }

    #[test]
    fn test_service_projection_reuses_metadata_namespace() {
        let svc = svc("chal-1-web", "team-9", "chal-1", "web");
        assert_eq!(Service::key(&svc).namespace, "team-9");
    }

    #[test]
    fn test_service_projection_falls_back_when_labels_missing() {
        let bare = Service {
            metadata: ObjectMeta {
                name: Some("bare-svc".to_string()),
                namespace: None,
                ..Default::default()
            },
            spec: Some(ServiceSpec::default()),
            ..Default::default()
        };

        let key = Service::key(&bare);
        assert_eq!(
            key.namespace, "default",
            "missing namespace defaults to default"
        );
        assert_eq!(
            key.instance, "bare-svc",
            "missing INSTANCE_LABEL falls back to the object name"
        );
        assert_eq!(
            key.resource, "",
            "missing RESOURCE_LABEL is an empty disambig"
        );
        assert_eq!(Service::name(&bare), "bare-svc");
    }

    #[test]
    fn test_service_projection_ignores_foreign_labels() {
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("chal-1-web".to_string()),
                namespace: Some("team-1".to_string()),
                labels: Some(crate::btreemap! {
                    "app".to_string() => "web",
                    INSTANCE_LABEL => "chal-1",
                    // deliberately no RESOURCE_LABEL
                }),
                ..Default::default()
            },
            spec: Some(ServiceSpec::default()),
            ..Default::default()
        };

        let key = Service::key(&svc);
        assert_eq!(key, ResourceKey::new("team-1", "chal-1", ""));
    }

    #[test]
    fn test_replicaset_projection_stores_status_snapshot() {
        let rs = rs("chal-1-web-8f3xq", "team-1", "chal-1", "web", 2, 1);

        assert_eq!(
            ReplicaSet::key(&rs),
            ResourceKey::new("team-1", "chal-1", "web")
        );
        assert_eq!(ReplicaSet::name(&rs), "chal-1-web-8f3xq");

        let status = ReplicaSet::value(&rs);
        assert_eq!(status.replicas, 2);
        assert_eq!(status.ready_replicas, Some(1));
        assert_eq!(status.observed_generation, Some(7));
    }

    #[test]
    fn test_replicaset_projection_defaults_to_empty_status() {
        let rs = ReplicaSet {
            metadata: ObjectMeta {
                name: Some("chal-1-web".to_string()),
                namespace: Some("team-1".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ReplicaSetSpec::default()),
            status: None,
        };

        assert_eq!(
            ReplicaSet::value(&rs),
            ReplicaSetStatus::default(),
            "absent status projects to a default (all-zero) snapshot"
        );
    }

    #[test]
    fn test_proxy_route_projection_keys_by_instance_namespace_not_system_ns() {
        // The route physically lives in the system namespace, but the cache
        // must group it under the owning instance's namespace.
        let route = proxy_route("p30001", "aincrad-system", "team-1", "chal-1", "web");

        let key = CTFProxyRoute::key(&route);
        assert_eq!(key, ResourceKey::new("team-1", "chal-1", "web"));
        assert_ne!(
            key.namespace, "aincrad-system",
            "the system namespace must not leak into the cache key"
        );
        assert_eq!(CTFProxyRoute::name(&route), "p30001");
        assert_eq!(CTFProxyRoute::value(&route), ());
    }

    #[test]
    fn test_proxy_route_projection_name_is_the_cluster_object_name() {
        assert_eq!(
            CTFProxyRoute::name(&proxy_route("rwhoami", "sys", "team-1", "chal-1", "main")),
            "rwhoami"
        );
        assert_eq!(
            CTFProxyRoute::name(&proxy_route("p30002", "sys", "team-2", "chal-2", "pwn")),
            "p30002"
        );
    }

    #[test]
    fn test_proxy_route_projection_defaults_labels_to_empty() {
        let route = proxy_route("p30001", "sys", "", "", "");
        assert_eq!(
            CTFProxyRoute::key(&route),
            ResourceKey::new("", "", ""),
            "unlabeled proxy routes fall back to empty key dimensions"
        );
    }

    /// ----- Cache integration with concrete projections -----------------

    #[test]
    fn test_service_cache_tracks_reallocated_names() {
        let cache = ResourceCache::<Service>::new();

        cache.handle(&Event::Apply(svc(
            "chal-1-web-old",
            "team-1",
            "chal-1",
            "web",
        )));
        cache.handle(&Event::Apply(svc(
            "chal-1-web-new",
            "team-1",
            "chal-1",
            "web",
        )));

        assert_eq!(cache.len(), 2, "both names must coexist until pruned");
        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.resource, "web");
    }

    #[test]
    fn test_service_cache_for_instance_boundaries() {
        let cache = ResourceCache::<Service>::new();
        cache.handle(&Event::Apply(svc("chal-1-web", "team-1", "chal-1", "web")));
        cache.handle(&Event::Apply(svc("chal-1-db", "team-1", "chal-1", "db")));
        cache.handle(&Event::Apply(svc("chal-2-web", "team-1", "chal-2", "web")));
        cache.handle(&Event::Apply(svc("citrus-web", "team-1", "chal", "web")));

        assert_eq!(cache.for_instance("team-1", "chal-1").len(), 2);
        assert_eq!(
            cache.for_instance("team-1", "chal").len(),
            1,
            "prefix 'chal' must not bleed into 'chal-1'"
        );
        assert_eq!(cache.for_instance("team-1", "chal-2").len(), 1);
    }

    #[test]
    fn test_proxy_route_cache_groups_across_system_namespace() {
        let cache = ResourceCache::<CTFProxyRoute>::new();
        cache.handle(&Event::Apply(proxy_route(
            "p30001",
            "aincrad-system",
            "team-1",
            "chal-1",
            "web",
        )));
        cache.handle(&Event::Apply(proxy_route(
            "p30002",
            "aincrad-system",
            "team-1",
            "chal-1",
            "pwn",
        )));
        cache.handle(&Event::Apply(proxy_route(
            "rwhoami",
            "aincrad-system",
            "team-2",
            "chal-2",
            "main",
        )));

        let mine = cache.for_instance("team-1", "chal-1");
        assert_eq!(mine.len(), 2);
        assert_eq!(cache.for_instance("team-2", "chal-2").len(), 1);

        let mut names = cache.names("team-1", "chal-1");
        names.sort();
        assert_eq!(names, vec!["p30001".to_string(), "p30002".to_string()]);
    }

    #[test]
    fn test_replicaset_cache_with_status_values() {
        let cache = ResourceCache::<ReplicaSet>::new();
        cache.handle(&Event::Apply(rs("a-abc", "team-1", "chal-1", "web", 3, 3)));
        cache.handle(&Event::Apply(rs("a-def", "team-1", "chal-1", "web", 3, 1)));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(e.value.replicas, 3, "each RS snapshot carries its status");
        }
        assert!(entries.iter().any(|e| e.value.ready_replicas == Some(3)));
        assert!(entries.iter().any(|e| e.value.ready_replicas == Some(1)));
    }

    /// ----- ReadyCache behavior ----------------------------------------

    #[test]
    fn test_ready_cache_transitions() {
        let cache = ResourceCache::<TestResource>::new();
        assert!(!cache.is_ready(), "fresh cache is not ready");

        let rx = cache.watch();
        assert!(!*rx.borrow(), "receiver agrees the cache is not ready");

        cache.mark_ready();
        assert!(cache.is_ready());
        assert!(*rx.borrow(), "existing receiver sees the transition");

        cache.mark_unready();
        assert!(!cache.is_ready(), "cache can be dragged back to unready");
    }

    #[test]
    fn test_ready_cache_late_subscriber_sees_ready() {
        let cache = ResourceCache::<TestResource>::new();
        cache.mark_ready();

        assert!(
            *cache.watch().borrow(),
            "a watch created after ready reports true immediately"
        );
    }

    #[test]
    fn test_ready_cache_clones_share_state() {
        let cache = ResourceCache::<TestResource>::new();
        let clone = cache.clone();

        cache.mark_ready();
        assert!(
            clone.is_ready(),
            "cloned handles observe the same readiness state"
        );
    }

    #[test]
    fn test_resource_cache_preserves_object_meta() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut replica_set = rs("chal-1-web-8f3xq", "team-1", "chal-1", "web", 2, 2);
        replica_set.metadata.generation = Some(42);
        replica_set.metadata.uid = Some("uid-12345".to_string());
        replica_set.metadata.resource_version = Some("999".to_string());

        cache.handle(&Event::Apply(replica_set));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.generation, Some(42));
        assert_eq!(entries[0].meta.uid.as_deref(), Some("uid-12345"));
        assert_eq!(entries[0].meta.resource_version.as_deref(), Some("999"));
        assert_eq!(
            entries[0]
                .meta
                .labels
                .as_ref()
                .unwrap()
                .get(INSTANCE_LABEL)
                .map(|s| s.as_str()),
            Some("chal-1")
        );
        assert_eq!(entries[0].name, "chal-1-web-8f3xq");
    }

    #[test]
    fn test_handle_ignores_stale_generation() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_gen2 = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_gen2.metadata.generation = Some(2);
        cache.handle(&Event::Apply(rs_gen2));

        let mut rs_gen1 = rs("chal-1-web", "team-1", "chal-1", "web", 1, 1);
        rs_gen1.metadata.generation = Some(1);
        cache.handle(&Event::Apply(rs_gen1));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.generation, Some(2));
        assert_eq!(entries[0].value.replicas, 2);
    }

    #[test]
    fn test_handle_ignores_stale_resource_version_same_generation() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_v2 = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_v2.metadata.generation = Some(1);
        rs_v2.metadata.resource_version = Some("200".to_string());
        cache.handle(&Event::Apply(rs_v2));

        let mut rs_v1 = rs("chal-1-web", "team-1", "chal-1", "web", 2, 0);
        rs_v1.metadata.generation = Some(1);
        rs_v1.metadata.resource_version = Some("100".to_string());
        cache.handle(&Event::Apply(rs_v1));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.resource_version.as_deref(), Some("200"));
        assert_eq!(entries[0].value.ready_replicas, Some(2));
    }

    #[test]
    fn test_handle_accepts_newer_resource_version_same_generation() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_v1 = rs("chal-1-web", "team-1", "chal-1", "web", 2, 0);
        rs_v1.metadata.generation = Some(1);
        rs_v1.metadata.resource_version = Some("100".to_string());
        cache.handle(&Event::Apply(rs_v1));

        let mut rs_v2 = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_v2.metadata.generation = Some(1);
        rs_v2.metadata.resource_version = Some("101".to_string());
        cache.handle(&Event::Apply(rs_v2));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.resource_version.as_deref(), Some("101"));
        assert_eq!(entries[0].value.ready_replicas, Some(2));
    }

    #[test]
    fn test_handle_delete_ignores_mismatched_uid() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_new = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_new.metadata.uid = Some("uid-new".to_string());
        cache.handle(&Event::Apply(rs_new));

        let mut rs_old = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_old.metadata.uid = Some("uid-old".to_string());
        cache.handle(&Event::Delete(rs_old));

        assert_eq!(
            cache.len(),
            1,
            "mismatched UID delete must not remove the newer object"
        );
    }

    #[test]
    fn test_handle_delete_removes_matching_uid() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_obj = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_obj.metadata.uid = Some("uid-123".to_string());
        cache.handle(&Event::Apply(rs_obj.clone()));
        assert_eq!(cache.len(), 1);

        cache.handle(&Event::Delete(rs_obj));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_handle_apply_accepts_recreated_object_with_new_uid() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_old = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_old.metadata.uid = Some("uid-old".to_string());
        rs_old.metadata.generation = Some(5);
        rs_old.metadata.resource_version = Some("100".to_string());
        cache.handle(&Event::Apply(rs_old));

        // Recreated object starts at generation 1 with new UID and higher RV
        let mut rs_new = rs("chal-1-web", "team-1", "chal-1", "web", 1, 1);
        rs_new.metadata.uid = Some("uid-new".to_string());
        rs_new.metadata.generation = Some(1);
        rs_new.metadata.resource_version = Some("105".to_string());
        cache.handle(&Event::Apply(rs_new));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.uid.as_deref(), Some("uid-new"));
        assert_eq!(entries[0].meta.generation, Some(1));
    }

    #[test]
    fn test_handle_apply_ignores_stale_old_uid() {
        let cache = ResourceCache::<ReplicaSet>::new();
        let mut rs_new = rs("chal-1-web", "team-1", "chal-1", "web", 1, 1);
        rs_new.metadata.uid = Some("uid-new".to_string());
        rs_new.metadata.generation = Some(1);
        rs_new.metadata.resource_version = Some("105".to_string());
        cache.handle(&Event::Apply(rs_new));

        // Stale event from older deleted incarnation arrives late
        let mut rs_old = rs("chal-1-web", "team-1", "chal-1", "web", 2, 2);
        rs_old.metadata.uid = Some("uid-old".to_string());
        rs_old.metadata.generation = Some(5);
        rs_old.metadata.resource_version = Some("100".to_string());
        cache.handle(&Event::Apply(rs_old));

        let entries = cache.for_instance("team-1", "chal-1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.uid.as_deref(), Some("uid-new"));
    }
}

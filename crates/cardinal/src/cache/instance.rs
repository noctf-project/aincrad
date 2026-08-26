use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use k8s_common::crd::{CTFInstance, CTFTemplate};
use kube::runtime::reflector::{ObjectRef, Store};

/// Encapsulates `Store<CTFInstance>` alongside an in-memory `BTreeMap` index
/// mapping key `"{namespace}:{template_name}:{instance_name}"` to `ObjectRef<CTFInstance>`.
#[derive(Clone)]
pub struct InstanceCache {
    store: Store<CTFInstance>,
    index: Arc<Mutex<BTreeMap<String, ObjectRef<CTFInstance>>>>,
}

impl InstanceCache {
    pub fn new(store: Store<CTFInstance>) -> Self {
        Self {
            store,
            index: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn store(&self) -> &Store<CTFInstance> {
        &self.store
    }

    pub fn make_key(namespace: &str, template: &str, instance: &str) -> String {
        format!("{namespace}:{template}:{instance}")
    }

    pub fn make_prefix(namespace: &str, template: &str) -> String {
        format!("{namespace}:{template}:")
    }

    /// Updates the instance index for a CTFInstance applied/created event.
    pub fn update(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let key = Self::make_key(ns, &instance.spec.template, name);

        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        if instance.spec.sync && instance.metadata.deletion_timestamp.is_none() {
            lock.insert(key, ObjectRef::from_obj(instance));
        } else {
            lock.remove(&key);
        }
    }

    /// Removes an instance from the index on deletion event.
    pub fn remove(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let key = Self::make_key(ns, &instance.spec.template, name);

        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.remove(&key);
    }

    /// Clears all entries from the index (e.g. on watcher Init event).
    pub fn clear(&self) {
        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.clear();
    }

    /// Maps a `CTFTemplate` update event to a vector of `ObjectRef<CTFInstance>` for all instances
    /// in the same namespace referencing the template that have `spec.sync == true` using prefix lookup.
    pub fn find_synced_instances(&self, template: &CTFTemplate) -> Vec<ObjectRef<CTFInstance>> {
        let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
        let tmpl_ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let prefix = Self::make_prefix(tmpl_ns, tmpl_name);

        let lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(_, val)| val.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFInstanceSpec, CTFTemplateSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::store;

    #[test]
    fn test_instance_cache_find_synced_instances() {
        let (store, _writer) = store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new("whoami-template", CTFTemplateSpec::default());

        let inst_sync_true = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        let inst_sync_false = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-2".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: false,
                ..Default::default()
            },
            status: None,
        };

        let inst_other_tmpl = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-3".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "other-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        cache.update(&inst_sync_true);
        cache.update(&inst_sync_false);
        cache.update(&inst_other_tmpl);

        let matched = cache.find_synced_instances(&tmpl);

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "inst-1");
        assert_eq!(matched[0].namespace.as_deref(), Some("default"));

        cache.remove(&inst_sync_true);
        let matched_after_remove = cache.find_synced_instances(&tmpl);
        assert_eq!(matched_after_remove.len(), 0);
    }

    #[test]
    fn test_instance_cache_update_sync_flag_toggles() {
        let (store, _writer) = store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new("whoami-template", CTFTemplateSpec::default());

        let mut inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-toggle".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        // Initial add with sync = true
        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);

        // Update with sync = false -> should be removed
        inst.spec.sync = false;
        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);

        // Toggle sync back to true -> should be re-added
        inst.spec.sync = true;
        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);
    }

    #[test]
    fn test_instance_cache_deletion_timestamp_pruning() {
        let (store, _writer) = store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new("whoami-template", CTFTemplateSpec::default());

        let mut inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-del".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);

        // Mark for deletion -> should be pruned from cache
        inst.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);
    }

    #[test]
    fn test_instance_cache_template_change_migration() {
        let (store, _writer) = store();
        let cache = InstanceCache::new(store);
        let tmpl_a = CTFTemplate::new("tmpl-a", CTFTemplateSpec::default());
        let tmpl_b = CTFTemplate::new("tmpl-b", CTFTemplateSpec::default());

        let mut inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-migrate".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "tmpl-a".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl_a).len(), 1);
        assert_eq!(cache.find_synced_instances(&tmpl_b).len(), 0);

        // Update instance to reference tmpl-b
        inst.spec.template = "tmpl-b".into();
        cache.update(&inst);

        assert_eq!(cache.find_synced_instances(&tmpl_b).len(), 1);

        // Explicit removal
        cache.remove(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl_b).len(), 0);
    }
}

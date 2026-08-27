use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use k8s_common::crd::{CTFInstance, CTFTemplate};
use kube::runtime::reflector::{ObjectRef, Store};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceKey {
    pub namespace: String,
    pub template: String,
    pub instance: String,
}

#[derive(Clone)]
pub struct InstanceCache {
    store: Store<CTFInstance>,
    index: Arc<Mutex<BTreeMap<InstanceKey, ObjectRef<CTFInstance>>>>,
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

    pub fn update(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let key = InstanceKey {
            namespace: ns.to_string(),
            template: instance.spec.template.clone(),
            instance: name.to_string(),
        };

        let observed_gen = instance.status.as_ref().and_then(|s| s.observed_generation);
        let spec_gen = instance.metadata.generation;
        let is_unobserved = match (observed_gen, spec_gen) {
            (Some(o), Some(g)) => o != g,
            (None, Some(_)) => true,
            _ => false,
        };
        let needs_template_watch = instance.spec.sync || is_unobserved;

        if needs_template_watch && instance.metadata.deletion_timestamp.is_none() {
            let obj_ref = ObjectRef::from_obj(instance);
            let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
            lock.insert(key, obj_ref);
        } else {
            let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
            lock.remove(&key);
        }
    }

    pub fn remove(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let key = InstanceKey {
            namespace: ns.to_string(),
            template: instance.spec.template.clone(),
            instance: name.to_string(),
        };

        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.remove(&key);
    }

    pub fn clear(&self) {
        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.clear();
    }

    pub fn find_synced_instances(&self, template: &CTFTemplate) -> Vec<ObjectRef<CTFInstance>> {
        let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
        let tmpl_ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let start_key = InstanceKey {
            namespace: tmpl_ns.to_string(),
            template: tmpl_name.to_string(),
            instance: String::new(),
        };

        let lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.range(start_key..)
            .take_while(|(k, _)| k.namespace == tmpl_ns && k.template == tmpl_name)
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

    #[test]
    fn test_instance_cache_indexes_unobserved_generation_instances() {
        let (store, _writer) = store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new("whoami-template", CTFTemplateSpec::default());

        // Instance with sync=false, but observed_generation=None and generation=1 (unobserved failed/initial instance)
        let mut inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-failed".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: false,
                ..Default::default()
            },
            status: None,
        };

        // Should be indexed because observed_generation (None) != generation (1)
        cache.update(&inst);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);

        // After successful reconciliation, observed_generation becomes Some(1)
        inst.status = Some(k8s_common::crd::CTFInstanceStatus {
            observed_generation: Some(1),
            conditions: vec![],
            endpoints: vec![],
            ..Default::default()
        });
        cache.update(&inst);

        // Because sync=false and observed_generation == generation, it should be removed from template watch index
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);
    }
}

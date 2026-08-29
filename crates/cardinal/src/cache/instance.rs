use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use k8s_common::crd::{CTFInstance, CTFTemplate};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceKey {
    pub namespace: String,
    pub template: String,
    pub instance: String,
}

#[derive(Default)]
struct Inner {
    index: BTreeMap<InstanceKey, Arc<CTFInstance>>,
    instance_templates: HashMap<(String, String), String>,
}

#[derive(Clone, Default)]
pub struct InstanceCache {
    inner: Arc<Mutex<Inner>>,
}

impl InstanceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let inst_id = (ns.to_string(), name.to_string());
        let new_template = instance.spec.template.clone();

        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Remove old indexed entry if the instance migrated from a different template
        if let Some(old_template) = lock.instance_templates.remove(&inst_id) {
            let old_key = InstanceKey {
                namespace: ns.to_string(),
                template: old_template,
                instance: name.to_string(),
            };
            lock.index.remove(&old_key);
        }

        if instance.metadata.deletion_timestamp.is_none() {
            let key = InstanceKey {
                namespace: ns.to_string(),
                template: new_template.clone(),
                instance: name.to_string(),
            };
            lock.index.insert(key, Arc::new(instance.clone()));
            lock.instance_templates.insert(inst_id, new_template);
        }
    }

    pub fn remove(&self, instance: &CTFInstance) {
        let name = instance.metadata.name.as_deref().unwrap_or_default();
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let inst_id = (ns.to_string(), name.to_string());

        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(template) = lock.instance_templates.remove(&inst_id) {
            let key = InstanceKey {
                namespace: ns.to_string(),
                template,
                instance: name.to_string(),
            };
            lock.index.remove(&key);
        } else {
            let key = InstanceKey {
                namespace: ns.to_string(),
                template: instance.spec.template.clone(),
                instance: name.to_string(),
            };
            lock.index.remove(&key);
        }
    }

    pub fn clear(&self) {
        let mut lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index.clear();
        lock.instance_templates.clear();
    }

    pub fn instances_to_sync(&self, template: &CTFTemplate) -> Vec<Arc<CTFInstance>> {
        let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
        let tmpl_ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let start_key = InstanceKey {
            namespace: tmpl_ns.to_string(),
            template: tmpl_name.to_string(),
            instance: String::new(),
        };

        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index
            .range(start_key..)
            .take_while(|(k, _)| k.namespace == tmpl_ns && k.template == tmpl_name)
            .map(|(_, val)| val.clone())
            .filter(|inst| {
                crate::utils::versions::requires_template_upgrade(&template.metadata, inst)
            })
            .collect()
    }

    /// Returns the `(namespace, name)` of every live (non-deleted) instance in
    /// the cluster as seen by the cache. The index only holds non-deleted
    /// instances, so every entry is live.
    pub fn live_instances(&self) -> Vec<(String, String)> {
        let lock = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        lock.index
            .values()
            .map(|inst| {
                let ns = inst.metadata.namespace.as_deref().unwrap_or("default");
                let name = inst.metadata.name.as_deref().unwrap_or("unknown");
                (ns.to_string(), name.to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFInstanceSpec, CTFInstanceStatus, CTFTemplateSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn tmpl(name: &str, generation: i64) -> CTFTemplate {
        CTFTemplate {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some("default".into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: CTFTemplateSpec::default(),
            status: None,
        }
    }

    fn inst(name: &str, template: &str, sync: bool, observed: Option<i64>) -> CTFInstance {
        CTFInstance {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: template.into(),
                sync,
                ..Default::default()
            },
            status: Some(CTFInstanceStatus {
                template_generation: observed,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn test_instance_cache_find_synced_instances() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        let inst_sync_true = inst("inst-1", "whoami-template", true, Some(1));
        let inst_sync_false = inst("inst-2", "whoami-template", false, Some(1));
        let inst_other_tmpl = inst("inst-3", "other-template", true, Some(1));

        cache.update(&inst_sync_true);
        cache.update(&inst_sync_false);
        cache.update(&inst_other_tmpl);

        let matched = cache.instances_to_sync(&tmpl);

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].metadata.name.as_deref(), Some("inst-1"));
        assert_eq!(matched[0].metadata.namespace.as_deref(), Some("default"));

        cache.remove(&inst_sync_true);
        let matched_after_remove = cache.instances_to_sync(&tmpl);
        assert_eq!(matched_after_remove.len(), 0);
    }

    #[test]
    fn test_instance_cache_update_sync_flag_toggles() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        let mut inst = inst("inst-toggle", "whoami-template", true, Some(1));

        // Initial add with sync = true and stale template generation
        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 1);

        // Update with sync = false -> filtered out of sync results
        inst.spec.sync = false;
        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);

        // Toggle sync back to true -> needs upgrade again
        inst.spec.sync = true;
        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 1);
    }

    #[test]
    fn test_instance_cache_skips_caught_up_synced_instances() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        // Synced but already current: must not be returned for re-apply.
        let caught_up = inst("inst-up-to-date", "whoami-template", true, Some(2));
        cache.update(&caught_up);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }

    #[test]
    fn test_instance_cache_deletion_timestamp_pruning() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        let mut inst = inst("inst-del", "whoami-template", true, Some(1));

        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 1);

        // Mark for deletion -> should be pruned from cache
        inst.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }

    #[test]
    fn test_instance_cache_template_change_migration() {
        let cache = InstanceCache::new();
        let tmpl_a = tmpl("tmpl-a", 2);
        let tmpl_b = tmpl("tmpl-b", 2);

        let mut inst = inst("inst-migrate", "tmpl-a", true, Some(1));

        cache.update(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl_a).len(), 1);
        assert_eq!(cache.instances_to_sync(&tmpl_b).len(), 0);

        // Update instance to reference tmpl-b
        inst.spec.template = "tmpl-b".into();
        cache.update(&inst);

        assert_eq!(cache.instances_to_sync(&tmpl_b).len(), 1);
        assert_eq!(
            cache.instances_to_sync(&tmpl_a).len(),
            0,
            "tmpl-a index entry must be purged on spec.template change"
        );

        // Explicit removal
        cache.remove(&inst);
        assert_eq!(cache.instances_to_sync(&tmpl_b).len(), 0);
    }

    #[test]
    fn test_instance_cache_synced_unobserved_instance_needs_catch_up() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 1);

        // Synced instance that has never applied the template (template_generation
        // absent) must be returned so its first apply happens.
        let inst_fresh = inst("inst-fresh", "whoami-template", true, None);
        cache.update(&inst_fresh);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 1);

        // After a successful apply, template_generation is caught up and it drops out.
        let mut inst_done = inst_fresh.clone();
        inst_done.status = Some(CTFInstanceStatus {
            template_generation: Some(1),
            ..Default::default()
        });
        cache.update(&inst_done);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }

    #[test]
    fn test_instance_cache_non_synced_not_returned_for_sync() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        // Non-synced instances never track the template, even if stale.
        let non_synced = inst("inst-static", "whoami-template", false, Some(1));
        cache.update(&non_synced);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }
}

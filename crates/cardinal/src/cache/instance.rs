use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use k8s_common::crd::{CTFInstance, CTFTemplate};
use parking_lot::RwLock;

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
    inner: Arc<RwLock<Inner>>,
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

        let mut lock = self.inner.write();

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

        let mut lock = self.inner.write();
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
        let mut lock = self.inner.write();
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

        let lock = self.inner.read();
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
        let lock = self.inner.read();
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

    fn inst(
        name: &str,
        template: &str,
        observed: Option<i64>,
        min_gen: Option<i64>,
    ) -> CTFInstance {
        CTFInstance {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some("default".into()),
                annotations: min_gen.map(|m| {
                    [(
                        k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                        m.to_string(),
                    )]
                    .into_iter()
                    .collect()
                }),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: template.into(),
                ..Default::default()
            },
            status: Some(CTFInstanceStatus {
                template_generation: observed,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn test_instance_cache_instances_to_sync_with_template_floor() {
        let cache = InstanceCache::new();
        let tmpl_no_floor = tmpl("whoami-template", 2);
        let mut tmpl_with_floor = tmpl("whoami-template", 2);
        tmpl_with_floor.metadata.annotations = Some(
            [(
                k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "2".to_string(),
            )]
            .into_iter()
            .collect(),
        );

        let inst_1 = inst("inst-1", "whoami-template", Some(1), None);
        let inst_other_tmpl = inst("inst-2", "other-template", Some(1), None);

        cache.update(&inst_1);
        cache.update(&inst_other_tmpl);

        // Without floor on template or instance, instances_to_sync returns nothing
        assert_eq!(cache.instances_to_sync(&tmpl_no_floor).len(), 0);

        // With floor on template, inst-1 requires upgrade
        let matched = cache.instances_to_sync(&tmpl_with_floor);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].metadata.name.as_deref(), Some("inst-1"));

        cache.remove(&inst_1);
        let matched_after_remove = cache.instances_to_sync(&tmpl_with_floor);
        assert_eq!(matched_after_remove.len(), 0);
    }

    #[test]
    fn test_instance_cache_instances_to_sync_with_instance_floor() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        let mut inst_stale = inst("inst-stale", "whoami-template", Some(1), None);
        cache.update(&inst_stale);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);

        // Add instance floor
        inst_stale.metadata.annotations = Some(
            [(
                k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "2".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        cache.update(&inst_stale);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 1);

        // Caught up
        inst_stale.status = Some(CTFInstanceStatus {
            template_generation: Some(2),
            ..Default::default()
        });
        cache.update(&inst_stale);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }

    #[test]
    fn test_instance_cache_deletion_timestamp_pruning() {
        let cache = InstanceCache::new();
        let mut tmpl = tmpl("whoami-template", 2);
        tmpl.metadata.annotations = Some(
            [(
                k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "2".to_string(),
            )]
            .into_iter()
            .collect(),
        );

        let mut inst = inst("inst-del", "whoami-template", Some(1), None);

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
        let mut tmpl_a = tmpl("tmpl-a", 2);
        tmpl_a.metadata.annotations = Some(
            [(
                k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "2".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let mut tmpl_b = tmpl("tmpl-b", 2);
        tmpl_b.metadata.annotations = Some(
            [(
                k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "2".to_string(),
            )]
            .into_iter()
            .collect(),
        );

        let mut inst = inst("inst-migrate", "tmpl-a", Some(1), None);

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
    fn test_instance_cache_instances_without_floor_never_sync() {
        let cache = InstanceCache::new();
        let tmpl = tmpl("whoami-template", 2);

        let inst_static = inst("inst-static", "whoami-template", Some(1), None);
        cache.update(&inst_static);
        assert_eq!(cache.instances_to_sync(&tmpl).len(), 0);
    }
}

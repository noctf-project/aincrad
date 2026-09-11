use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use globset::GlobSet;
use k8s_common::{SpecPatcher, crd::Template};
use parking_lot::RwLock;
use tokio::sync::watch;

use crate::cache::ReadyCache;
use crate::planners::replicaset::POD_PATCH_BLACKLIST;

use std::time::Duration;

pub type PodPatchersMap = Arc<HashMap<String, Option<SpecPatcher>>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateKey {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CachedTemplateEntry {
    pub template: Arc<Template>,
    pub pod_patchers: Result<PodPatchersMap, String>,
    pub default_ttl: Option<Duration>,
}

#[derive(Clone)]
pub struct TemplateCache {
    index: Arc<RwLock<BTreeMap<TemplateKey, CachedTemplateEntry>>>,
    ready: watch::Sender<bool>,
    ready_rx: watch::Receiver<bool>,
}

impl Default for TemplateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateCache {
    pub fn new() -> Self {
        let (ready, ready_rx) = watch::channel(false);
        Self {
            index: Arc::new(RwLock::new(BTreeMap::new())),
            ready,
            ready_rx,
        }
    }

    /// Marks the cache as having completed an initial sync.
    pub fn mark_ready(&self) {
        let _ = self.ready.send(true);
    }

    /// Marks the cache as beginning (or restarting) an initial sync.
    pub fn mark_unready(&self) {
        let _ = self.ready.send(false);
    }

    pub fn get(&self, namespace: &str, name: &str) -> Option<CachedTemplateEntry> {
        let key = TemplateKey {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        let lock = self.index.read();
        lock.get(&key).cloned()
    }

    pub fn update(&self, template: &Template) {
        let name = template.metadata.name.as_deref().unwrap_or_default();
        let ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let key = TemplateKey {
            namespace: ns.to_string(),
            name: name.to_string(),
        };

        if template.metadata.deletion_timestamp.is_some() {
            let mut lock = self.index.write();
            lock.remove(&key);
            return;
        }

        let pod_patchers = compile_patchers(
            template
                .spec
                .pods
                .iter()
                .map(|p| (p.name.clone(), p.patch_spec.clone())),
            &POD_PATCH_BLACKLIST,
        );
        let default_ttl = template
            .metadata
            .annotations
            .as_ref()
            .and_then(|ann| ann.get(k8s_common::labels::DEFAULT_TTL_ANNOTATION))
            .and_then(|val| crate::utils::ttl::parse_duration(val).ok());

        let entry = CachedTemplateEntry {
            template: Arc::new(template.clone()),
            pod_patchers,
            default_ttl,
        };

        let mut lock = self.index.write();
        lock.insert(key, entry);
    }

    pub fn remove(&self, template: &Template) {
        let name = template.metadata.name.as_deref().unwrap_or_default();
        let ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let key = TemplateKey {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let mut lock = self.index.write();
        lock.remove(&key);
    }

    pub fn clear(&self) {
        let mut lock = self.index.write();
        lock.clear();
    }
}

impl ReadyCache for TemplateCache {
    fn is_ready(&self) -> bool {
        *self.ready_rx.borrow()
    }

    fn watch(&self) -> watch::Receiver<bool> {
        self.ready.subscribe()
    }
}

fn compile_patchers(
    entries: impl Iterator<Item = (String, Option<json_patch::Patch>)>,
    blacklist: &GlobSet,
) -> Result<Arc<HashMap<String, Option<SpecPatcher>>>, String> {
    let mut patchers = HashMap::new();
    for (name, patch) in entries {
        let patcher = if let Some(patch) = patch {
            Some(SpecPatcher::new(blacklist, patch)?)
        } else {
            None
        };
        patchers.insert(name, patcher);
    }
    Ok(Arc::new(patchers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::TemplateSpec;
    use k8s_common::crd::TemplateSpecPod;
    use k8s_openapi::api::core::v1::{Container, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use serde_json::json;

    #[test]
    fn test_template_cache_update_and_get() {
        let cache = TemplateCache::new();
        let valid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/metadata/labels/test", "value": "true" }
        ]))
        .unwrap();

        let pod_tmpl = TemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch_spec: Some(valid_patch),
            spec: PodSpec {
                containers: vec![Container {
                    name: "web".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        };

        let tmpl = Template {
            metadata: ObjectMeta {
                name: Some("tmpl1".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: TemplateSpec {
                pods: vec![pod_tmpl],
                ..Default::default()
            },
            status: None,
        };

        // Cache update compiles patchers
        cache.update(&tmpl);

        let entry = cache.get("default", "tmpl1").unwrap();
        assert_eq!(entry.template.metadata.name.as_deref(), Some("tmpl1"));
        let patchers = entry.pod_patchers.unwrap();
        assert!(patchers.contains_key("web"));

        // Second lookup should return same compiled Arc pointer
        let entry2 = cache.get("default", "tmpl1").unwrap();
        let patchers2 = entry2.pod_patchers.unwrap();
        assert!(Arc::ptr_eq(&patchers, &patchers2));
    }

    #[test]
    fn test_template_cache_failed_compile_cached() {
        let cache = TemplateCache::new();
        // Path "/hostNetwork" is blacklisted by POD_PATCH_BLACKLIST
        let invalid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/hostNetwork", "value": true }
        ]))
        .unwrap();

        let pod_tmpl = TemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch_spec: Some(invalid_patch),
            spec: PodSpec::default(),
        };

        let tmpl = Template {
            metadata: ObjectMeta {
                name: Some("tmpl_invalid".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: TemplateSpec {
                pods: vec![pod_tmpl],
                ..Default::default()
            },
            status: None,
        };

        cache.update(&tmpl);
        let entry = cache.get("default", "tmpl_invalid").unwrap();
        assert!(entry.pod_patchers.is_err());
        assert!(entry.pod_patchers.unwrap_err().contains("blacklisted"));
    }

    #[test]
    fn test_template_cache_remove_and_clear() {
        let cache = TemplateCache::new();
        let tmpl1 = Template {
            metadata: ObjectMeta {
                name: Some("tmpl1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: TemplateSpec::default(),
            status: None,
        };
        let tmpl2 = Template {
            metadata: ObjectMeta {
                name: Some("tmpl2".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: TemplateSpec::default(),
            status: None,
        };

        cache.update(&tmpl1);
        cache.update(&tmpl2);

        assert!(cache.get("default", "tmpl1").is_some());
        assert!(cache.get("default", "tmpl2").is_some());

        // Remove tmpl1
        cache.remove(&tmpl1);
        assert!(cache.get("default", "tmpl1").is_none());
        assert!(cache.get("default", "tmpl2").is_some());

        // Clear all
        cache.clear();
        assert!(cache.get("default", "tmpl2").is_none());
    }

    #[test]
    fn test_template_cache_default_ttl() {
        let cache = TemplateCache::new();

        // Valid duration string "30m"
        let mut annotations = BTreeMap::new();
        annotations.insert(
            k8s_common::labels::DEFAULT_TTL_ANNOTATION.to_string(),
            "30m".to_string(),
        );
        let tmpl_valid = Template {
            metadata: ObjectMeta {
                name: Some("tmpl_valid".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: TemplateSpec::default(),
            status: None,
        };
        cache.update(&tmpl_valid);
        let entry = cache.get("default", "tmpl_valid").unwrap();
        assert_eq!(entry.default_ttl, Some(Duration::from_secs(1800)));

        // Invalid duration string "not-a-duration" -> None (infinite)
        let mut annotations_invalid = BTreeMap::new();
        annotations_invalid.insert(
            k8s_common::labels::DEFAULT_TTL_ANNOTATION.to_string(),
            "not-a-duration".to_string(),
        );
        let tmpl_invalid = Template {
            metadata: ObjectMeta {
                name: Some("tmpl_invalid_ttl".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations_invalid),
                ..Default::default()
            },
            spec: TemplateSpec::default(),
            status: None,
        };
        cache.update(&tmpl_invalid);
        let entry = cache.get("default", "tmpl_invalid_ttl").unwrap();
        assert_eq!(entry.default_ttl, None);

        // Omitted annotation -> None (infinite)
        let tmpl_omitted = Template {
            metadata: ObjectMeta {
                name: Some("tmpl_no_ttl".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: TemplateSpec::default(),
            status: None,
        };
        cache.update(&tmpl_omitted);
        let entry = cache.get("default", "tmpl_no_ttl").unwrap();
        assert_eq!(entry.default_ttl, None);
    }
}

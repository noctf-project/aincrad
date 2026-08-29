use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use k8s_common::{
    SpecPatcher,
    crd::{CTFTemplate, CTFTemplateSpecPod},
};
use kube::runtime::reflector::Store;

use crate::planners::replicaset::POD_PATCH_BLACKLIST;

pub type PodPatchersMap = Arc<HashMap<String, Option<SpecPatcher>>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateKey {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CachedTemplateEntry {
    pub template: Arc<CTFTemplate>,
    pub pod_patchers: Result<PodPatchersMap, String>,
}

#[derive(Clone)]
pub struct TemplateCache {
    store: Store<CTFTemplate>,
    index: Arc<Mutex<BTreeMap<TemplateKey, CachedTemplateEntry>>>,
}

impl TemplateCache {
    pub fn new(store: Store<CTFTemplate>) -> Self {
        Self {
            store,
            index: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn store(&self) -> &Store<CTFTemplate> {
        &self.store
    }

    pub fn get(&self, namespace: &str, name: &str) -> Option<CachedTemplateEntry> {
        let key = TemplateKey {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
        let lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.get(&key).cloned()
    }

    pub fn update(&self, template: &CTFTemplate) {
        let name = template.metadata.name.as_deref().unwrap_or_default();
        let ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let key = TemplateKey {
            namespace: ns.to_string(),
            name: name.to_string(),
        };

        if template.metadata.deletion_timestamp.is_some() {
            let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
            lock.remove(&key);
            return;
        }

        let pod_patchers = compile_pod_patchers(&template.spec.pods);
        let entry = CachedTemplateEntry {
            template: Arc::new(template.clone()),
            pod_patchers,
        };

        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.insert(key, entry);
    }

    pub fn remove(&self, template: &CTFTemplate) {
        let name = template.metadata.name.as_deref().unwrap_or_default();
        let ns = template.metadata.namespace.as_deref().unwrap_or("default");
        let key = TemplateKey {
            namespace: ns.to_string(),
            name: name.to_string(),
        };
        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.remove(&key);
    }

    pub fn clear(&self) {
        let mut lock = self.index.lock().unwrap_or_else(|e| e.into_inner());
        lock.clear();
    }
}

pub fn compile_pod_patchers(pods: &[CTFTemplateSpecPod]) -> Result<PodPatchersMap, String> {
    let mut pod_patchers = HashMap::new();
    for pod in pods {
        let patcher = if let Some(patch) = &pod.patch_spec {
            Some(SpecPatcher::new(&POD_PATCH_BLACKLIST, patch.clone())?)
        } else {
            None
        };
        pod_patchers.insert(pod.name.clone(), patcher);
    }
    Ok(Arc::new(pod_patchers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::CTFTemplateSpec;
    use k8s_openapi::api::core::v1::{Container, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::store;
    use serde_json::json;

    #[test]
    fn test_template_cache_update_and_get() {
        let (store, _writer) = store();
        let cache = TemplateCache::new(store);
        let valid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/metadata/labels/test", "value": "true" }
        ]))
        .unwrap();

        let pod_tmpl = CTFTemplateSpecPod {
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

        let tmpl = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("tmpl1".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFTemplateSpec {
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
        let (store, _writer) = store();
        let cache = TemplateCache::new(store);
        // Path "/hostNetwork" is blacklisted by POD_PATCH_BLACKLIST
        let invalid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/hostNetwork", "value": true }
        ]))
        .unwrap();

        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch_spec: Some(invalid_patch),
            spec: PodSpec::default(),
        };

        let tmpl = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("tmpl_invalid".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFTemplateSpec {
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
        let (store, _writer) = store();
        let cache = TemplateCache::new(store);
        let tmpl1 = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("tmpl1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFTemplateSpec::default(),
            status: None,
        };
        let tmpl2 = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("tmpl2".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFTemplateSpec::default(),
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
}

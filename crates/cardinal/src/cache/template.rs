use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k8s_common::{SpecPatcher, crd::CTFTemplateSpecPod};

use crate::planners::replicaset::POD_PATCH_BLACKLIST;

pub type PodPatchersMap = Arc<HashMap<String, Option<SpecPatcher>>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateKey {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CachedTemplateEntry {
    pub generation: i64,
    pub pod_patchers: Result<PodPatchersMap, String>,
}

#[derive(Debug, Clone, Default)]
pub struct TemplateCache {
    cache: Arc<Mutex<BTreeMap<TemplateKey, CachedTemplateEntry>>>,
}

impl TemplateCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn get_or_compile(
        &self,
        key: &TemplateKey,
        generation: i64,
        pods: &[CTFTemplateSpecPod],
    ) -> Result<PodPatchersMap, String> {
        {
            let lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = lock.get(key)
                && entry.generation == generation
            {
                return entry.pod_patchers.clone();
            }
        }

        let compiled_result = compile_pod_patchers(pods);
        let entry = CachedTemplateEntry {
            generation,
            pod_patchers: compiled_result.clone(),
        };

        let mut lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        lock.insert(key.clone(), entry);
        compiled_result
    }

    pub fn remove(&self, key: &TemplateKey) {
        let mut lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        lock.remove(key);
    }

    pub fn clear(&self) {
        let mut lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        lock.clear();
    }
}

fn compile_pod_patchers(pods: &[CTFTemplateSpecPod]) -> Result<PodPatchersMap, String> {
    let mut pod_patchers = HashMap::new();
    for pod in pods {
        let patcher = if let Some(patch) = &pod.patch {
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
    use k8s_openapi::api::core::v1::{Container, PodSpec};
    use serde_json::json;

    #[test]
    fn test_template_cache_compile_hit_and_generation_shift() {
        let cache = TemplateCache::new();
        let valid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/metadata/labels/test", "value": "true" }
        ]))
        .unwrap();

        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch: Some(valid_patch),
            spec: PodSpec {
                containers: vec![Container {
                    name: "web".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        };

        let pods = vec![pod_tmpl];
        let key = TemplateKey {
            namespace: "default".into(),
            name: "tmpl1".into(),
        };

        // First compile for gen 1
        let patchers_gen1 = cache.get_or_compile(&key, 1, &pods).unwrap();
        assert!(patchers_gen1.contains_key("web"));

        // Second lookup for gen 1 should hit cache (same Arc pointer)
        let patchers_gen1_hit = cache.get_or_compile(&key, 1, &pods).unwrap();
        assert!(Arc::ptr_eq(&patchers_gen1, &patchers_gen1_hit));

        // Generation shift to gen 2 should re-compile (different Arc pointer)
        let patchers_gen2 = cache.get_or_compile(&key, 2, &pods).unwrap();
        assert!(!Arc::ptr_eq(&patchers_gen1, &patchers_gen2));
    }

    #[test]
    fn test_template_cache_failed_compile_caching() {
        let cache = TemplateCache::new();
        // Path "/hostNetwork" is blacklisted by POD_PATCH_BLACKLIST
        let invalid_patch: json_patch::Patch = serde_json::from_value(json!([
            { "op": "add", "path": "/hostNetwork", "value": true }
        ]))
        .unwrap();

        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch: Some(invalid_patch),
            spec: PodSpec::default(),
        };

        let pods = vec![pod_tmpl];
        let key = TemplateKey {
            namespace: "default".into(),
            name: "tmpl1".into(),
        };

        // Compilation should fail and cache the error for gen 1
        let err1 = cache.get_or_compile(&key, 1, &pods).unwrap_err();
        let err2 = cache.get_or_compile(&key, 1, &pods).unwrap_err();
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_template_cache_remove_and_clear() {
        let cache = TemplateCache::new();
        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            allow_internet: false,
            replicas: 1,
            patch: None,
            spec: PodSpec::default(),
        };
        let pods = vec![pod_tmpl];

        let key1 = TemplateKey {
            namespace: "default".into(),
            name: "tmpl1".into(),
        };
        let key2 = TemplateKey {
            namespace: "default".into(),
            name: "tmpl2".into(),
        };

        cache.get_or_compile(&key1, 1, &pods).unwrap();
        cache.get_or_compile(&key2, 1, &pods).unwrap();

        // Remove tmpl1
        cache.remove(&key1);
        let patchers_recompiled = cache.get_or_compile(&key1, 1, &pods).unwrap();
        assert!(patchers_recompiled.contains_key("web"));

        // Clear all
        cache.clear();
    }
}

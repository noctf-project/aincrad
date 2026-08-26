use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use k8s_common::{
    SpecPatcher,
    crd::{CTFInstance, CTFTemplate, CTFTemplateSpec, CTFTemplateSpecPod, PatchValue},
};
use k8s_openapi::api::core::v1::PodSpec;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use tracing::instrument;

use crate::{Context, Error, resources::replicaset::POD_PATCH_BLACKLIST};

pub type PodPatchersMap = Arc<HashMap<String, Option<SpecPatcher>>>;

#[derive(Debug, Clone)]
pub struct CachedTemplateEntry {
    pub generation: i64,
    pub pod_patchers: Result<PodPatchersMap, String>,
}

/// In-memory cache of compiled SpecPatchers for CTFTemplates keyed by "namespace/name".
/// Caches both successful SpecPatcher maps and failed compilation errors per generation.
#[derive(Debug, Clone, Default)]
pub struct TemplateCache {
    cache: Arc<Mutex<HashMap<String, CachedTemplateEntry>>>,
}

impl TemplateCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Looks up or compiles and caches the `PodPatchersMap` for a CTFTemplate generation.
    pub fn get_or_compile(
        &self,
        key: &str,
        generation: i64,
        pods: &[CTFTemplateSpecPod],
    ) -> Result<PodPatchersMap, String> {
        let mut lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = lock.get(key)
            && entry.generation == generation
        {
            return entry.pod_patchers.clone();
        }

        let compiled_result = compile_pod_patchers(pods);
        let entry = CachedTemplateEntry {
            generation,
            pod_patchers: compiled_result.clone(),
        };

        lock.insert(key.to_string(), entry);
        compiled_result
    }

    /// Removes a template entry from the cache (e.g. when deleted, updated, or dropped).
    pub fn remove(&self, key: &str) {
        let mut lock = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        lock.remove(key);
    }

    /// Clears all entries from the template cache (e.g. on watcher resync).
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

/// Resolved CTFTemplate with merged parameter map and pre-compiled SpecPatchers for pod JSON patches.
#[derive(Debug, Clone)]
pub struct ResolvedTemplate {
    pub metadata: ObjectMeta,
    pub spec: CTFTemplateSpec,
    pub pod_patchers: PodPatchersMap,
    pub params_map: BTreeMap<String, String>,
}

impl ResolvedTemplate {
    /// Evaluates pre-compiled JSON patches for `pod_tmpl` and returns the final `PodSpec`.
    pub fn get_patched_pod_spec<V>(
        &self,
        pod_tmpl: &CTFTemplateSpecPod,
        context_map: &BTreeMap<String, V>,
    ) -> Result<PodSpec, Error>
    where
        V: serde::Serialize,
    {
        if let Some(Some(patcher)) = self.pod_patchers.get(&pod_tmpl.name) {
            patcher
                .apply(&pod_tmpl.spec, context_map)
                .map_err(Error::PatchEvaluationFailed)
        } else {
            Ok(pod_tmpl.spec.clone())
        }
    }
}

/// Resolves the `CTFTemplate` referenced by `instance.spec.template`, applying parameter overrides,
/// generating the merged params_map, and querying the TemplateCache for pre-compiled SpecPatchers.
#[instrument(skip(ctx, instance), fields(instance = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: &CTFInstance, ctx: &Context) -> Result<ResolvedTemplate, Error> {
    let template_name = &instance.spec.template;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    // Check in-memory reflector store cache first
    let cached_template = if let Some(store) = &ctx.template_store {
        let key = kube::runtime::reflector::ObjectRef::new(template_name).within(ns);
        store.get(&key).map(|t| (*t).clone())
    } else {
        None
    };

    let template = match cached_template {
        Some(t) => t,
        None => {
            let templates: Api<CTFTemplate> = Api::namespaced(ctx.client.clone(), ns);
            match templates.get_opt(template_name).await? {
                Some(t) => t,
                None => return Err(Error::TemplateNotFound(template_name.clone())),
            }
        }
    };

    let generation = template.metadata.generation.unwrap_or(1);
    let cache_key = format!("{ns}/{template_name}");

    let pod_patchers = ctx
        .template_cache
        .get_or_compile(&cache_key, generation, &template.spec.pods)
        .map_err(Error::InvalidPatch)?;

    let params_map = resolve_template_params(&template.spec, instance);

    Ok(ResolvedTemplate {
        metadata: template.metadata,
        spec: template.spec,
        pod_patchers,
        params_map,
    })
}

/// Merges CTFTemplateSpec params with instance.spec.params into a BTreeMap<String, String>.
/// Instance overrides have higher priority.
/// If an instance param override has PatchValue::Null (`value: null`), it is removed from the merged map.
pub fn resolve_template_params(
    template_spec: &CTFTemplateSpec,
    instance: &CTFInstance,
) -> BTreeMap<String, String> {
    let mut param_map: BTreeMap<String, String> = BTreeMap::new();

    // Base parameters from CTFTemplate
    for param in &template_spec.params {
        map_insert_param(&mut param_map, param.name.clone(), param.value.clone());
    }

    // Instance parameter overrides (higher priority)
    for override_param in &instance.spec.params {
        match &override_param.value {
            PatchValue::Value(val) => {
                map_insert_param(&mut param_map, override_param.name.clone(), val.clone());
            }
            PatchValue::Null => {
                // Remove parameter if explicitly set to null/nil
                param_map.remove(&override_param.name);
            }
            PatchValue::Unset => {}
        }
    }

    param_map
}

fn map_insert_param(map: &mut BTreeMap<String, String>, name: String, val: String) {
    map.insert(name, val);
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFInstanceSpec, CTFInstanceSpecParam, CTFTemplateSpecParam};
    use k8s_openapi::api::core::v1::Container;
    use serde_json::json;

    #[test]
    fn test_merge_template_params_override_and_remove() {
        let template_spec = CTFTemplateSpec {
            params: vec![
                CTFTemplateSpecParam {
                    name: "PORT".into(),
                    value: "8080".into(),
                },
                CTFTemplateSpecParam {
                    name: "DEBUG".into(),
                    value: "true".into(),
                },
                CTFTemplateSpecParam {
                    name: "FLAG".into(),
                    value: "CTF{base}".into(),
                },
            ],
            ..Default::default()
        };

        let instance = CTFInstance {
            spec: CTFInstanceSpec {
                template: "whoami".into(),
                params: vec![
                    // Override PORT value
                    CTFInstanceSpecParam {
                        name: "PORT".into(),
                        value: PatchValue::Value("9000".into()),
                    },
                    // Remove DEBUG parameter via null
                    CTFInstanceSpecParam {
                        name: "DEBUG".into(),
                        value: PatchValue::Null,
                    },
                    // Add new param
                    CTFInstanceSpecParam {
                        name: "SECRET".into(),
                        value: PatchValue::Value("supersecret".into()),
                    },
                ],
                ..Default::default()
            },
            metadata: ObjectMeta::default(),
            status: None,
        };

        let param_map = resolve_template_params(&template_spec, &instance);

        assert_eq!(param_map.get("PORT"), Some(&"9000".to_string()));
        assert_eq!(param_map.get("FLAG"), Some(&"CTF{base}".to_string()));
        assert_eq!(param_map.get("SECRET"), Some(&"supersecret".to_string()));
        assert_eq!(param_map.get("DEBUG"), None); // Verifies removal!
    }

    #[test]
    fn test_resolved_template_pod_spec_patching() {
        let patch_json = json!([
            {
                "op": "add",
                "path": "/activeDeadlineSeconds",
                "value": "{{ params.ttl }}"
            }
        ]);
        let patch: json_patch::Patch = serde_json::from_value(patch_json).unwrap();

        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            patch: Some(patch.clone()),
            spec: PodSpec {
                containers: vec![Container {
                    name: "web".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let patcher = SpecPatcher::new(&POD_PATCH_BLACKLIST, patch).unwrap();

        let mut pod_patchers = HashMap::new();
        pod_patchers.insert("web".to_string(), Some(patcher));

        let mut params_map = BTreeMap::new();
        params_map.insert("ttl".to_string(), "7200".to_string());

        let resolved = ResolvedTemplate {
            metadata: ObjectMeta::default(),
            spec: CTFTemplateSpec {
                pods: vec![pod_tmpl.clone()],
                ..Default::default()
            },
            pod_patchers: Arc::new(pod_patchers),
            params_map: params_map.clone(),
        };

        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), &params_map);

        let patched_spec = resolved
            .get_patched_pod_spec(&pod_tmpl, &context_map)
            .unwrap();
        assert_eq!(patched_spec.active_deadline_seconds, Some(7200));
    }

    #[test]
    fn test_template_cache_eviction() {
        let cache = TemplateCache::new();
        let key = "default/web-template";
        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            ..Default::default()
        };

        let patchers1 = cache.get_or_compile(key, 1, &[pod_tmpl.clone()]).unwrap();
        let patchers2 = cache.get_or_compile(key, 1, &[pod_tmpl.clone()]).unwrap();

        // Must reuse cached Arc
        assert!(Arc::ptr_eq(&patchers1, &patchers2));

        // Evict key from cache
        cache.remove(key);

        let patchers3 = cache.get_or_compile(key, 1, &[pod_tmpl]).unwrap();
        assert!(!Arc::ptr_eq(&patchers1, &patchers3));
    }

    #[test]
    fn test_template_cache_failed_compile_caching() {
        let cache = TemplateCache::new();
        let key = "default/blacklisted-template";
        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/securityContext",
                "value": { "privileged": true }
            }
        ]);
        let patch: json_patch::Patch = serde_json::from_value(patch_json).unwrap();
        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            patch: Some(patch),
            ..Default::default()
        };

        // First call fails and caches the Err
        let res1 = cache.get_or_compile(key, 1, &[pod_tmpl.clone()]);
        assert!(res1.is_err());
        assert!(res1.as_ref().unwrap_err().contains("blacklisted"));

        // Second call for same generation returns cached Err instantly
        let res2 = cache.get_or_compile(key, 1, &[pod_tmpl]);
        assert_eq!(res1.unwrap_err(), res2.unwrap_err());
    }
}

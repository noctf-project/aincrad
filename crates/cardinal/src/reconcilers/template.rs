use std::collections::BTreeMap;

use k8s_common::crd::{Instance, PatchValue, TemplateSpec, TemplateSpecPod};
use k8s_openapi::api::core::v1::PodSpec;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use tracing::instrument;

use crate::{Context, Error};

pub use crate::cache::{CachedTemplateEntry, PodPatchersMap, TemplateCache};

/// Resolved Template with merged parameter map and pre-compiled SpecPatchers for pod JSON patches.
#[derive(Debug, Clone)]
pub struct ResolvedTemplate {
    pub metadata: ObjectMeta,
    pub spec: TemplateSpec,
    pub pod_patchers: PodPatchersMap,
    pub params_map: BTreeMap<String, String>,
}

impl ResolvedTemplate {
    /// Evaluates pre-compiled JSON patches for `pod_tmpl` and returns the final `PodSpec`.
    pub fn get_patched_pod_spec<V>(
        &self,
        pod_tmpl: &TemplateSpecPod,
        context_map: &BTreeMap<String, V>,
    ) -> Result<PodSpec, Error>
    where
        V: serde::Serialize,
    {
        if let Some(Some(patcher)) = self.pod_patchers.get(&pod_tmpl.name) {
            patcher
                .apply(&pod_tmpl.spec, context_map)
                .map_err(Error::TemplateBuildError)
        } else {
            Ok(pod_tmpl.spec.clone())
        }
    }
}

/// Resolves the `Template` referenced by `instance.spec.template`, applying parameter overrides,
/// generating the merged params_map, and querying the in-memory TemplateCache for pre-compiled SpecPatchers.
#[instrument(skip(ctx, instance), fields(instance = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: &Instance, ctx: &Context) -> Result<ResolvedTemplate, Error> {
    let template_name = &instance.spec.template;
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    let entry = ctx
        .caches
        .templates
        .get(ns, template_name)
        .ok_or_else(|| Error::TemplateNotFound(template_name.clone()))?;

    let pod_patchers = entry.pod_patchers.map_err(Error::TemplateBuildError)?;
    let params_map = resolve_template_params(&entry.template.spec, instance);

    Ok(ResolvedTemplate {
        metadata: entry.template.metadata.clone(),
        spec: entry.template.spec.clone(),
        pod_patchers,
        params_map,
    })
}

/// Merges TemplateSpec params with instance.spec.params into a BTreeMap<String, String>.
/// Instance overrides have higher priority.
/// If an instance param override has PatchValue::Null (`value: null`), it is removed from the merged map.
pub fn resolve_template_params(
    template_spec: &TemplateSpec,
    instance: &Instance,
) -> BTreeMap<String, String> {
    let mut param_map: BTreeMap<String, String> = BTreeMap::new();

    // Base parameters from Template
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
    use crate::planners::replicaset::POD_PATCH_BLACKLIST;
    use k8s_common::SpecPatcher;
    use k8s_common::crd::{InstanceSpec, InstanceSpecParam, TemplateSpecParam};
    use k8s_openapi::api::core::v1::Container;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_merge_template_params_override_and_remove() {
        let template_spec = TemplateSpec {
            params: vec![
                TemplateSpecParam {
                    name: "PORT".into(),
                    value: "8080".into(),
                },
                TemplateSpecParam {
                    name: "DEBUG".into(),
                    value: "true".into(),
                },
                TemplateSpecParam {
                    name: "FLAG".into(),
                    value: "CTF{base}".into(),
                },
            ],
            ..Default::default()
        };

        let instance = Instance {
            spec: InstanceSpec {
                template: "whoami".into(),
                params: vec![
                    // Override PORT value
                    InstanceSpecParam {
                        name: "PORT".into(),
                        value: PatchValue::Value("9000".into()),
                    },
                    // Remove DEBUG parameter via null
                    InstanceSpecParam {
                        name: "DEBUG".into(),
                        value: PatchValue::Null,
                    },
                    // Add new param
                    InstanceSpecParam {
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

        let pod_tmpl = TemplateSpecPod {
            name: "web".into(),
            patch_spec: Some(patch.clone()),
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
            spec: TemplateSpec {
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
        let pod_tmpl = TemplateSpecPod {
            name: "web".into(),
            ..Default::default()
        };
        let tmpl = k8s_common::crd::Template {
            metadata: ObjectMeta {
                name: Some("web-template".into()),
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
        let entry1 = cache.get("default", "web-template").unwrap();
        let entry2 = cache.get("default", "web-template").unwrap();

        // Must reuse cached Arc
        assert!(Arc::ptr_eq(
            &entry1.pod_patchers.unwrap(),
            &entry2.pod_patchers.unwrap()
        ));

        // Evict key from cache
        cache.remove(&tmpl);
        assert!(cache.get("default", "web-template").is_none());
    }

    #[test]
    fn test_template_cache_failed_compile_caching() {
        let cache = TemplateCache::new();
        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/securityContext",
                "value": { "privileged": true }
            }
        ]);
        let patch: json_patch::Patch = serde_json::from_value(patch_json).unwrap();
        let pod_tmpl = TemplateSpecPod {
            name: "web".into(),
            patch_spec: Some(patch),
            ..Default::default()
        };
        let tmpl = k8s_common::crd::Template {
            metadata: ObjectMeta {
                name: Some("blacklisted-template".into()),
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
        let entry = cache.get("default", "blacklisted-template").unwrap();
        assert!(entry.pod_patchers.is_err());
        assert!(
            entry
                .pod_patchers
                .as_ref()
                .unwrap_err()
                .contains("blacklisted")
        );
    }
}

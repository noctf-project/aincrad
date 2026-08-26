use std::collections::BTreeMap;

use crate::crd::CTFTemplateSpecParam;
use globset::GlobSet;
use json_patch::{Patch, PatchOperation};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
enum ValuePathSegment {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone)]
struct TemplateBinding {
    op_index: usize,
    value_path: Vec<ValuePathSegment>,
    template_id: String,
}

/// Validates RFC 6902 JSON Patches against a GlobSet blacklist and compiles
/// string template values using `upon` for evaluation at patch application time.
pub struct SpecPatcher {
    engine: upon::Engine<'static>,
    patch: Patch,
    bindings: Vec<TemplateBinding>,
}

impl std::fmt::Debug for SpecPatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpecPatcher")
            .field("patch", &self.patch)
            .field("bindings", &self.bindings)
            .finish()
    }
}

/// Standalone helper function converting a slice of `CTFTemplateSpecParam` into a `BTreeMap<String, String>`.
pub fn params_to_map(params: &[CTFTemplateSpecParam]) -> BTreeMap<String, String> {
    params
        .iter()
        .map(|p| (p.name.clone(), p.value.clone()))
        .collect()
}

impl SpecPatcher {
    /// Creates a new `SpecPatcher`:
    /// - Checks all patch operations (paths and source paths) against `blacklist`.
    /// - Compiles any string template values found in `patch` using `upon`.
    pub fn new(blacklist: &GlobSet, patch: Patch) -> Result<Self, String> {
        // Validate all patch operations against the blacklist
        for op in &patch.0 {
            let path = match op {
                PatchOperation::Add(op) => op.path.as_str(),
                PatchOperation::Remove(op) => op.path.as_str(),
                PatchOperation::Replace(op) => op.path.as_str(),
                PatchOperation::Move(op) => {
                    if blacklist.is_match(op.from.as_str()) {
                        return Err(format!("patch source path '{}' is blacklisted", op.from));
                    }
                    op.path.as_str()
                }
                PatchOperation::Copy(op) => {
                    if blacklist.is_match(op.from.as_str()) {
                        return Err(format!("patch source path '{}' is blacklisted", op.from));
                    }
                    op.path.as_str()
                }
                PatchOperation::Test(op) => op.path.as_str(),
            };

            if blacklist.is_match(path) {
                return Err(format!("patch path '{path}' is blacklisted"));
            }
        }

        let mut engine = upon::Engine::new();
        let mut bindings = Vec::new();
        let mut counter = 0;

        // Traverse patch operations and compile embedded string templates
        for (op_idx, op) in patch.0.iter().enumerate() {
            let value_opt = match op {
                PatchOperation::Add(op) => Some(&op.value),
                PatchOperation::Replace(op) => Some(&op.value),
                PatchOperation::Test(op) => Some(&op.value),
                _ => None,
            };

            if let Some(val) = value_opt {
                collect_and_compile_strings(
                    val,
                    Vec::new(),
                    op_idx,
                    &mut engine,
                    &mut bindings,
                    &mut counter,
                )?;
            }
        }

        Ok(Self {
            engine,
            patch,
            bindings,
        })
    }

    /// Evaluates compiled string templates with `params` map and applies the patch to `spec`.
    pub fn apply<T, V>(&self, spec: &T, params: &BTreeMap<String, V>) -> Result<T, String>
    where
        T: Serialize + DeserializeOwned,
        V: Serialize,
    {
        let mut string_patch = self.patch.clone();
        let mut coerced_patch = self.patch.clone();

        for binding in &self.bindings {
            let rendered_str = self
                .engine
                .template(&binding.template_id)
                .render(params)
                .to_string()
                .map_err(|e| format!("failed to render template: {e}"))?;

            let string_val = serde_json::Value::String(rendered_str.clone());

            let coerced_val = if let Ok(n) = rendered_str.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else if let Ok(f) = rendered_str.parse::<f64>() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::String(rendered_str.clone()))
            } else if let Ok(b) = rendered_str.parse::<bool>() {
                serde_json::Value::Bool(b)
            } else {
                serde_json::Value::String(rendered_str.clone())
            };

            let string_op_val = match &mut string_patch.0[binding.op_index] {
                PatchOperation::Add(op) => &mut op.value,
                PatchOperation::Replace(op) => &mut op.value,
                PatchOperation::Test(op) => &mut op.value,
                _ => continue,
            };

            if binding.value_path.is_empty() {
                *string_op_val = string_val;
            } else {
                set_json_value_at_path(string_op_val, &binding.value_path, string_val)?;
            }

            let coerced_op_val = match &mut coerced_patch.0[binding.op_index] {
                PatchOperation::Add(op) => &mut op.value,
                PatchOperation::Replace(op) => &mut op.value,
                PatchOperation::Test(op) => &mut op.value,
                _ => continue,
            };

            if binding.value_path.is_empty() {
                *coerced_op_val = coerced_val;
            } else {
                set_json_value_at_path(coerced_op_val, &binding.value_path, coerced_val)?;
            }
        }

        let base_doc =
            serde_json::to_value(spec).map_err(|e| format!("failed to serialize spec: {e}"))?;

        // First try string patch (preserves string fields like EnvVar values with numbers "8080")
        let mut doc = base_doc.clone();
        if json_patch::patch(&mut doc, &string_patch).is_ok() {
            if let Ok(res) = serde_json::from_value::<T>(doc) {
                return Ok(res);
            }
        }

        // Fall back to coerced patch (for numeric/boolean struct fields like activeDeadlineSeconds)
        let mut doc = base_doc;
        json_patch::patch(&mut doc, &coerced_patch)
            .map_err(|e| format!("failed to apply json patch: {e}"))?;
        serde_json::from_value(doc).map_err(|e| format!("failed to deserialize patched spec: {e}"))
    }
}

fn collect_and_compile_strings(
    val: &serde_json::Value,
    current_path: Vec<ValuePathSegment>,
    op_idx: usize,
    engine: &mut upon::Engine<'static>,
    bindings: &mut Vec<TemplateBinding>,
    counter: &mut usize,
) -> Result<(), String> {
    match val {
        serde_json::Value::String(s) => {
            let template_id = format!("t_{counter}");
            *counter += 1;
            engine
                .add_template(template_id.clone(), s.clone())
                .map_err(|e| format!("failed to compile template '{s}': {e}"))?;

            bindings.push(TemplateBinding {
                op_index: op_idx,
                value_path: current_path,
                template_id,
            });
        }
        serde_json::Value::Array(arr) => {
            for (i, elem) in arr.iter().enumerate() {
                let mut next_path = current_path.clone();
                next_path.push(ValuePathSegment::Index(i));
                collect_and_compile_strings(elem, next_path, op_idx, engine, bindings, counter)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let mut next_path = current_path.clone();
                next_path.push(ValuePathSegment::Key(k.clone()));
                collect_and_compile_strings(v, next_path, op_idx, engine, bindings, counter)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn set_json_value_at_path(
    root: &mut serde_json::Value,
    path: &[ValuePathSegment],
    new_val: serde_json::Value,
) -> Result<(), String> {
    let mut curr = root;
    for (i, seg) in path.iter().enumerate() {
        if i == path.len() - 1 {
            match (curr, seg) {
                (serde_json::Value::Object(map), ValuePathSegment::Key(k)) => {
                    map.insert(k.clone(), new_val);
                    return Ok(());
                }
                (serde_json::Value::Array(arr), ValuePathSegment::Index(idx)) => {
                    if let Some(elem) = arr.get_mut(*idx) {
                        *elem = new_val;
                        return Ok(());
                    }
                }
                _ => {}
            }
            return Err("invalid json path during template evaluation".to_string());
        } else {
            curr = match (curr, seg) {
                (serde_json::Value::Object(map), ValuePathSegment::Key(k)) => {
                    map.get_mut(k).ok_or("path key not found")?
                }
                (serde_json::Value::Array(arr), ValuePathSegment::Index(idx)) => {
                    arr.get_mut(*idx).ok_or("path index out of bounds")?
                }
                _ => return Err("invalid json path navigation".to_string()),
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use globset::{Glob, GlobSetBuilder};
    use k8s_openapi::api::core::v1::{Container, PodSpec};
    use serde_json::json;

    fn build_test_blacklist() -> GlobSet {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/containers/*/securityContext**").unwrap());
        builder.build().unwrap()
    }

    #[test]
    fn test_spec_patcher_template_rendering() {
        let blacklist = build_test_blacklist();
        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/env",
                "value": [
                    { "name": "SERVICE_URL", "value": "http://{{ params.instance }}-c-web:8080" }
                ]
            }
        ]);
        let patch: Patch = serde_json::from_value(patch_json).unwrap();

        let patcher = SpecPatcher::new(&blacklist, patch).unwrap();

        let base_spec = PodSpec {
            containers: vec![Container {
                name: "web".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let params = vec![CTFTemplateSpecParam {
            name: "instance".into(),
            value: "team-alpha".into(),
        }];
        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), params_to_map(&params));

        let patched: PodSpec = patcher.apply(&base_spec, &context_map).unwrap();
        let envs = patched.containers[0].env.as_ref().unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].name, "SERVICE_URL");
        assert_eq!(envs[0].value, Some("http://team-alpha-c-web:8080".into()));
    }

    #[test]
    fn test_spec_patcher_blacklisted_path_rejected() {
        let blacklist = build_test_blacklist();
        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/securityContext",
                "value": { "privileged": true }
            }
        ]);
        let patch: Patch = serde_json::from_value(patch_json).unwrap();

        let res = SpecPatcher::new(&blacklist, patch);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("blacklisted"));
    }

    #[test]
    fn test_spec_patcher_active_deadline_seconds_numeric_coercion() {
        let blacklist = build_test_blacklist();
        let patch_json = json!([
            {
                "op": "add",
                "path": "/activeDeadlineSeconds",
                "value": "{{ params.ttl }}"
            }
        ]);
        let patch: Patch = serde_json::from_value(patch_json).unwrap();
        let patcher = SpecPatcher::new(&blacklist, patch).unwrap();

        let base_spec = PodSpec::default();
        let params = vec![CTFTemplateSpecParam {
            name: "ttl".into(),
            value: "3600".into(),
        }];
        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), params_to_map(&params));

        let patched: PodSpec = patcher.apply(&base_spec, &context_map).unwrap();
        assert_eq!(patched.active_deadline_seconds, Some(3600));
    }

    #[test]
    fn test_spec_patcher_env_var_numeric_string_preservation() {
        let blacklist = build_test_blacklist();
        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/env",
                "value": [
                    { "name": "PORT", "value": "{{ params.port }}" }
                ]
            }
        ]);
        let patch: Patch = serde_json::from_value(patch_json).unwrap();
        let patcher = SpecPatcher::new(&blacklist, patch).unwrap();

        let base_spec = PodSpec {
            containers: vec![Container {
                name: "web".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let params = vec![CTFTemplateSpecParam {
            name: "port".into(),
            value: "8080".into(),
        }];
        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), params_to_map(&params));

        let patched: PodSpec = patcher.apply(&base_spec, &context_map).unwrap();
        let envs = patched.containers[0].env.as_ref().unwrap();
        assert_eq!(envs[0].name, "PORT");
        assert_eq!(envs[0].value, Some("8080".into()));
    }
}

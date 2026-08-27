use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use k8s_common::crd::{CTFInstance, CTFTemplateSpecPod};
use k8s_openapi::api::apps::v1::{ReplicaSet, ReplicaSetSpec};
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use sha2::{Digest, Sha256};

use crate::utils::HashWriter;
use crate::utils::naming::resource_name;
use crate::{
    Error, btreemap,
    planners::{Planner, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{
        INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL, RESTARTED_AT_ANNOTATION,
    },
};

/// Default GlobSet blacklist enforced for pod JSON patches.
pub static POD_PATCH_BLACKLIST: LazyLock<GlobSet> = LazyLock::new(|| {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new("/containers/*/securityContext**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostNetwork**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostPID**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostIPC**").expect("valid glob pattern"));
    builder.build().expect("valid globset")
});

pub struct ReplicaSetPlanner;

impl Planner for ReplicaSetPlanner {
    type Resource = ReplicaSet;

    fn plan(instance: &CTFInstance, template: &ResolvedTemplate) -> Result<Vec<ReplicaSet>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let instance_restarted_at = instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(RESTARTED_AT_ANNOTATION))
            .map(|s| s.as_str());

        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), &template.params_map);

        let mut desired = Vec::new();

        for pod_tmpl in &template.spec.pods {
            let pod_override = instance.spec.pods.iter().find(|p| p.name == pod_tmpl.name);
            let replicas = pod_override
                .map(|p| p.replicas)
                .unwrap_or(pod_tmpl.replicas);

            let patched_pod_spec = template.get_patched_pod_spec(pod_tmpl, &context_map)?;

            let rs_spec = build_replicaset_spec(
                instance_name,
                pod_tmpl,
                patched_pod_spec,
                replicas,
                instance_restarted_at,
            );

            let labels = btreemap! {
                MANAGED_BY_LABEL => MANAGED_BY_VALUE,
                INSTANCE_LABEL => instance_name,
                POD_LABEL => pod_tmpl.name.as_str(),
            };

            let mut rs = ReplicaSet {
                metadata: ObjectMeta {
                    name: None,
                    namespace: Some(ns.to_string()),
                    labels: Some(labels),
                    ..Default::default()
                },
                spec: Some(rs_spec),
                ..Default::default()
            };
            set_owner_ref(&mut rs, instance);
            desired.push(rs);
        }

        // As both replicasets should be managed together, they should be hashed together
        let indices = {
            let mut idx: Vec<usize> = (0..template.spec.pods.len()).collect();
            idx.sort_by_key(|&i| &template.spec.pods[i].name);
            idx
        };
        let mut hash = Sha256::new();
        let mut writer = HashWriter(&mut hash);
        for i in indices {
            let d = &desired[i];
            write!(writer, "pod/{}", template.spec.pods[i].name).unwrap();
            serde_json::to_writer(&mut writer, &d.spec.as_ref().map(|x| &x.template))
                .map_err(|e| format!("failed to serialize spec: {}", e))?;
            write!(writer, "\n").unwrap();
        }
        let digest = hash.finalize();
        let encoded = base32::encode(base32::Alphabet::Crockford, &digest).to_lowercase();
        let chars = &encoded[..10.min(encoded.len())];
        for (i, pod) in template.spec.pods.iter().enumerate() {
            desired[i].metadata.name = Some(resource_name(
                instance_name,
                &format!("{}-{}", pod.name, chars),
            ));
        }

        Ok(desired)
    }
}

/// Builds a ReplicaSetSpec for a specific pod within a CTFInstance.
///
/// - Replicas: Overridden or template replica count.
/// - Selector: Matches `INSTANCE_LABEL => instance_name` and `POD_LABEL => pod_name`
/// - PodSpec: The patched, evaluated PodSpec obtained from `ResolvedTemplate::get_patched_pod_spec`.
/// - RestartedAt: Optional timestamp annotation attached to the pod template.
pub fn build_replicaset_spec(
    instance_name: &str,
    pod_tmpl: &CTFTemplateSpecPod,
    patched_pod_spec: PodSpec,
    replicas: i32,
    restarted_at: Option<&str>,
) -> ReplicaSetSpec {
    let labels = btreemap! {
        MANAGED_BY_LABEL => MANAGED_BY_VALUE,
        INSTANCE_LABEL => instance_name,
        POD_LABEL => pod_tmpl.name.as_str(),
    };

    let selector = btreemap! {
        INSTANCE_LABEL => instance_name,
        POD_LABEL => pod_tmpl.name.as_str(),
    };

    let mut annotations = BTreeMap::new();
    if let Some(restarted_at) = restarted_at
        && !restarted_at.is_empty()
    {
        annotations.insert(
            RESTARTED_AT_ANNOTATION.to_string(),
            restarted_at.to_string(),
        );
    }

    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        }),
        spec: Some(patched_pod_spec),
    };

    ReplicaSetSpec {
        replicas: Some(replicas),
        selector: LabelSelector {
            match_labels: Some(selector),
            ..Default::default()
        },
        template: Some(pod_template),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{dummy_instance, dummy_resolved_template};
    use k8s_openapi::api::core::v1::Container;

    #[test]
    fn test_build_replicaset_spec() {
        let pod_tmpl = CTFTemplateSpecPod {
            name: "web".into(),
            replicas: 1,
            spec: PodSpec {
                containers: vec![Container {
                    name: "web".into(),
                    image: Some("nginx:latest".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let spec = build_replicaset_spec(
            "team-alpha",
            &pod_tmpl,
            pod_tmpl.spec.clone(),
            3,
            Some("2026-08-27T00:00:00Z"),
        );

        assert_eq!(spec.replicas, Some(3));

        let selector = spec.selector.match_labels.unwrap();
        assert_eq!(
            selector.get(INSTANCE_LABEL),
            Some(&"team-alpha".to_string())
        );
        assert_eq!(selector.get(POD_LABEL), Some(&"web".to_string()));

        let pod_template = spec.template.unwrap();
        let annotations = pod_template
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .as_ref()
            .unwrap();
        assert_eq!(
            annotations.get(RESTARTED_AT_ANNOTATION),
            Some(&"2026-08-27T00:00:00Z".to_string())
        );

        let pod_spec = pod_template.spec.unwrap();
        assert_eq!(pod_spec.containers[0].name, "web");
    }

    #[test]
    fn test_plan_replicasets() {
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);

        let desired = ReplicaSetPlanner::plan(&instance, &template).unwrap();
        assert_eq!(desired.len(), 1);
        let rs = &desired[0];
        assert!(
            rs.metadata
                .name
                .as_ref()
                .unwrap()
                .starts_with("chal-1-c-web-")
        );
        assert_eq!(rs.metadata.owner_references.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_plan_replicasets_restarted_at_changes_name() {
        let mut instance1 = dummy_instance("chal-1", None);
        let mut instance2 = dummy_instance("chal-1", None);

        let annotations1 = instance1
            .metadata
            .annotations
            .get_or_insert_with(Default::default);
        annotations1.insert(
            RESTARTED_AT_ANNOTATION.to_string(),
            "2026-08-27T01:00:00Z".to_string(),
        );

        let annotations2 = instance2
            .metadata
            .annotations
            .get_or_insert_with(Default::default);
        annotations2.insert(
            RESTARTED_AT_ANNOTATION.to_string(),
            "2026-08-27T02:00:00Z".to_string(),
        );

        let template = dummy_resolved_template(1);

        let desired1 = ReplicaSetPlanner::plan(&instance1, &template).unwrap();
        let desired2 = ReplicaSetPlanner::plan(&instance2, &template).unwrap();

        assert_ne!(desired1[0].metadata.name, desired2[0].metadata.name);
    }
}

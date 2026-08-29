use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use k8s_common::crd::{CTFInstance, CTFTemplateSpecPod};
use k8s_openapi::api::apps::v1::{ReplicaSet, ReplicaSetSpec};
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, LabelSelector, ObjectMeta};
use k8s_openapi::jiff::Timestamp;
use sha2::{Digest, Sha256};

use crate::utils::HashWriter;
use crate::utils::naming::resource_name;
use crate::{
    Context, Error, btreemap,
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
    const KIND: &'static str = "ReplicaSet";
    type Resource = ReplicaSet;

    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<ReplicaSet>, Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let instance_restarted_at = instance
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(RESTARTED_AT_ANNOTATION))
            .map(|s| s.as_str());

        let mut services_map = BTreeMap::new();
        for pod_tmpl in &template.spec.pods {
            let svc_name = resource_name(instance_name, &pod_tmpl.name);
            services_map.insert(pod_tmpl.name.clone(), svc_name);
        }

        let mut context_map = BTreeMap::new();
        context_map.insert("params".to_string(), &template.params_map);
        context_map.insert("services".to_string(), &services_map);

        let mut desired = Vec::new();

        for pod_tmpl in &template.spec.pods {
            let pod_override = instance.spec.pods.iter().find(|p| p.name == pod_tmpl.name);
            let replicas = pod_override
                .map(|p| p.replicas)
                .unwrap_or(pod_tmpl.replicas);

            let patched_pod_spec = template.get_patched_pod_spec(pod_tmpl, &context_map)?;
            let mut patched_pod_spec = patched_pod_spec;
            apply_image_aliases(&mut patched_pod_spec, &ctx.image_aliases);

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
            writeln!(writer).unwrap();
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

    fn check_status(
        instance: &CTFInstance,
        _ctx: &Context,
    ) -> Result<(Condition, Option<k8s_common::crd::CTFInstanceResources>), Error> {
        // TODO: Query ReplicaSet cache to verify ready_replicas >= desired_replicas
        Ok((
            Condition {
                type_: Self::KIND.to_string(),
                status: "Unknown".to_string(),
                reason: "ResourceManaged".to_string(),
                message: "Resource applied".to_string(),
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    Timestamp::now(),
                ),
                observed_generation: instance.metadata.generation,
            },
            None,
        ))
    }
}

fn apply_pod_defaults(pod_spec: &mut PodSpec) {
    if pod_spec.automount_service_account_token.is_none() {
        pod_spec.automount_service_account_token = Some(false);
    }
    if pod_spec.enable_service_links.is_none() {
        pod_spec.enable_service_links = Some(false);
    }
    if pod_spec.termination_grace_period_seconds.is_none() {
        pod_spec.termination_grace_period_seconds = Some(5);
    }

    for container in &mut pod_spec.containers {
        let limits = container
            .resources
            .get_or_insert_with(Default::default)
            .limits
            .get_or_insert_with(Default::default);
        limits
            .entry("ephemeral-storage".to_string())
            .or_insert_with(|| {
                k8s_openapi::apimachinery::pkg::api::resource::Quantity("256Mi".to_string())
            });
    }
}

/// Rewrites each container's image reference in place by resolving its leading
/// segment against the configured image aliases.
///
/// An alias maps a short repository key (e.g. `_challenges`) to a registry
/// prefix. Any image whose first path segment matches a key is rewritten to the
/// registry prefix followed by the remainder of the reference:
/// `_challenges/foo:tag` becomes `australia.se-registry.example/foo:tag`.
/// Images without a slash, or whose first segment is not aliased, are left
/// untouched. Applied to regular, init and ephemeral containers.
fn apply_image_aliases(pod_spec: &mut PodSpec, aliases: &BTreeMap<String, String>) {
    if aliases.is_empty() {
        return;
    }
    for container in pod_spec.containers.iter_mut() {
        rewrite_container_image(container, aliases);
    }
    if let Some(containers) = pod_spec.init_containers.as_mut() {
        for container in containers.iter_mut() {
            rewrite_container_image(container, aliases);
        }
    }
    if let Some(containers) = pod_spec.ephemeral_containers.as_mut() {
        for container in containers.iter_mut() {
            rewrite_container_image(container, aliases);
        }
    }
}

fn rewrite_container_image<T: ImageReference>(
    container: &mut T,
    aliases: &BTreeMap<String, String>,
) {
    let Some(image) = container.image() else {
        return;
    };
    rewrite_image(image, aliases);
}

fn rewrite_image(image: &mut String, aliases: &BTreeMap<String, String>) {
    let Some((key, rest)) = image.split_once('/') else {
        return;
    };
    if let Some(prefix) = aliases.get(key) {
        // Values are normalized (trailing slash stripped) at parse time, so the
        // prefix is always a clean registry prefix.
        *image = format!("{prefix}/{rest}");
    }
}

/// Trait for types exposing a mutable image reference (regular, init and
/// ephemeral containers).
trait ImageReference {
    fn image(&mut self) -> Option<&mut String>;
}

impl ImageReference for k8s_openapi::api::core::v1::Container {
    fn image(&mut self) -> Option<&mut String> {
        self.image.as_mut()
    }
}

impl ImageReference for k8s_openapi::api::core::v1::EphemeralContainer {
    fn image(&mut self) -> Option<&mut String> {
        self.image.as_mut()
    }
}

pub fn build_replicaset_spec(
    instance_name: &str,
    pod_tmpl: &CTFTemplateSpecPod,
    mut patched_pod_spec: PodSpec,
    replicas: i32,
    restarted_at: Option<&str>,
) -> ReplicaSetSpec {
    apply_pod_defaults(&mut patched_pod_spec);

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

    #[tokio::test]
    async fn test_plan_replicasets() {
        let instance = dummy_instance("chal-1", None);
        let template = dummy_resolved_template(1);
        let (_store, _ctx) = crate::test_utils::tests::dummy_context();

        let desired = ReplicaSetPlanner::plan(&instance, &template, &_ctx).unwrap();
        assert_eq!(desired.len(), 1);
        let rs = &desired[0];
        assert!(
            rs.metadata
                .name
                .as_ref()
                .unwrap()
                .starts_with("chal-1-web-")
        );
        assert_eq!(rs.metadata.owner_references.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_plan_replicasets_restarted_at_changes_name() {
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
        let (_store, _ctx) = crate::test_utils::tests::dummy_context();

        let desired1 = ReplicaSetPlanner::plan(&instance1, &template, &_ctx).unwrap();
        let desired2 = ReplicaSetPlanner::plan(&instance2, &template, &_ctx).unwrap();

        assert_ne!(desired1[0].metadata.name, desired2[0].metadata.name);
    }

    #[test]
    fn test_pod_defaults_injection() {
        let mut pod_spec = PodSpec {
            containers: vec![k8s_openapi::api::core::v1::Container {
                name: "web".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        apply_pod_defaults(&mut pod_spec);

        assert_eq!(pod_spec.automount_service_account_token, Some(false));
        assert_eq!(pod_spec.enable_service_links, Some(false));
        assert_eq!(pod_spec.termination_grace_period_seconds, Some(5));
        let limits = pod_spec.containers[0]
            .resources
            .as_ref()
            .unwrap()
            .limits
            .as_ref()
            .unwrap();
        assert_eq!(limits.get("ephemeral-storage").unwrap().0, "256Mi");

        // Ensure explicit overrides in template are preserved
        let mut custom_pod_spec = PodSpec {
            automount_service_account_token: Some(true),
            enable_service_links: Some(true),
            termination_grace_period_seconds: Some(30),
            ..Default::default()
        };
        apply_pod_defaults(&mut custom_pod_spec);

        assert_eq!(custom_pod_spec.automount_service_account_token, Some(true));
        assert_eq!(custom_pod_spec.enable_service_links, Some(true));
        assert_eq!(custom_pod_spec.termination_grace_period_seconds, Some(30));
    }

    #[test]
    fn test_apply_image_aliases_containers_and_init() {
        let mut aliases = BTreeMap::new();
        aliases.insert("_challenges".to_string(), "reg.example/infra".to_string());
        aliases.insert("_infra".to_string(), "reg.example/chal".to_string());

        let mut pod_spec = PodSpec {
            containers: vec![
                k8s_openapi::api::core::v1::Container {
                    name: "web".into(),
                    image: Some("_challenges/foo:tag".into()),
                    ..Default::default()
                },
                k8s_openapi::api::core::v1::Container {
                    name: "plain".into(),
                    image: Some("nginx:latest".into()),
                    ..Default::default()
                },
            ],
            init_containers: Some(vec![k8s_openapi::api::core::v1::Container {
                name: "init".into(),
                image: Some("_infra/setup:v1".into()),
                ..Default::default()
            }]),
            ephemeral_containers: Some(vec![k8s_openapi::api::core::v1::EphemeralContainer {
                name: "debug".into(),
                image: Some("_challenges/sidecar:1".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };

        apply_image_aliases(&mut pod_spec, &aliases);

        assert_eq!(
            pod_spec.containers[0].image.as_deref(),
            Some("reg.example/infra/foo:tag")
        );
        assert_eq!(
            pod_spec.containers[1].image.as_deref(),
            Some("nginx:latest")
        );
        assert_eq!(
            pod_spec.init_containers.as_ref().unwrap()[0]
                .image
                .as_deref(),
            Some("reg.example/chal/setup:v1")
        );
        assert_eq!(
            pod_spec.ephemeral_containers.as_ref().unwrap()[0]
                .image
                .as_deref(),
            Some("reg.example/infra/sidecar:1")
        );
    }

    #[test]
    fn test_apply_image_aliases_unmatched_key_untouched() {
        let mut aliases = BTreeMap::new();
        aliases.insert("_challenges".to_string(), "reg.example/infra".to_string());

        let mut pod_spec = PodSpec {
            containers: vec![k8s_openapi::api::core::v1::Container {
                name: "web".into(),
                image: Some("_other/foo:tag".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        apply_image_aliases(&mut pod_spec, &aliases);
        assert_eq!(
            pod_spec.containers[0].image.as_deref(),
            Some("_other/foo:tag")
        );
    }

    #[test]
    fn test_apply_image_aliases_empty_map_noop() {
        let mut pod_spec = PodSpec {
            containers: vec![k8s_openapi::api::core::v1::Container {
                name: "web".into(),
                image: Some("_challenges/foo:tag".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        apply_image_aliases(&mut pod_spec, &BTreeMap::new());
        assert_eq!(
            pod_spec.containers[0].image.as_deref(),
            Some("_challenges/foo:tag")
        );
    }

    #[tokio::test]
    async fn test_plan_replicasets_with_services_context() {
        use k8s_common::patcher::SpecPatcher;
        use serde_json::json;
        use std::collections::HashMap;
        use std::sync::Arc;

        let patch_json = json!([
            {
                "op": "add",
                "path": "/containers/0/env/0/value",
                "value": "{{ services.db }}"
            }
        ]);
        let patch: json_patch::Patch = serde_json::from_value(patch_json).unwrap();
        let patcher = SpecPatcher::new(&POD_PATCH_BLACKLIST, patch).unwrap();

        let mut pod_patchers = HashMap::new();
        pod_patchers.insert("web".to_string(), Some(patcher));

        let pod_tmpl_web = CTFTemplateSpecPod {
            name: "web".into(),
            replicas: 1,
            spec: PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "web".into(),
                    env: Some(vec![k8s_openapi::api::core::v1::EnvVar {
                        name: "DB_HOST".into(),
                        value: None,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let pod_tmpl_db = CTFTemplateSpecPod {
            name: "db".into(),
            replicas: 1,
            ..Default::default()
        };

        let instance = dummy_instance("chal-web", None);
        let template = ResolvedTemplate {
            metadata: ObjectMeta::default(),
            spec: k8s_common::crd::CTFTemplateSpec {
                pods: vec![pod_tmpl_web, pod_tmpl_db],
                ..Default::default()
            },
            pod_patchers: Arc::new(pod_patchers),
            params_map: BTreeMap::new(),
        };

        let (_store, _ctx) = crate::test_utils::tests::dummy_context();
        let desired = ReplicaSetPlanner::plan(&instance, &template, &_ctx).unwrap();
        let web_rs = desired
            .iter()
            .find(|rs| {
                rs.metadata.labels.as_ref().unwrap().get(POD_LABEL) == Some(&"web".to_string())
            })
            .unwrap();
        let web_pod_spec = web_rs
            .spec
            .as_ref()
            .unwrap()
            .template
            .as_ref()
            .unwrap()
            .spec
            .as_ref()
            .unwrap();
        assert_eq!(
            web_pod_spec.containers[0].env.as_ref().unwrap()[0]
                .value
                .as_deref(),
            Some("chal-web-db")
        );
    }
}

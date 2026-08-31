use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use k8s_common::RESOURCE_LABEL;
use k8s_common::crd::{CTFInstance, CTFTemplateSpecPod};
use k8s_openapi::api::apps::v1::{ReplicaSet, ReplicaSetSpec};
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, LabelSelector, ObjectMeta};
use k8s_openapi::jiff::Timestamp;
use sha2::{Digest, Sha256};

use crate::planners::get_services_map;
use crate::utils::HashWriter;
use crate::utils::naming::resource_name;
use crate::{
    Context, Error, btreemap,
    planners::{Planner, set_owner_ref},
    reconcilers::template::ResolvedTemplate,
    utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, RESTARTED_AT_ANNOTATION},
};

/// Default GlobSet blacklist enforced for pod JSON patches.
pub static POD_PATCH_BLACKLIST: LazyLock<GlobSet> = LazyLock::new(|| {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new("/containers/*/securityContext**").expect("valid glob pattern"));
    // Container ports define the exposed topology (Services, routes); templating
    // them lets per-instance values desync from what is actually routed.
    builder.add(Glob::new("/containers/*/ports**").expect("valid glob pattern"));
    builder.add(Glob::new("/initContainers/*/ports**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostNetwork**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostPID**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostIPC**").expect("valid glob pattern"));
    builder.build().expect("valid globset")
});

/// Blacklist enforced for route policy JSON patches. Empty: all policy fields are author-owned.
pub static ROUTE_POLICY_PATCH_BLACKLIST: LazyLock<GlobSet> =
    LazyLock::new(|| GlobSetBuilder::new().build().expect("valid globset"));

pub struct ReplicaSetPlanner;

impl Planner for ReplicaSetPlanner {
    const KIND: &'static str = "ReplicaSet";

    type Resource = ReplicaSet;

    fn cache(ctx: &Context) -> Option<&crate::cache::ResourceCache<Self::Resource>> {
        Some(&ctx.caches.replica_sets)
    }

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

        let mut context_map = BTreeMap::new();
        let services = get_services_map(template, instance_name);
        context_map.insert("params".to_string(), &template.params_map);
        context_map.insert("services".to_string(), &services);

        let mut desired = Vec::new();

        for pod_tmpl in &template.spec.pods {
            let pod_override = instance.spec.pods.iter().find(|p| p.name == pod_tmpl.name);
            let replicas = pod_override
                .map(|p| p.replicas)
                .unwrap_or(pod_tmpl.replicas);

            let mut patched_pod_spec = template.get_patched_pod_spec(pod_tmpl, &context_map)?;
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
                RESOURCE_LABEL => pod_tmpl.name.as_str(),
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
        ctx: &Context,
    ) -> Result<(Condition, Option<k8s_common::crd::CTFInstanceResources>), Error> {
        let instance_name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

        let cached_entries = ctx.caches.replica_sets.for_instance(ns, instance_name);
        if cached_entries.is_empty() {
            return Ok((
                Condition {
                    type_: Self::KIND.to_string(),
                    status: "False".to_string(),
                    reason: "Pending".to_string(),
                    message: "ReplicaSets not yet present in cache".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        Timestamp::now(),
                    ),
                    observed_generation: instance.metadata.generation,
                },
                None,
            ));
        }

        let mut total_desired = 0;
        let mut total_ready = 0;
        let mut all_available = true;

        for entry in &cached_entries {
            let desired = entry.value.replicas;
            let ready = entry.value.ready_replicas.unwrap_or(0);
            total_desired += desired;
            total_ready += ready;

            // A ReplicaSet is available if at least 1 replica is ready (or desired is 0).
            if desired > 0 && ready < 1 {
                all_available = false;
            }
        }

        // Verify that every previously recorded expected child ReplicaSet still exists in cache
        if let Some(expected) = instance
            .status
            .as_ref()
            .and_then(|s| s.children.get(Self::KIND))
        {
            for exp in expected {
                if !cached_entries.iter().any(|e| &e.name == exp) {
                    all_available = false;
                }
            }
        }

        let (status, reason) = if all_available {
            ("True", "Available")
        } else {
            ("False", "Unavailable")
        };

        Ok((
            Condition {
                type_: Self::KIND.to_string(),
                status: status.to_string(),
                reason: reason.to_string(),
                message: format!("{total_ready}/{total_desired} pod replicas ready"),
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
        RESOURCE_LABEL => pod_tmpl.name.as_str(),
    };

    let selector = btreemap! {
        INSTANCE_LABEL => instance_name,
        RESOURCE_LABEL => pod_tmpl.name.as_str(),
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
    use crate::test_utils::tests::dummy_context;
    use crate::test_utils::tests::{dummy_instance, dummy_resolved_template};
    use k8s_openapi::api::core::v1::Container;

    #[tokio::test]
    async fn test_cached_names_returns_instance_replica_sets() {
        let (_store, ctx) = dummy_context();
        let rs = ReplicaSet {
            metadata: ObjectMeta {
                name: Some("chal-1-web-abc".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-1",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ReplicaSetSpec::default()),
            status: Some(k8s_openapi::api::apps::v1::ReplicaSetStatus::default()),
        };
        ctx.caches
            .replica_sets
            .handle(&kube::runtime::watcher::Event::Apply(rs));

        let instance = dummy_instance("chal-1", None);
        let names = ReplicaSetPlanner::cached_names(&instance, &ctx).unwrap();
        assert_eq!(
            names,
            vec!["chal-1-web-abc".to_string()],
            "cached_names must surface replica sets owned by the instance"
        );
    }

    #[tokio::test]
    async fn test_cached_names_ignores_other_instances() {
        let (_store, ctx) = dummy_context();
        let rs = ReplicaSet {
            metadata: ObjectMeta {
                name: Some("chal-2-web-abc".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(crate::btreemap! {
                    INSTANCE_LABEL => "chal-2",
                    RESOURCE_LABEL => "web",
                }),
                ..Default::default()
            },
            spec: Some(ReplicaSetSpec::default()),
            status: None,
        };
        ctx.caches
            .replica_sets
            .handle(&kube::runtime::watcher::Event::Apply(rs));

        let instance = dummy_instance("chal-1", None);
        let names = ReplicaSetPlanner::cached_names(&instance, &ctx).unwrap();
        assert!(
            names.is_empty(),
            "another instance's replica sets must not be surfaced"
        );
    }

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
        assert_eq!(selector.get(RESOURCE_LABEL), Some(&"web".to_string()));

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
            route_patchers: Arc::new(std::collections::HashMap::new()),
            params_map: BTreeMap::new(),
        };

        let (_store, _ctx) = crate::test_utils::tests::dummy_context();
        let desired = ReplicaSetPlanner::plan(&instance, &template, &_ctx).unwrap();
        let web_rs = desired
            .iter()
            .find(|rs| {
                rs.metadata.labels.as_ref().unwrap().get(RESOURCE_LABEL) == Some(&"web".to_string())
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

    #[test]
    fn test_pod_patch_blacklist_blocks_ports() {
        let blocked = [
            "/containers/0/ports",
            "/containers/0/ports/0/containerPort",
            "/initContainers/0/ports",
            "/initContainers/0/ports/0/containerPort",
        ];
        for path in blocked {
            assert!(
                POD_PATCH_BLACKLIST.is_match(path),
                "path '{path}' must be blacklisted"
            );
        }

        let allowed = [
            "/containers/0/env/0/value",
            "/activeDeadlineSeconds",
            "/containers/0/resources",
        ];
        for path in allowed {
            assert!(
                !POD_PATCH_BLACKLIST.is_match(path),
                "path '{path}' must not be blacklisted"
            );
        }
    }

    #[tokio::test]
    async fn test_check_status_evaluates_replica_availability() {
        use k8s_openapi::api::apps::v1::ReplicaSetStatus;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = crate::test_utils::tests::dummy_context();
        let instance = dummy_instance("chal-1", None);

        // Initially no ReplicaSets in cache -> False
        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Pending");

        // Seed ReplicaSet with ready_replicas = 0 < desired (1) -> False
        let mut rs = ReplicaSet::default();
        rs.metadata.name = Some("chal-1-web".to_string());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs.status = Some(ReplicaSetStatus {
            ready_replicas: Some(0),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs.clone()));

        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Unavailable");

        // Update ReplicaSet with ready_replicas = 1 -> True
        rs.status = Some(ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs));

        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Available");
    }

    #[tokio::test]
    async fn test_check_status_multi_replicaset_partial_and_full_readiness() {
        use k8s_openapi::api::apps::v1::ReplicaSetStatus;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = crate::test_utils::tests::dummy_context();
        let instance = dummy_instance("chal-1", None);

        // Seed web: 2/2 ready
        let mut rs_web = ReplicaSet::default();
        rs_web.metadata.name = Some("chal-1-web".to_string());
        rs_web.metadata.namespace = Some("default".to_string());
        rs_web.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs_web.status = Some(ReplicaSetStatus {
            ready_replicas: Some(2),
            replicas: 2,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs_web));

        // Seed db: 0/1 ready
        let mut rs_db = ReplicaSet::default();
        rs_db.metadata.name = Some("chal-1-db".to_string());
        rs_db.metadata.namespace = Some("default".to_string());
        rs_db.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "db",
        });
        rs_db.status = Some(ReplicaSetStatus {
            ready_replicas: Some(0),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs_db.clone()));

        // Partial readiness -> False (2/3 ready)
        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Unavailable");
        assert_eq!(cond.message, "2/3 pod replicas ready");

        // Update db: 1/1 ready -> True (3/3 ready)
        rs_db.status = Some(ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs_db));

        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Available");
        assert_eq!(cond.message, "3/3 pod replicas ready");
    }

    #[tokio::test]
    async fn test_check_status_partial_replicas_at_least_one_ready_is_available() {
        use k8s_openapi::api::apps::v1::ReplicaSetStatus;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = crate::test_utils::tests::dummy_context();
        let instance = dummy_instance("chal-1", None);

        // Seed web: desired 3, ready 1 (at least 1 is ready -> Available)
        let mut rs_web = ReplicaSet::default();
        rs_web.metadata.name = Some("chal-1-web".to_string());
        rs_web.metadata.namespace = Some("default".to_string());
        rs_web.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs_web.status = Some(ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 3,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs_web));

        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Available");
        assert_eq!(cond.message, "1/3 pod replicas ready");
    }

    #[tokio::test]
    async fn test_check_status_zero_replicas_is_available() {
        use k8s_openapi::api::apps::v1::ReplicaSetStatus;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = crate::test_utils::tests::dummy_context();
        let instance = dummy_instance("chal-1", None);

        let mut rs = ReplicaSet::default();
        rs.metadata.name = Some("chal-1-worker".to_string());
        rs.metadata.namespace = Some("default".to_string());
        rs.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "worker",
        });
        rs.status = Some(ReplicaSetStatus {
            ready_replicas: None,
            replicas: 0,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs));

        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Available");
        assert_eq!(cond.message, "0/0 pod replicas ready");
    }

    #[tokio::test]
    async fn test_check_status_missing_expected_child_evaluates_unavailable() {
        use k8s_openapi::api::apps::v1::ReplicaSetStatus;
        use kube::runtime::watcher::Event;

        let (_store, ctx) = crate::test_utils::tests::dummy_context();
        let mut instance = dummy_instance("chal-1", None);

        // Record expected ReplicaSets in status.children: web and db
        instance.status = Some(k8s_common::crd::CTFInstanceStatus {
            children: crate::btreemap! {
                "ReplicaSet".to_string() => vec!["chal-1-web".to_string(), "chal-1-db".to_string()],
            },
            ..Default::default()
        });

        // Seed ONLY web (1/1 ready) in cache, db is missing
        let mut rs_web = ReplicaSet::default();
        rs_web.metadata.name = Some("chal-1-web".to_string());
        rs_web.metadata.namespace = Some("default".to_string());
        rs_web.metadata.labels = Some(crate::btreemap! {
            crate::utils::labels::NAMESPACE_LABEL => "default",
            crate::utils::labels::INSTANCE_LABEL => "chal-1",
            crate::utils::labels::RESOURCE_LABEL => "web",
        });
        rs_web.status = Some(ReplicaSetStatus {
            ready_replicas: Some(1),
            replicas: 1,
            ..Default::default()
        });
        ctx.caches.replica_sets.handle(&Event::Apply(rs_web));

        // Because db is missing from cache, condition must evaluate to Unavailable
        let (cond, _) = ReplicaSetPlanner::check_status(&instance, &ctx).unwrap();
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Unavailable");
    }
}

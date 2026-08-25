use globset::{Glob, GlobSet, GlobSetBuilder};
use k8s_common::crd::CTFTemplateSpecPod;
use k8s_openapi::api::apps::v1::ReplicaSetSpec;
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use std::sync::LazyLock;

use crate::btreemap;
use crate::utils::labels::{INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, POD_LABEL};

/// Default GlobSet blacklist enforced for pod JSON patches.
pub static POD_PATCH_BLACKLIST: LazyLock<GlobSet> = LazyLock::new(|| {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new("/containers/*/securityContext**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostNetwork**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostPID**").expect("valid glob pattern"));
    builder.add(Glob::new("/hostIPC**").expect("valid glob pattern"));
    builder.build().expect("valid globset")
});

/// Builds a ReplicaSetSpec for a specific pod within a CTFInstance.
///
/// - Replicas: Overridden or template replica count.
/// - Selector: Matches `INSTANCE_LABEL => instance_name` and `POD_LABEL => pod_name`
/// - PodSpec: The patched, evaluated PodSpec obtained from `ResolvedTemplate::get_patched_pod_spec`.
pub fn build_replicaset_spec(
    instance_name: &str,
    pod_tmpl: &CTFTemplateSpecPod,
    patched_pod_spec: PodSpec,
    replicas: i32,
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

    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels),
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

        let spec = build_replicaset_spec("team-alpha", &pod_tmpl, pod_tmpl.spec.clone(), 3);

        assert_eq!(spec.replicas, Some(3));

        let selector = spec.selector.match_labels.unwrap();
        assert_eq!(
            selector.get(INSTANCE_LABEL),
            Some(&"team-alpha".to_string())
        );
        assert_eq!(selector.get(POD_LABEL), Some(&"web".to_string()));

        let pod_spec = spec.template.unwrap().spec.unwrap();
        assert_eq!(pod_spec.containers[0].name, "web");
    }
}

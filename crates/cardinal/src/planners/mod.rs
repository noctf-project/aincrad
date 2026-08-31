pub mod helpers;
pub mod network_policy;
pub mod proxy_route;
pub mod replicaset;
pub mod service;

use std::collections::BTreeMap;

pub use helpers::apply_condition;
pub use helpers::validate_overrides;
pub use network_policy::NetworkPolicyPlanner;
pub use proxy_route::ProxyRoutePlanner;
pub use replicaset::ReplicaSetPlanner;
pub use service::ServicePlanner;

use k8s_common::crd::CTFInstance;
use kube::{Resource, core::NamespaceResourceScope};
use serde::{Serialize, de::DeserializeOwned};

use crate::cache::{ResourceCache, ResourceProjection};
use crate::utils::naming::resource_name;
use crate::{Context, Error, reconcilers::template::ResolvedTemplate};

/// Pure trait for declaring the desired state of a child Kubernetes resource type.
pub trait Planner {
    const KIND: &'static str;

    type Resource: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
        + ResourceProjection
        + Clone
        + DeserializeOwned
        + Serialize
        + std::fmt::Debug
        + Send
        + Sync
        + 'static;

    /// Pure planning function that returns all desired resources for this instance and template.
    fn plan(
        instance: &CTFInstance,
        template: &ResolvedTemplate,
        ctx: &Context,
    ) -> Result<Vec<Self::Resource>, Error>;

    /// Returns the cache tracking this resource type, if tracked in memory.
    fn cache(ctx: &Context) -> Option<&ResourceCache<Self::Resource>> {
        let _ = ctx;
        None
    }

    /// Returns the object names of this kind owned by `instance` as known to the
    /// cache. Default implementation queries `Self::cache`.
    fn cached_names(instance: &CTFInstance, ctx: &Context) -> Option<Vec<String>> {
        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let name = instance.metadata.name.as_deref().unwrap_or("unknown");
        Self::cache(ctx).map(|c| c.names(ns, name))
    }

    /// Evaluates this resource's readiness and any status payload it contributes.
    ///
    /// Returns the resource's condition (status "True"/"False"/"Unknown"), plus an
    /// optional typed `CTFInstanceResources` in which the planner sets only its own
    /// fields. `None` means the resource owns no extra status data.
    fn check_status(
        instance: &CTFInstance,
        ctx: &Context,
    ) -> Result<
        (
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition,
            Option<k8s_common::crd::CTFInstanceResources>,
        ),
        Error,
    > {
        let now = k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        );

        let Some(cache) = Self::cache(ctx) else {
            return Ok((
                k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                    type_: Self::KIND.to_string(),
                    status: "Unknown".to_string(),
                    reason: "ResourceManaged".to_string(),
                    message: "Resource applied".to_string(),
                    last_transition_time: now,
                    observed_generation: instance.metadata.generation,
                },
                None,
            ));
        };

        let ns = instance.metadata.namespace.as_deref().unwrap_or("default");
        let name = instance.metadata.name.as_deref().unwrap_or("unknown");
        let cached_entries = cache.for_instance(ns, name);

        let expected_names = instance
            .status
            .as_ref()
            .and_then(|s| s.children.get(Self::KIND));

        let (status, reason, message) = if let Some(expected) = expected_names {
            let mut missing = Vec::new();
            for exp in expected {
                if !cached_entries.iter().any(|e| &e.name == exp) {
                    missing.push(exp.as_str());
                }
            }
            if missing.is_empty() {
                (
                    "True",
                    "Available",
                    format!(
                        "All {} {}(s) available",
                        expected.len(),
                        Self::KIND.to_lowercase()
                    ),
                )
            } else {
                (
                    "False",
                    "Unavailable",
                    format!("{}(s) missing: {}", Self::KIND, missing.join(", ")),
                )
            }
        } else if cached_entries.is_empty() {
            ("Unknown", "ResourceManaged", "Resource applied".to_string())
        } else {
            (
                "True",
                "Available",
                format!(
                    "All {} {}(s) available",
                    cached_entries.len(),
                    Self::KIND.to_lowercase()
                ),
            )
        };

        Ok((
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
                type_: Self::KIND.to_string(),
                status: status.to_string(),
                reason: reason.to_string(),
                message,
                last_transition_time: now,
                observed_generation: instance.metadata.generation,
            },
            None,
        ))
    }
}

/// Sets controller owner reference on a resource pointing to the CTFInstance.
pub fn set_owner_ref<K: Resource>(resource: &mut K, instance: &CTFInstance) {
    let meta = resource.meta_mut();
    meta.managed_fields = None;
    if let Some(owner) = instance.controller_owner_ref(&()) {
        meta.owner_references = Some(vec![owner]);
    }
}

pub fn get_services_map(
    template: &ResolvedTemplate,
    instance_name: &str,
) -> BTreeMap<String, String> {
    let mut services_map = BTreeMap::new();
    for pod_tmpl in &template.spec.pods {
        let svc_name = resource_name(instance_name, &pod_tmpl.name);
        services_map.insert(pod_tmpl.name.clone(), svc_name);
    }
    services_map
}

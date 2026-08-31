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

use crate::utils::naming::resource_name;
use crate::{Context, Error, reconcilers::template::ResolvedTemplate};

/// Pure trait for declaring the desired state of a child Kubernetes resource type.
pub trait Planner {
    const KIND: &'static str;

    type Resource: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
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

    /// Returns the object names of this kind owned by `instance` as known to the
    /// cache. `None` means this kind is not pruned; the cache query lets pruning
    /// diff against the live cluster without a per-reconcile API list.
    fn cached_names(instance: &CTFInstance, ctx: &Context) -> Option<Vec<String>> {
        let _ = (instance, ctx);
        None
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
    >;
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

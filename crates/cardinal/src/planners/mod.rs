pub mod network_policy;
pub mod proxy_route;
pub mod replicaset;
pub mod service;

pub use network_policy::NetworkPolicyPlanner;
pub use proxy_route::{PlannedRoutes, ProxyRoutePlanner, build_merged_route_spec};
pub use replicaset::ReplicaSetPlanner;
pub use service::ServicePlanner;

use k8s_common::crd::CTFInstance;
use kube::{Resource, core::NamespaceResourceScope};
use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, reconcilers::template::ResolvedTemplate};

/// Pure trait for declaring the desired state of a child Kubernetes resource type.
pub trait Planner {
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
    ) -> Result<Vec<Self::Resource>, Error>;
}

/// Sets controller owner reference on a resource pointing to the CTFInstance.
pub fn set_owner_ref<K: Resource>(resource: &mut K, instance: &CTFInstance) {
    let meta = resource.meta_mut();
    meta.managed_fields = None;
    if let Some(owner) = instance.controller_owner_ref(&()) {
        meta.owner_references = Some(vec![owner]);
    }
}

use std::collections::BTreeMap;

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "aincrad-cardinal";

pub const INSTANCE_LABEL: &str = "aincrad.noctf.dev/instance";
pub const NAMESPACE_LABEL: &str = "aincrad.noctf.dev/namespace";
pub const TEMPLATE_LABEL: &str = "aincrad.noctf.dev/template";
pub const RESOURCE_LABEL: &str = "aincrad.noctf.dev/resource";

pub const ROUTES_FINALIZER: &str = "aincrad.noctf.dev/routes";

pub const RESTARTED_AT_ANNOTATION: &str = "aincrad.noctf.dev/restartedAt";
pub const MIN_TEMPLATE_GENERATION_ANNOTATION: &str = "aincrad.noctf.dev/minTemplateGeneration";
pub const EXPIRES_AT_ANNOTATION: &str = "aincrad.noctf.dev/expiresAt";

/// Constructs standard selector labels for child resources belonging to a CTFInstance.
pub fn instance_labels(instance_name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    labels.insert(INSTANCE_LABEL.to_string(), instance_name.to_string());
    labels
}

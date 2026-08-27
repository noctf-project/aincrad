use crate::btreemap;
use std::collections::BTreeMap;

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "aincrad-cardinal";

pub const INSTANCE_LABEL: &str = "aincrad.noctf.dev/instance";
pub const TEMPLATE_LABEL: &str = "aincrad.noctf.dev/template";
pub const POD_LABEL: &str = "aincrad.noctf.dev/pod";

pub const RESTARTED_AT_ANNOTATION: &str = "aincrad.noctf.dev/restartedAt";

/// Constructs standard selector labels for child resources belonging to a CTFInstance.
pub fn instance_labels(instance_name: &str) -> BTreeMap<String, String> {
    btreemap! {
        MANAGED_BY_LABEL => MANAGED_BY_VALUE,
        INSTANCE_LABEL => instance_name,
    }
}

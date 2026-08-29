use k8s_common::crd::CTFInstanceStatus;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

/// Adds or replaces a status condition by type.
pub fn apply_condition(status: &mut CTFInstanceStatus, condition: Condition) {
    if let Some(pos) = status.conditions.iter_mut().find(|c| c.type_ == condition.type_) {
        *pos = condition;
    } else {
        status.conditions.push(condition);
    }
}

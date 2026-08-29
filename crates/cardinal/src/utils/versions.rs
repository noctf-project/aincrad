use k8s_common::crd::CTFInstance;

use crate::utils::labels::MIN_TEMPLATE_GENERATION_ANNOTATION;

/// Returns true when a synced instance must re-apply against a newer template
/// generation.
///
/// An instance only needs upgrading when it tracks the template (`spec.sync`)
/// and its last applied template generation is older than the template's current
/// one. `minTemplateGeneration` acts as a floor: the instance only upgrades once
/// the template's current generation has reached it, allowing instances to hold
/// at an older template revision until the annotation is raised or the template
/// catches up. A missing or non-positive annotation defers entirely to the
/// `current > observed` comparison. Non-synced instances never require an
/// upgrade.
pub fn requires_template_upgrade(template_generation: Option<i64>, instance: &CTFInstance) -> bool {
    if !instance.spec.sync {
        return false;
    }

    let Some(current) = template_generation else {
        return false;
    };

    let observed = instance.status.as_ref().and_then(|s| s.template_generation);
    match observed {
        Some(o) if o >= current => return false,
        // A missing observed generation is treated as out of sync so failed or
        // never-reconciled instances are still picked up for their first apply.
        _ => {}
    }

    let min = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(MIN_TEMPLATE_GENERATION_ANNOTATION))
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&g| g > 0);

    min.is_none_or(|m| current >= m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFInstanceSpec, CTFInstanceStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn instance(sync: bool, observed: Option<i64>) -> CTFInstance {
        CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "tmpl".into(),
                sync,
                ..Default::default()
            },
            status: observed.map(|g| CTFInstanceStatus {
                template_generation: Some(g),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn non_synced_never_upgrades() {
        let inst = instance(false, Some(1));
        assert!(!requires_template_upgrade(Some(5), &inst));
    }

    #[test]
    fn caught_up_does_not_upgrade() {
        let inst = instance(true, Some(3));
        assert!(!requires_template_upgrade(Some(3), &inst));
        assert!(!requires_template_upgrade(Some(2), &inst));
    }

    #[test]
    fn newer_template_upgrades() {
        let inst = instance(true, Some(1));
        assert!(requires_template_upgrade(Some(2), &inst));
    }

    #[test]
    fn missing_observed_is_out_of_sync() {
        let inst = instance(true, None);
        assert!(requires_template_upgrade(Some(1), &inst));
        assert!(!requires_template_upgrade(None, &inst));
    }

    #[test]
    fn min_floor_gates_upgrade() {
        let mut inst = instance(true, Some(1));
        // Without an annotation it upgrades when current > observed.
        assert!(requires_template_upgrade(Some(2), &inst));
        assert!(!requires_template_upgrade(Some(1), &inst));

        // Pin to generation 4: only upgrade once the template reaches it.
        inst.metadata.annotations = Some(
            [(
                MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "4".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        assert!(!requires_template_upgrade(Some(2), &inst));
        assert!(!requires_template_upgrade(Some(3), &inst));
        assert!(requires_template_upgrade(Some(4), &inst));
        assert!(requires_template_upgrade(Some(5), &inst));
    }

    #[test]
    fn min_floor_ignores_invalid_or_non_positive() {
        let mut inst = instance(true, Some(1));
        inst.metadata.annotations = Some(
            [(
                MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "bogus".into(),
            )]
            .into_iter()
            .collect(),
        );
        assert!(requires_template_upgrade(Some(2), &inst));

        inst.metadata.annotations = Some(
            [(MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(), "0".into())]
                .into_iter()
                .collect(),
        );
        assert!(requires_template_upgrade(Some(2), &inst));
    }
}

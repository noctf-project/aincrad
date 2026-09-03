use k8s_common::{crd::CTFInstance, labels::MIN_TEMPLATE_GENERATION_ANNOTATION};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

/// Returns true when an instance must re-apply against its template.
///
/// Both the instance and the template may carry a `minTemplateGeneration`
/// annotation acting as a floor; the effective floor is the higher of the two.
/// When a floor is set the instance must have observed at least that generation,
/// so it upgrades whenever its observed generation is below the floor. This is
/// what lets a floor set on the template force even non-synced instances to
/// upgrade (cascading from the template update watcher).
///
/// When no floor is set, only synced instances track the template and upgrade
/// when the template's current generation is newer than the last observed one.
pub fn requires_template_upgrade(template: &ObjectMeta, instance: &CTFInstance) -> bool {
    let observed = instance.status.as_ref().and_then(|s| s.template_generation);

    if let Some(floor) = template_floor(template).max(instance_floor(instance)) {
        return observed.is_none_or(|o| o < floor);
    }

    let Some(current) = template.generation else {
        return false;
    };

    if !instance.spec.sync {
        return false;
    }
    observed.is_none_or(|o| o < current)
}

/// Parses the `minTemplateGeneration` floor from a template's metadata.
pub fn template_floor(template: &ObjectMeta) -> Option<i64> {
    min_generation_floor(template.annotations.as_ref())
}

/// Parses the `minTemplateGeneration` floor from an instance's annotations.
fn instance_floor(instance: &CTFInstance) -> Option<i64> {
    min_generation_floor(instance.metadata.annotations.as_ref())
}

/// Parses the `minTemplateGeneration` floor from an annotation map, ignoring
/// missing, non-numeric and non-positive values.
pub fn min_generation_floor(
    annotations: Option<&std::collections::BTreeMap<String, String>>,
) -> Option<i64> {
    annotations
        .and_then(|a| a.get(MIN_TEMPLATE_GENERATION_ANNOTATION))
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&g| g > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFInstanceSpec, CTFInstanceStatus, CTFTemplate, CTFTemplateSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn template(generation: Option<i64>, min: Option<i64>) -> CTFTemplate {
        CTFTemplate {
            metadata: ObjectMeta {
                name: Some("tmpl".into()),
                namespace: Some("default".into()),
                generation,
                annotations: min.map(|m| {
                    [(
                        MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                        m.to_string(),
                    )]
                    .into_iter()
                    .collect()
                }),
                ..Default::default()
            },
            spec: CTFTemplateSpec::default(),
            status: None,
        }
    }

    fn instance(sync: bool, observed: Option<i64>, min: Option<i64>) -> CTFInstance {
        CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst".into()),
                namespace: Some("default".into()),
                annotations: min.map(|m| {
                    [(
                        MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                        m.to_string(),
                    )]
                    .into_iter()
                    .collect()
                }),
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
    fn non_synced_never_upgrades_without_floor() {
        let tmpl = template(Some(5), None);
        let inst = instance(false, Some(1), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn caught_up_does_not_upgrade() {
        let tmpl = template(Some(3), None);
        let inst = instance(true, Some(3), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn newer_template_upgrades_synced() {
        let tmpl = template(Some(2), None);
        let inst = instance(true, Some(1), None);
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn missing_observed_is_out_of_sync() {
        let tmpl = template(Some(1), None);
        let mut inst = instance(true, None, None);
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        let no_gen = template(None, None);
        assert!(!requires_template_upgrade(&no_gen.metadata, &inst));

        inst.spec.sync = false;
        assert!(!requires_template_upgrade(&no_gen.metadata, &inst));
    }

    #[test]
    fn template_floor_forces_non_synced_upgrade() {
        // Template pins a floor of 4; a non-synced instance observed at 1 must
        // be forced up (break-glass cascade).
        let tmpl = template(Some(5), Some(4));
        let inst = instance(false, Some(1), None);
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        // Once observed reaches the floor it holds, even below the latest (5).
        let inst = instance(false, Some(4), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn effective_floor_is_max_of_template_and_instance() {
        // Template floor 3, instance floor 2 -> effective 3.
        let tmpl = template(Some(5), Some(3));
        let inst = instance(true, Some(2), Some(2));
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        // Template floor 2, instance floor 4 -> effective 4 (instance higher).
        let tmpl = template(Some(5), Some(2));
        let inst = instance(true, Some(3), Some(4));
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        // Observed 4 meets the effective floor 4, so no upgrade.
        let inst = instance(true, Some(4), Some(4));
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn floor_ignores_invalid_or_non_positive() {
        let tmpl = template(Some(2), None);
        let mut inst = instance(true, Some(1), None);
        inst.metadata.annotations = Some(
            [(
                MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "bogus".into(),
            )]
            .into_iter()
            .collect(),
        );
        // Invalid instance floor ignored -> falls back to synced current check.
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        inst.metadata.annotations = Some(
            [(MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(), "0".into())]
                .into_iter()
                .collect(),
        );
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));
    }
}

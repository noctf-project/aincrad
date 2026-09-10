use k8s_common::{crd::Instance, labels::MIN_TEMPLATE_GENERATION_ANNOTATION};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

/// Returns true when an instance must re-apply against its template.
///
/// Both the instance and the template may carry a `minTemplateGeneration`
/// annotation acting as a floor; the effective floor is the higher of the two.
/// When a floor is set the instance must have observed at least that generation,
/// so it upgrades whenever its observed generation is below the floor.
pub fn requires_template_upgrade(template: &ObjectMeta, instance: &Instance) -> bool {
    let observed = instance.status.as_ref().and_then(|s| s.template_generation);

    let Some(floor) = template_floor(template).max(instance_floor(instance)) else {
        return false;
    };

    observed.is_none_or(|o| o < floor)
}

/// Parses the `minTemplateGeneration` floor from a template's metadata.
pub fn template_floor(template: &ObjectMeta) -> Option<i64> {
    min_generation_floor(template.annotations.as_ref())
}

/// Parses the `minTemplateGeneration` floor from an instance's annotations.
fn instance_floor(instance: &Instance) -> Option<i64> {
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
    use k8s_common::crd::{InstanceSpec, InstanceStatus, Template, TemplateSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn template(generation: Option<i64>, min: Option<i64>) -> Template {
        Template {
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
            spec: TemplateSpec::default(),
            status: None,
        }
    }

    fn instance(observed: Option<i64>, min: Option<i64>) -> Instance {
        Instance {
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
            spec: InstanceSpec {
                template: "tmpl".into(),
                ..Default::default()
            },
            status: observed.map(|g| InstanceStatus {
                template_generation: Some(g),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn never_upgrades_without_floor() {
        let tmpl = template(Some(5), None);
        let inst = instance(Some(1), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn caught_up_to_floor_does_not_upgrade() {
        let tmpl = template(Some(5), Some(3));
        let inst = instance(Some(3), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn template_floor_forces_upgrade() {
        let tmpl = template(Some(5), Some(4));
        let inst = instance(Some(1), None);
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        let inst = instance(Some(4), None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn instance_floor_forces_upgrade() {
        let tmpl = template(Some(5), None);
        let inst = instance(Some(1), Some(3));
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        let inst = instance(Some(3), Some(3));
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn missing_observed_with_floor_requires_upgrade() {
        let tmpl = template(Some(5), Some(1));
        let inst = instance(None, None);
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn missing_observed_without_floor_does_not_upgrade() {
        let tmpl = template(Some(5), None);
        let inst = instance(None, None);
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn effective_floor_is_max_of_template_and_instance() {
        // Template floor 3, instance floor 2 -> effective 3.
        let tmpl = template(Some(5), Some(3));
        let inst = instance(Some(2), Some(2));
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        // Template floor 2, instance floor 4 -> effective 4 (instance higher).
        let tmpl = template(Some(5), Some(2));
        let inst = instance(Some(3), Some(4));
        assert!(requires_template_upgrade(&tmpl.metadata, &inst));

        // Observed 4 meets the effective floor 4, so no upgrade.
        let inst = instance(Some(4), Some(4));
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }

    #[test]
    fn floor_ignores_invalid_or_non_positive() {
        let tmpl = template(Some(2), None);
        let mut inst = instance(Some(1), None);
        inst.metadata.annotations = Some(
            [(
                MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(),
                "bogus".into(),
            )]
            .into_iter()
            .collect(),
        );
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));

        inst.metadata.annotations = Some(
            [(MIN_TEMPLATE_GENERATION_ANNOTATION.to_string(), "0".into())]
                .into_iter()
                .collect(),
        );
        assert!(!requires_template_upgrade(&tmpl.metadata, &inst));
    }
}

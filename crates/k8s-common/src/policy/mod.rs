use k8s_openapi::api::admissionregistration::v1::{
    MatchResources, NamedRuleWithOperations, ValidatingAdmissionPolicy,
    ValidatingAdmissionPolicyBinding, ValidatingAdmissionPolicyBindingSpec,
    ValidatingAdmissionPolicySpec, Validation,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::CustomResourceExt;

use crate::crd::{Instance, Template};
use crate::labels::{
    EXPIRES_AT_ANNOTATION, MIN_TEMPLATE_GENERATION_ANNOTATION, RESTARTED_AT_ANNOTATION,
};

/// Generates the ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding for instance annotations.
pub fn generate_instance_admission_policy()
-> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
    let policy_name = "cardinal-instance-metadata";

    let policy = ValidatingAdmissionPolicy {
        metadata: ObjectMeta {
            name: Some(policy_name.to_string()),
            ..Default::default()
        },
        spec: Some(ValidatingAdmissionPolicySpec {
            match_constraints: Some(MatchResources {
                resource_rules: Some(vec![NamedRuleWithOperations {
                    api_groups: Some(vec!["cardinal.noctf.dev".to_string()]),
                    api_versions: Some(vec!["v1".to_string()]),
                    operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                    resources: Some(vec![Instance::api_resource().plural.to_ascii_lowercase()]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            validations: Some(vec![
                Validation {
                    expression: format!(
                        "!has(object.metadata.annotations) || !('{RESTARTED_AT_ANNOTATION}' in object.metadata.annotations) || !format.datetime().validate(string(object.metadata.annotations['{RESTARTED_AT_ANNOTATION}'])).hasValue()"
                    ),
                    message: Some(format!(
                        "annotation '{RESTARTED_AT_ANNOTATION}' must be a valid RFC3339 date/time string"
                    )),
                    ..Default::default()
                },
                Validation {
                    expression: format!(
                        "!has(object.metadata.annotations) || !('{EXPIRES_AT_ANNOTATION}' in object.metadata.annotations) || object.metadata.annotations['{EXPIRES_AT_ANNOTATION}'] == 'auto' || !format.datetime().validate(string(object.metadata.annotations['{EXPIRES_AT_ANNOTATION}'])).hasValue()"
                    ),
                    message: Some(format!(
                        "annotation '{EXPIRES_AT_ANNOTATION}' must be 'auto' or a valid RFC3339 date/time string"
                    )),
                    ..Default::default()
                },
                Validation {
                    expression: format!(
                        "!has(object.metadata.annotations) || !('{MIN_TEMPLATE_GENERATION_ANNOTATION}' in object.metadata.annotations) || object.metadata.annotations['{MIN_TEMPLATE_GENERATION_ANNOTATION}'].matches(r'^[1-9][0-9]*$')"
                    ),
                    message: Some(format!(
                        "annotation '{MIN_TEMPLATE_GENERATION_ANNOTATION}' must be a positive integer"
                    )),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        status: None,
    };

    let binding = ValidatingAdmissionPolicyBinding {
        metadata: ObjectMeta {
            name: Some(format!("{policy_name}-binding")),
            ..Default::default()
        },
        spec: ValidatingAdmissionPolicyBindingSpec {
            policy_name: policy_name.to_string(),
            validation_actions: vec!["Deny".to_string()],
            ..Default::default()
        },
    };

    (policy, binding)
}

/// Generates the ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding for template annotations.
pub fn generate_template_admission_policy()
-> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
    let policy_name = "cardinal-template-metadata";

    let policy = ValidatingAdmissionPolicy {
        metadata: ObjectMeta {
            name: Some(policy_name.to_string()),
            ..Default::default()
        },
        spec: Some(ValidatingAdmissionPolicySpec {
            match_constraints: Some(MatchResources {
                resource_rules: Some(vec![NamedRuleWithOperations {
                    api_groups: Some(vec!["cardinal.noctf.dev".to_string()]),
                    api_versions: Some(vec!["v1".to_string()]),
                    operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                    resources: Some(vec![Template::api_resource().plural.to_ascii_lowercase()]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            validations: Some(vec![Validation {
                expression: format!(
                    "!has(object.metadata.annotations) || !('{MIN_TEMPLATE_GENERATION_ANNOTATION}' in object.metadata.annotations) || object.metadata.annotations['{MIN_TEMPLATE_GENERATION_ANNOTATION}'].matches(r'^[1-9][0-9]*$')"
                ),
                message: Some(format!(
                    "annotation '{MIN_TEMPLATE_GENERATION_ANNOTATION}' must be a positive integer"
                )),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    };

    let binding = ValidatingAdmissionPolicyBinding {
        metadata: ObjectMeta {
            name: Some(format!("{policy_name}-binding")),
            ..Default::default()
        },
        spec: ValidatingAdmissionPolicyBindingSpec {
            policy_name: policy_name.to_string(),
            validation_actions: vec!["Deny".to_string()],
            ..Default::default()
        },
    };

    (policy, binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_instance_admission_policy() {
        let (policy, binding) = generate_instance_admission_policy();
        assert_eq!(
            policy.metadata.name.as_deref(),
            Some("cardinal-instance-metadata")
        );
        assert_eq!(
            binding.metadata.name.as_deref(),
            Some("cardinal-instance-metadata-binding")
        );
        let validations = policy.spec.unwrap().validations.unwrap();
        assert_eq!(validations.len(), 3);
    }

    #[test]
    fn test_generate_template_admission_policy() {
        let (policy, binding) = generate_template_admission_policy();
        assert_eq!(
            policy.metadata.name.as_deref(),
            Some("cardinal-template-metadata")
        );
        assert_eq!(
            binding.metadata.name.as_deref(),
            Some("cardinal-template-metadata-binding")
        );
        let validations = policy.spec.unwrap().validations.unwrap();
        assert_eq!(validations.len(), 1);
    }
}

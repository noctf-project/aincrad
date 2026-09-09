use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use k8s_common::{
    crd::CTFTemplate,
    labels::{AVAILABLE_AT_ANNOTATION, MANAGED_BY_LABEL, MANAGED_BY_VALUE, TEMPLATE_LABEL},
};
use k8s_openapi::{
    api::networking::v1::NetworkPolicy,
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use kube::{
    Api, Resource,
    api::{DeleteParams, Patch, PatchParams},
    runtime::controller::Action,
};
use tracing::{error, info, warn};

use crate::{Context, Error, btreemap, controller::AVAILABILITY_LEAD_TIME};

pub async fn reconcile_template(
    template: Arc<CTFTemplate>,
    ctx: Arc<Context>,
) -> Result<Action, Error> {
    let name = template.metadata.name.as_deref().unwrap_or_default();
    let ns = template.metadata.namespace.as_deref().unwrap_or("default");
    let netpol_name = format!("{name}-tpl");

    let api: Api<NetworkPolicy> = Api::namespaced(ctx.client.clone(), ns);

    let (is_available, requeue_duration) = check_availability(&template);

    let desired_spec = if is_available {
        ctx.config.network_policies.template.available.as_ref()
    } else {
        ctx.config.network_policies.template.unavailable.as_ref()
    };

    if let Some(spec) = desired_spec {
        let mut policy_spec = spec.clone();
        policy_spec.pod_selector = Some(LabelSelector {
            match_labels: Some(btreemap! {
                TEMPLATE_LABEL.to_string() => name.to_string(),
            }),
            ..Default::default()
        });

        let mut meta = ObjectMeta {
            name: Some(netpol_name.clone()),
            namespace: Some(ns.to_string()),
            owner_references: template.controller_owner_ref(&()).map(|o| vec![o]),
            labels: Some(btreemap! {
                MANAGED_BY_LABEL.to_string() => MANAGED_BY_VALUE.to_string(),
                TEMPLATE_LABEL.to_string() => name.to_string(),
            }),
            ..Default::default()
        };
        meta.managed_fields = None;

        let policy = NetworkPolicy {
            metadata: meta,
            spec: Some(policy_spec),
        };

        api.patch(
            &netpol_name,
            &PatchParams::apply("cardinal-template-controller").force(),
            &Patch::Apply(&policy),
        )
        .await
        .map_err(|e| {
            Error::Custom(format!(
                "Failed to apply template NetPol {netpol_name}: {e}"
            ))
        })?;

        info!(
            template = %name,
            netpol = %netpol_name,
            available = is_available,
            "Applied template network policy"
        );
    } else {
        match api.delete(&netpol_name, &DeleteParams::default()).await {
            Ok(_) => {
                info!(
                    template = %name,
                    netpol = %netpol_name,
                    available = is_available,
                    "Wiped template network policy"
                );
            }
            Err(kube::Error::Api(ref err)) if err.code == 404 => {}
            Err(err) => {
                warn!(
                    template = %name,
                    netpol = %netpol_name,
                    error = %err,
                    "Failed to delete template network policy"
                );
            }
        }
    }

    match requeue_duration {
        Some(duration) => Ok(Action::requeue(duration)),
        None => Ok(Action::await_change()),
    }
}

pub fn error_policy(template: Arc<CTFTemplate>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = template.metadata.name.as_deref().unwrap_or_default();
    error!(template = %name, %error, "Error in template controller");
    Action::requeue(Duration::from_secs(15))
}

fn check_availability(template: &CTFTemplate) -> (bool, Option<Duration>) {
    let available_at_str = template
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(AVAILABLE_AT_ANNOTATION));

    let Some(ts_str) = available_at_str else {
        return (true, None);
    };

    match DateTime::parse_from_rfc3339(ts_str) {
        Ok(dt) => {
            let available_at_utc = dt.with_timezone(&Utc);
            let target_time = available_at_utc
                - chrono::Duration::seconds(AVAILABILITY_LEAD_TIME.as_secs() as i64);
            let now = Utc::now();
            if now >= target_time {
                (true, None)
            } else {
                let diff = target_time - now;
                let duration = diff
                    .to_std()
                    .unwrap_or(Duration::from_secs(1))
                    .max(Duration::from_secs(1));
                (false, Some(duration))
            }
        }
        Err(e) => {
            warn!(
                template = template.metadata.name.as_deref().unwrap_or_default(),
                annotation = ts_str,
                error = %e,
                "Invalid availableAt timestamp format; defaulting to available"
            );
            (true, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::CTFTemplateSpec;
    use std::collections::BTreeMap;

    fn test_template(annotations: Option<BTreeMap<String, String>>) -> CTFTemplate {
        let mut template = CTFTemplate::new("test-chal", CTFTemplateSpec::default());
        template.metadata.annotations = annotations;
        template
    }

    #[test]
    fn test_check_availability_no_annotation() {
        let template = test_template(None);
        let (avail, requeue) = check_availability(&template);
        assert!(avail);
        assert!(requeue.is_none());
    }

    #[test]
    fn test_check_availability_past_timestamp() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            AVAILABLE_AT_ANNOTATION.to_string(),
            "2020-01-01T00:00:00Z".to_string(),
        );
        let template = test_template(Some(annotations));
        let (avail, requeue) = check_availability(&template);
        assert!(avail);
        assert!(requeue.is_none());
    }

    #[test]
    fn test_check_availability_future_timestamp() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            AVAILABLE_AT_ANNOTATION.to_string(),
            "2099-01-01T00:00:00Z".to_string(),
        );
        let template = test_template(Some(annotations));
        let (avail, requeue) = check_availability(&template);
        assert!(!avail);
        assert!(requeue.is_some());
    }

    #[test]
    fn test_check_availability_within_lead_time() {
        let mut annotations = BTreeMap::new();
        // 15 seconds in future is within the 30-second lead time
        let near_future = Utc::now() + chrono::Duration::seconds(15);
        annotations.insert(
            AVAILABLE_AT_ANNOTATION.to_string(),
            near_future.to_rfc3339(),
        );
        let template = test_template(Some(annotations));
        let (avail, requeue) = check_availability(&template);
        assert!(avail);
        assert!(requeue.is_none());
    }
}

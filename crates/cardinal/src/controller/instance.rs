use std::{sync::Arc, time::Duration};

use k8s_common::crd::CTFInstance;
use kube::runtime::{Predicate, controller::Action, predicates};
use tracing::{error, instrument};

use crate::{Context, Error, reconcilers};

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    match crate::controller::phases::run(&instance, &ctx).await {
        Ok(action) => Ok(action),
        Err(err) => {
            let _ = reconcilers::status::reconcile_failure(&instance, &ctx, &err).await;
            Err(err)
        }
    }
}

pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");

    if let Error::Kube(kube::Error::Api(status)) = error
        && status.code == 404
    {
        tracing::debug!(name, "Instance already deleted from cluster");
        return Action::await_change();
    }

    error!(name, %error, "Reconciliation failed");

    match error {
        Error::RouteAllocationError(_) => Action::requeue(Duration::from_secs(30)),
        Error::TemplateBuildError(_) | Error::TemplateNotFound(_) | Error::KubeCommon(_) => {
            Action::await_change()
        }
        Error::Kube(e) => match e {
            kube::Error::Api(status) if status.code == 409 => {
                Action::requeue(Duration::from_millis(200))
            }
            kube::Error::HyperError(_) | kube::Error::HttpError(_) => {
                Action::requeue(Duration::from_secs(2))
            }
            kube::Error::Api(status) if status.code == 429 || status.code >= 500 => {
                Action::requeue(Duration::from_secs(10))
            }
            kube::Error::Api(_) => Action::await_change(),
            _ => Action::requeue(Duration::from_secs(30)),
        },
        _ => Action::requeue(Duration::from_secs(60)),
    }
}

/// Predicate for streaming CTFInstances into the controller. Includes deletion
/// state so finalizer cleanup reconciles (deletionTimestamp changes) are delivered
/// even when generation and annotations are untouched.
pub(crate) fn instance_predicate() -> impl Predicate<CTFInstance> {
    predicates::generation
        .combine(predicates::annotations)
        .combine(|obj: &CTFInstance| Some(u64::from(obj.metadata.deletion_timestamp.is_some())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::{
        dummy_context, dummy_ctx, dummy_instance, recording_kube_client,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use futures::StreamExt;
    use k8s_common::crd::{CTFInstanceSpec, CTFInstanceStatus, RouteBackend, RouteSpec};
    use k8s_common::labels::{EXPIRES_AT_ANNOTATION, RESTARTED_AT_ANNOTATION};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::WatchStreamExt;
    use kube::runtime::watcher::Error as WatcherError;

    #[tokio::test]
    async fn test_template_ready_wait_delivers_concurrent_send() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);

        let task = tokio::spawn(async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("template ready wait must not deadlock when send races the check")
            .unwrap();
    }

    #[tokio::test]
    async fn test_template_ready_wait_returns_immediately_when_already_ready() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        tx.send(true).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("template ready wait must return immediately when already ready");
    }

    #[tokio::test]
    async fn test_reconcile_no_expiration() {
        let (_store, ctx) = dummy_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_future_expiration() {
        let (_store, ctx) = dummy_context();
        let future_time = Utc::now() + ChronoDuration::seconds(120);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), future_time.to_rfc3339());

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_past_expiration() {
        let (_store, ctx) = dummy_context();
        let past_time = Utc::now() - ChronoDuration::seconds(60);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(EXPIRES_AT_ANNOTATION.to_string(), past_time.to_rfc3339());

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_deletion_timestamp() {
        let (_store, ctx) = dummy_context();
        let now = Utc::now();

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                deletion_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(now.timestamp()).unwrap(),
                )),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_deletion_timestamp_instances_are_delivered_to_controller() {
        let mut inst = dummy_instance("chal-1", None);
        inst.metadata.uid = Some("uid-1".to_string());
        inst.metadata.resource_version = Some("1".to_string());

        let mut dying = inst.clone();
        dying.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        dying.metadata.resource_version = Some("2".to_string());

        let events: Vec<Result<CTFInstance, WatcherError>> = vec![Ok(inst), Ok(dying)];
        let filtered = futures::stream::iter(events)
            .predicate_filter(instance_predicate(), Default::default());

        let items: Vec<CTFInstance> = filtered.map(|r| r.unwrap()).collect().await;
        assert_eq!(
            items.len(),
            2,
            "events for deleted instances must be delivered"
        );
        assert!(
            items
                .iter()
                .any(|i| i.metadata.deletion_timestamp.is_some()),
            "deleted instance must reach the reconcile loop"
        );
    }

    #[tokio::test]
    async fn test_spec_change_after_ready_reapplies_children() {
        let (client, log) = recording_kube_client();
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
                protocol: None,
            },
            port: Some(0),
            ..Default::default()
        };
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route]);

        let count_rs_patches = |log: &std::sync::Mutex<Vec<String>>| {
            log.lock()
                .unwrap()
                .iter()
                .filter(|s| s.starts_with("PATCH") && s.contains("/replicasets"))
                .count()
        };

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });

        reconcile(instance.clone(), ctx.clone()).await.unwrap();
        assert_eq!(
            count_rs_patches(&log),
            0,
            "ready + observed instance must not re-apply children"
        );

        log.lock().unwrap().clear();
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(2);
        inst.spec
            .params
            .push(k8s_common::crd::CTFInstanceSpecParam {
                name: "FLAG".into(),
                value: k8s_common::crd::PatchValue::Value("CTF{rotated}".into()),
            });

        reconcile(instance, ctx).await.unwrap();
        assert!(
            count_rs_patches(&log) > 0,
            "children must be re-applied after the spec generation changes"
        );
    }

    #[tokio::test]
    async fn test_restart_annotation_after_ready_reapplies_children() {
        let (client, log) = recording_kube_client();
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
                protocol: None,
            },
            port: Some(0),
            ..Default::default()
        };
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route]);

        let count_rs_patches = |log: &std::sync::Mutex<Vec<String>>| {
            log.lock()
                .unwrap()
                .iter()
                .filter(|s| s.starts_with("PATCH") && s.contains("/replicasets"))
                .count()
        };

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });

        reconcile(instance.clone(), ctx.clone()).await.unwrap();
        log.lock().unwrap().clear();

        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                RESTARTED_AT_ANNOTATION.to_string(),
                "2026-08-29T12:00:00Z".to_string(),
            );

        reconcile(instance, ctx).await.unwrap();
        assert!(
            count_rs_patches(&log) > 0,
            "children must be re-applied when restartedAt changes without a generation bump"
        );
    }

    #[tokio::test]
    async fn test_synced_instance_stamps_template_generation_after_apply() {
        let (client, log) = recording_kube_client();
        let tcp_route = RouteSpec {
            name: "chal".to_string(),
            backend: RouteBackend {
                service: "web".into(),
                port: 80,
                protocol: None,
            },
            port: Some(0),
            ..Default::default()
        };
        let (_store, ctx) = dummy_ctx(client, vec![tcp_route.clone()]);

        let tmpl = k8s_common::crd::CTFTemplate {
            metadata: ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: k8s_common::crd::CTFTemplateSpec {
                routes: vec![tcp_route],
                ..Default::default()
            },
            status: None,
        };
        ctx.caches.templates.update(&tmpl);

        let mut instance = Arc::new(dummy_instance("chal-1", None));
        let inst = Arc::get_mut(&mut instance).unwrap();
        inst.metadata.annotations = Some(crate::btreemap! {
            k8s_common::labels::MIN_TEMPLATE_GENERATION_ANNOTATION.to_string() => "2".to_string(),
        });
        inst.metadata.generation = Some(1);
        inst.status = Some(CTFInstanceStatus {
            observed_generation: Some(1),
            template_generation: Some(1),
            restarted_at: None,
            conditions: vec![],
            resources: Default::default(),
            ..Default::default()
        });

        reconcile(instance, ctx).await.unwrap();

        let stamped = log
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("PATCH") && s.contains("/status"));
        assert!(
            stamped,
            "reconcile must stamp templateGeneration after applying a bumped template \
             so the instance can return to Ready"
        );
    }

    #[tokio::test]
    async fn test_reconcile_observed_generation_skips() {
        let (_store, ctx) = dummy_context();
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                ..Default::default()
            },
            status: Some(CTFInstanceStatus {
                observed_generation: Some(1),
                template_generation: Some(1),
                conditions: vec![Condition {
                    type_: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "Reconciled".to_string(),
                    message: "CTFInstance reconciled successfully".to_string(),
                    last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ),
                    observed_generation: Some(1),
                }],
                ..Default::default()
            }),
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }
}

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_common::crd::{CTFInstance, CTFRoute, CTFTemplate};
use k8s_openapi::api::{apps::v1::ReplicaSet, core::v1::Service, networking::v1::NetworkPolicy};
use kube::{
    Api, Client,
    runtime::{
        WatchStreamExt,
        controller::{Action, Controller},
        reflector::{reflector, store},
        watcher::{Config, Event, watcher},
    },
};
use tracing::{error, info, instrument};

use crate::{Context, Error, reconcilers, utils::ttl::calculate_remaining_ttl};

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    info!(name, ns, "Reconciling CTFInstance");

    // Skip reconciliation if instance is marked for deletion
    if instance.metadata.deletion_timestamp.is_some() {
        info!(name, ns, "CTFInstance marked for deletion, skipping reconciliation");
        return Ok(Action::await_change());
    }

    // Check if instance has expired
    if crate::utils::ttl::is_expired(instance.spec.expires_at) {
        info!(name, ns, "CTFInstance has expired, deleting resource...");
        let instances: Api<CTFInstance> = Api::namespaced(ctx.client.clone(), ns);
        instances.delete(name, &Default::default()).await?;
        return Ok(Action::await_change());
    }

    // Resolve CTFTemplate referenced by `instance.spec.template`.
    let template = reconcilers::template::reconcile(&instance, &ctx).await?;

    let target_gen = template.metadata.generation.unwrap_or(1).to_string();

    let res = reconcile_children(&instance, &template, &ctx).await;
    if let Err(Error::TemplateGenShifted { .. }) = res {
        info!(
            name,
            target_gen,
            "Template generation shifted, updating CTFInstance template-generation annotation"
        );
        reconcilers::status::reconcile(&instance, &ctx, &target_gen, false).await?;
        return Ok(Action::await_change());
    }

    res?;

    // Success! Update status conditions (Ready = True, Synced = True) & observedGeneration
    reconcilers::status::reconcile(&instance, &ctx, &target_gen, true).await?;

    if let Some(remaining) = calculate_remaining_ttl(instance.spec.expires_at) {
        // We want to make sure the object really expires to save requeuing
        return Ok(Action::requeue(remaining + Duration::from_secs(10)));
    }

    Ok(Action::await_change())
}

/// Reconciles all child resources (workloads, network policies, services, routes) for a CTFInstance.
async fn reconcile_children(
    instance: &CTFInstance,
    template: &reconcilers::template::ResolvedTemplate,
    ctx: &Context,
) -> Result<(), Error> {
    reconcilers::replicaset::reconcile(instance, template, ctx).await?;
    reconcilers::network_policy::reconcile(instance, template, ctx).await?;
    reconcilers::service::reconcile(instance, template, ctx).await?;
    reconcilers::route::reconcile(instance, template, ctx).await?;
    Ok(())
}

/// Error policy handler invoked when reconciliation returns an error.
pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    error!(name, %error, "Reconciliation failed");

    let backoff_secs = match error {
        Error::TemplateBuildError(_) => 120,
        Error::TemplateNotFound(_) => 120,
        _ => 15,
    };

    Action::requeue(Duration::from_secs(backoff_secs))
}

/// Spawns and runs the `CTFInstance` controller loop.
pub async fn run(client: Client) {
    let instances = Api::<CTFInstance>::all(client.clone());
    let templates = Api::<CTFTemplate>::all(client.clone());
    let replica_sets = Api::<ReplicaSet>::all(client.clone());
    let network_policies = Api::<NetworkPolicy>::all(client.clone());
    let ctf_routes = Api::<CTFRoute>::all(client.clone());
    let services = Api::<Service>::all(client.clone());

    // Initialize in-memory CTFTemplate reflector store cache
    let (template_store, template_writer) = store();
    let template_reflector = reflector(
        template_writer,
        watcher(templates.clone(), Config::default()),
    );

    let context = Arc::new(Context::with_template_store(client, template_store));

    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    // Spawn background task to update in-memory template store
    let reflector_task = tokio::spawn(async move {
        let stream = template_reflector.touched_objects();
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(err) = res {
                error!(%err, "CTFTemplate reflector watcher error");
            }
        }
    });
    let _reflector_guard = AbortOnDrop(reflector_task);

    // Spawn background task to watch CTFTemplate events and evict updated/deleted templates from patcher cache
    let template_cache_watcher = context.template_cache.clone();
    let templates_watcher_api = templates.clone();
    let cache_task = tokio::spawn(async move {
        let watcher_stream = watcher(templates_watcher_api, Config::default());
        tokio::pin!(watcher_stream);
        while let Some(res) = watcher_stream.next().await {
            match res {
                Ok(Event::Apply(t)) | Ok(Event::Delete(t)) | Ok(Event::InitApply(t)) => {
                    let name = t.metadata.name.as_deref().unwrap_or_default();
                    let ns = t.metadata.namespace.as_deref().unwrap_or("default");
                    let cache_key = format!("{ns}/{name}");
                    template_cache_watcher.remove(&cache_key);
                    info!(cache_key = %cache_key, "Evicted updated/deleted CTFTemplate from patcher cache");
                }
                Ok(Event::Init) => {
                    template_cache_watcher.clear();
                    info!("Cleared all entries from CTFTemplate patcher cache on watcher init");
                }
                Ok(Event::InitDone) => {}
                Err(err) => {
                    error!(%err, "CTFTemplate watcher error");
                }
            }
        }
    });
    let _cache_watcher_guard = AbortOnDrop(cache_task);

    info!("Starting CTFInstance controller with template caching");

    let child_config = Config::default().labels("app.kubernetes.io/managed-by=aincrad-cardinal");

    Controller::new(instances, Config::default())
        .owns(replica_sets, child_config.clone())
        .owns(network_policies, child_config.clone())
        .owns(ctf_routes, child_config.clone())
        .owns(services, child_config)
        .watches(templates, Config::default(), |template| {
            // Watch CTFTemplates and trigger reconciliation for CTFInstances referencing the template
            let name = template.metadata.name.as_deref().unwrap_or_default();
            info!(
                template_name = name,
                "CTFTemplate updated, triggering watch evaluation"
            );
            None::<kube::runtime::reflector::ObjectRef<CTFInstance>>
        })
        .run(reconcile, error_policy, context)
        .for_each(|res| async {
            match res {
                Ok((object, _action)) => {
                    info!(name = %object.name, "Successfully reconciled CTFInstance");
                }
                Err(err) => {
                    error!(%err, "Controller error occurred");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::tests::dummy_kube_client;
    use crate::utils::labels::TEMPLATE_GEN_ANNOTATION;
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::crd::CTFInstanceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[tokio::test]
    async fn test_reconcile_no_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: None,
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_future_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let future_time = Utc::now() + ChronoDuration::seconds(120);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(crate::btreemap! {
                    TEMPLATE_GEN_ANNOTATION.to_string() => "1".to_string()
                }),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: Some(future_time),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_ne!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_past_expiration() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        let past_time = Utc::now() - ChronoDuration::seconds(60);

        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                expires_at: Some(past_time),
                ..Default::default()
            },
            status: None,
        });

        let action = reconcile(instance, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    #[tokio::test]
    async fn test_reconcile_deletion_timestamp() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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
    async fn test_reconcile_template_gen_shifted() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
        // Instance annotation is at gen "2", but mock template is at gen 1
        let instance = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("test-challenge".into()),
                namespace: Some("default".into()),
                annotations: Some(crate::btreemap! {
                    TEMPLATE_GEN_ANNOTATION.to_string() => "2".to_string()
                }),
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
    async fn test_error_policy() {
        let client = dummy_kube_client();
        let ctx = Arc::new(Context::new(client));
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

        let err_build = Error::TemplateBuildError("invalid json patch".into());
        let action_build = error_policy(instance.clone(), &err_build, ctx.clone());
        assert_eq!(action_build, Action::requeue(Duration::from_secs(120)));

        let err_transient = Error::Custom("failed to connect".into());
        let action_transient = error_policy(instance, &err_transient, ctx);
        assert_eq!(action_transient, Action::requeue(Duration::from_secs(15)));
    }
}

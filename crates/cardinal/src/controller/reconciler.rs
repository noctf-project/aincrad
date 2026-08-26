use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_common::crd::{CTFInstance, CTFRoute, CTFTemplate};
use k8s_openapi::api::{apps::v1::ReplicaSet, core::v1::Service, networking::v1::NetworkPolicy};
use kube::{
    Api, Client,
    runtime::{
        WatchStreamExt,
        controller::{Action, Controller},
        reflector::{ObjectRef, reflector, store},
        watcher::{Config, Event, watcher},
    },
};
use tracing::{error, info, instrument, warn};

use crate::{Context, Error, reconcilers, utils::ttl::calculate_remaining_ttl};

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    info!(name, ns, "Reconciling CTFInstance");

    // Skip reconciliation if instance is marked for deletion
    if instance.metadata.deletion_timestamp.is_some() {
        info!(
            name,
            ns, "CTFInstance marked for deletion, skipping reconciliation"
        );
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

/// Maps a `CTFTemplate` update event to a vector of `ObjectRef<CTFInstance>` for all instances
/// in the same namespace referencing the template that have `spec.sync == true`.
pub fn find_synced_instances(
    template: &CTFTemplate,
    instances: &[Arc<CTFInstance>],
) -> Vec<ObjectRef<CTFInstance>> {
    let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
    let tmpl_ns = template.metadata.namespace.as_deref().unwrap_or("default");

    instances
        .iter()
        .filter(|inst| {
            let inst_ns = inst.metadata.namespace.as_deref().unwrap_or("default");
            inst_ns == tmpl_ns && inst.spec.template == tmpl_name && inst.spec.sync
        })
        .map(|inst| ObjectRef::from_obj(&**inst))
        .collect()
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Handles watcher events for `CTFInstance` to update or clear the in-memory index.
pub fn handle_instance_watcher_event(
    event: Event<CTFInstance>,
    cache: &crate::cache::InstanceCache,
) {
    match event {
        Event::Apply(inst) | Event::InitApply(inst) => {
            cache.update(&inst);
        }
        Event::Delete(inst) => {
            cache.remove(&inst);
        }
        Event::Init => {
            cache.clear();
            info!("Cleared instance index on watcher init");
        }
        Event::InitDone => {}
    }
}

/// Handles watcher events for `CTFTemplate` to evict updated or deleted entries from the patcher cache.
pub fn handle_template_watcher_event(
    event: Result<Event<CTFTemplate>, kube::runtime::watcher::Error>,
    cache: &crate::cache::TemplateCache,
) {
    match event {
        Ok(Event::Apply(t)) | Ok(Event::Delete(t)) | Ok(Event::InitApply(t)) => {
            let name = t.metadata.name.as_deref().unwrap_or_default().to_string();
            let ns = t
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let cache_key = crate::cache::TemplateKey {
                namespace: ns,
                name,
            };
            cache.remove(&cache_key);
            info!("Evicted updated/deleted CTFTemplate from patcher cache");
        }
        Ok(Event::Init) => {
            cache.clear();
            info!("Cleared all entries from CTFTemplate patcher cache on watcher init");
        }
        Ok(Event::InitDone) => {}
        Err(err) => {
            error!(%err, "CTFTemplate watcher error");
        }
    }
}

/// Spawns a background task to process a reflector stream.
fn spawn_reflector_watcher<S, K>(stream: S, kind: &'static str) -> AbortOnDrop
where
    S: futures::Stream<Item = Result<K, kube::runtime::watcher::Error>> + Send + 'static,
    K: Send + Sync + 'static,
{
    let task = tokio::spawn(async move {
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(err) = res {
                error!(kind, %err, "Reflector watcher error");
            }
        }
    });
    AbortOnDrop(task)
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

    // Initialize in-memory CTFInstance reflector store cache for watches mapping
    let (instance_store, instance_writer) = store();
    let instance_reflector = reflector(
        instance_writer,
        watcher(instances.clone(), Config::default()),
    );

    let context = Arc::new(Context::with_template_store(client, template_store));

    let _tmpl_store_guard =
        spawn_reflector_watcher(template_reflector.touched_objects(), "CTFTemplate");
    let _inst_store_guard =
        spawn_reflector_watcher(instance_reflector.touched_objects(), "CTFInstance");

    use crate::cache::InstanceCache;
    let instance_cache = InstanceCache::new(instance_store);

    // Spawn background task to watch CTFInstance events and update index
    let instance_cache_task = instance_cache.clone();
    let instances_watcher_api = instances.clone();
    let instance_watcher_task = tokio::spawn(async move {
        let watcher_stream = watcher(instances_watcher_api, Config::default());
        tokio::pin!(watcher_stream);
        while let Some(res) = watcher_stream.next().await {
            match res {
                Ok(event) => handle_instance_watcher_event(event, &instance_cache_task),
                Err(err) => error!(%err, "CTFInstance watcher error"),
            }
        }
    });
    let _instance_watcher_guard = AbortOnDrop(instance_watcher_task);

    // Spawn background task to watch CTFTemplate events and evict entries from patcher cache
    let template_cache_watcher = context.template_cache.clone();
    let templates_watcher_api = templates.clone();
    let template_watcher_task = tokio::spawn(async move {
        let watcher_stream = watcher(templates_watcher_api, Config::default());
        tokio::pin!(watcher_stream);
        while let Some(res) = watcher_stream.next().await {
            handle_template_watcher_event(res, &template_cache_watcher);
        }
    });
    let _template_watcher_guard = AbortOnDrop(template_watcher_task);

    info!("Starting CTFInstance controller with template caching");

    let child_config = Config::default().labels("app.kubernetes.io/managed-by=aincrad-cardinal");

    Controller::new(instances, Config::default())
        .owns(replica_sets, child_config.clone())
        .owns(network_policies, child_config.clone())
        .owns(ctf_routes, child_config.clone())
        .owns(services, child_config)
        .watches(templates, Config::default(), move |template| {
            let tmpl_name = template.metadata.name.as_deref().unwrap_or_default();
            info!(
                template_name = tmpl_name,
                "CTFTemplate updated, evaluating synced CTFInstances to retrigger"
            );
            instance_cache.find_synced_instances(&template)
        })
        .run(reconcile, error_policy, context)
        .for_each(|res| async {
            match res {
                Ok((object, _action)) => {
                    info!(name = %object.name, "Successfully reconciled CTFInstance");
                }
                Err(err) => {
                    warn!(%err, "Controller error occurred");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::InstanceCache;
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

    #[tokio::test]
    async fn test_find_synced_instances() {
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let inst_sync_true = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let inst_sync_false = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-2".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: false,
                ..Default::default()
            },
            status: None,
        });

        let inst_other_tmpl = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-3".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "other-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let inst_other_ns = Arc::new(CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-4".into()),
                namespace: Some("other-ns".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        });

        let instances = vec![
            inst_sync_true,
            inst_sync_false,
            inst_other_tmpl,
            inst_other_ns,
        ];
        let matched = find_synced_instances(&tmpl, &instances);

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "inst-1");
        assert_eq!(matched[0].namespace.as_deref(), Some("default"));
    }

    #[tokio::test]
    async fn test_handle_instance_watcher_event() {
        let (store, _writer) = kube::runtime::reflector::store();
        let cache = InstanceCache::new(store);
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let inst = CTFInstance {
            metadata: ObjectMeta {
                name: Some("inst-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".into(),
                sync: true,
                ..Default::default()
            },
            status: None,
        };

        handle_instance_watcher_event(Event::Apply(inst.clone()), &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 1);

        handle_instance_watcher_event(Event::Delete(inst), &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);

        handle_instance_watcher_event(Event::Init, &cache);
        assert_eq!(cache.find_synced_instances(&tmpl).len(), 0);
    }

    #[tokio::test]
    async fn test_handle_template_watcher_event() {
        let cache = crate::cache::TemplateCache::new();
        let tmpl = CTFTemplate::new(
            "whoami-template",
            k8s_common::crd::CTFTemplateSpec::default(),
        );

        let key = crate::cache::TemplateKey {
            namespace: "default".into(),
            name: "whoami-template".into(),
        };

        // Populate cache
        cache.get_or_compile(&key, 1, &[]).unwrap();

        // Test Apply event evicts entry
        handle_template_watcher_event(Ok(Event::Apply(tmpl.clone())), &cache);

        // Test Init event clears cache
        cache.get_or_compile(&key, 1, &[]).unwrap();
        handle_template_watcher_event(Ok(Event::Init), &cache);
    }
}

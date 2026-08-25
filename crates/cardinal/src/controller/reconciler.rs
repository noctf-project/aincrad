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

use crate::{
    Context, Error, reconcilers, utils::labels::TEMPLATE_GEN_ANNOTATION,
    utils::ttl::calculate_remaining_ttl,
};

/// Reconciles a single `CTFInstance` resource state.
#[instrument(skip(ctx, instance), fields(name = %instance.metadata.name.as_deref().unwrap_or_default()))]
pub async fn reconcile(instance: Arc<CTFInstance>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    let ns = instance.metadata.namespace.as_deref().unwrap_or("default");

    info!(name, ns, "Reconciling CTFInstance");

    // Resolve CTFTemplate referenced by `instance.spec.template`.
    let template = reconcilers::template::reconcile(&instance, &ctx).await?;

    let target_gen = template.metadata.generation.unwrap_or(1).to_string();
    let instance_gen = instance
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(TEMPLATE_GEN_ANNOTATION))
        .map(String::as_str);

    let res = reconcile_children(&instance, &template, &ctx, instance_gen, &target_gen).await;
    if let Err(Error::TemplateGenShifted { .. }) = res {
        info!(
            name,
            target_gen,
            "Template generation shifted, updating CTFInstance template-generation annotation"
        );
        reconcilers::status::reconcile(&instance, &ctx, &target_gen).await?;
        return Ok(Action::await_change());
    }

    res?;

    if let Some(remaining) = calculate_remaining_ttl(instance.spec.expires_at) {
        return Ok(Action::requeue(remaining));
    }

    Ok(Action::await_change())
}

/// Reconciles all child resources (workloads, network policies, services, routes) for a CTFInstance.
async fn reconcile_children(
    instance: &CTFInstance,
    template: &reconcilers::template::ResolvedTemplate,
    ctx: &Context,
    instance_gen: Option<&str>,
    target_gen: &str,
) -> Result<(), Error> {
    reconcilers::workload::reconcile(instance, template, ctx, instance_gen, target_gen).await?;
    reconcilers::network_policy::reconcile(instance, template, ctx, instance_gen, target_gen)
        .await?;
    reconcilers::service::reconcile(instance, template, ctx, instance_gen, target_gen).await?;
    reconcilers::route::reconcile(instance, template, ctx, instance_gen, target_gen).await?;
    Ok(())
}

/// Error policy handler invoked when reconciliation returns an error.
pub fn error_policy(instance: Arc<CTFInstance>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = instance.metadata.name.as_deref().unwrap_or("unknown");
    error!(name, %error, "Reconciliation failed");

    Action::requeue(Duration::from_secs(10))
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

    // Spawn background task to update in-memory template store
    tokio::spawn(async move {
        let stream = template_reflector.touched_objects();
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(err) = res {
                error!(%err, "CTFTemplate reflector watcher error");
            }
        }
    });

    // Spawn background task to watch CTFTemplate events and evict updated/deleted templates from patcher cache
    let template_cache_watcher = context.template_cache.clone();
    let templates_watcher_api = templates.clone();
    tokio::spawn(async move {
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
    use chrono::{Duration as ChronoDuration, Utc};
    use k8s_common::crd::CTFInstanceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn dummy_kube_client() -> Client {
        use axum::http::{Request, Response, Uri};
        use kube::Config;
        use tower::Service;

        let config = Config::new(Uri::from_static("http://localhost:8080"));
        struct DummyService;
        type BoxFuture = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Response<axum::body::Body>, std::convert::Infallible>,
                    > + Send,
            >,
        >;
        impl<B> Service<Request<B>> for DummyService {
            type Response = Response<axum::body::Body>;
            type Error = std::convert::Infallible;
            type Future = BoxFuture;

            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::convert::Infallible>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<B>) -> BoxFuture {
                let path = req.uri().path().to_string();
                let query_str = req.uri().query().unwrap_or_default().to_string();
                let is_get = req.method() == axum::http::Method::GET;
                Box::pin(async move {
                    if is_get {
                        if path.contains("ctftemplates") {
                            let tmpl = serde_json::json!({
                                "apiVersion": "aincrad.noctf.dev/v1",
                                "kind": "CTFTemplate",
                                "metadata": {
                                    "name": "whoami-template",
                                    "namespace": "default",
                                    "generation": 1
                                },
                                "spec": {
                                    "params": [],
                                    "pods": [
                                        {
                                            "name": "web",
                                            "replicas": 1,
                                            "spec": {
                                                "containers": [
                                                    { "name": "web", "image": "nginx" }
                                                ]
                                            }
                                        }
                                    ],
                                    "routes": []
                                }
                            });
                            let body_str = serde_json::to_string(&tmpl).unwrap();
                            return Ok(axum::http::Response::builder()
                                .status(axum::http::StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(body_str))
                                .unwrap());
                        }

                        if query_str.contains("labelSelector") {
                            let list = serde_json::json!({
                                "apiVersion": "v1",
                                "kind": "List",
                                "metadata": {},
                                "items": []
                            });
                            let body_str = serde_json::to_string(&list).unwrap();
                            return Ok(axum::http::Response::builder()
                                .status(axum::http::StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(body_str))
                                .unwrap());
                        }

                        let status = serde_json::json!({
                            "kind": "Status",
                            "apiVersion": "v1",
                            "status": "Failure",
                            "message": "not found",
                            "reason": "NotFound",
                            "code": 404
                        });
                        let body_str = serde_json::to_string(&status).unwrap();
                        Ok(axum::http::Response::builder()
                            .status(axum::http::StatusCode::NOT_FOUND)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body_str))
                            .unwrap())
                    } else {
                        let (api_version, kind) = if path.contains("networkpolicies") {
                            ("networking.k8s.io/v1", "NetworkPolicy")
                        } else if path.contains("replicasets") {
                            ("apps/v1", "ReplicaSet")
                        } else if path.contains("ctfroutes") {
                            ("aincrad.noctf.dev/v1", "CTFRoute")
                        } else {
                            ("v1", "Service")
                        };

                        let body = serde_json::json!({
                            "apiVersion": api_version,
                            "kind": kind,
                            "metadata": {
                                "name": "dummy",
                                "namespace": "default"
                            }
                        });
                        let body_str = serde_json::to_string(&body).unwrap();
                        Ok(axum::http::Response::builder()
                            .status(axum::http::StatusCode::CREATED)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body_str))
                            .unwrap())
                    }
                })
            }
        }

        Client::new(DummyService, config.default_namespace)
    }

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

        let err = Error::Custom("failed to connect".into());
        let action = error_policy(instance, &err, ctx);

        assert_eq!(action, Action::requeue(Duration::from_secs(10)));
    }
}

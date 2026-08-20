use std::{
    fmt::Debug,
    pin::{Pin, pin},
    time::Duration,
};

use fluct::Error;
use futures::{Stream, TryStreamExt};
use k8s_openapi::NamespaceResourceScope;
use kube::{
    Api, Client,
    runtime::watcher::{Config, Event, watch_object, watcher},
};
use kube_lease_manager::{LeaseManager, LeaseManagerBuilder};
use serde::de::DeserializeOwned;
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Clone)]
pub struct KubernetesClient {
    client: Client,
}

impl KubernetesClient {
    pub async fn new() -> Result<Self, Error> {
        let client = Client::try_default().await?;
        Ok(Self { client })
    }

    #[allow(dead_code)]
    pub async fn update_object_status<K, S>(
        &self,
        name: &str,
        namespace: &str,
        status: S,
    ) -> Result<(), kube::Error>
    where
        K: kube::core::Resource<Scope = NamespaceResourceScope>
            + Clone
            + DeserializeOwned
            + Debug
            + Send
            + 'static,
        <K as kube::Resource>::DynamicType: std::default::Default,
        S: serde::Serialize + Send + Sync,
    {
        use kube::api::{Patch, PatchParams};

        let api: Api<K> = Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({
            "status": status
        });
        let pp = PatchParams::default();
        let _ = api.patch_status(name, &pp, &Patch::Merge(&patch)).await?;
        Ok(())
    }

    pub async fn watch_object<K>(
        &self,
        cancel: CancellationToken,
        name: &str,
        chan: mpsc::Sender<Option<K>>,
    ) where
        K: kube::core::Resource<Scope = NamespaceResourceScope>
            + Clone
            + DeserializeOwned
            + Debug
            + Send
            + 'static,
        <K as kube::Resource>::DynamicType: std::default::Default,
    {
        let api: Api<K> = Api::default_namespaced(self.client.clone());
        let stream = pin!(watch_object(api, name));
        self.do_watch(cancel, stream, chan).await;
    }

    pub async fn get_lease_manager(
        &self,
        name: &str,
        duration: Duration,
    ) -> Result<LeaseManager, Error> {
        Ok(LeaseManagerBuilder::new(self.client.clone(), name)
            .with_duration(duration.as_secs())
            .with_namespace(self.client.default_namespace())
            .build()
            .await?)
    }

    pub async fn watch<K>(
        &self,
        cancel: CancellationToken,
        chan: mpsc::Sender<Event<K>>,
        namespace: Option<String>,
    ) where
        K: kube::core::Resource<Scope = NamespaceResourceScope>
            + Clone
            + DeserializeOwned
            + Debug
            + Send
            + 'static,
        <K as kube::Resource>::DynamicType: std::default::Default,
    {
        let api: Api<K> = match namespace {
            Some(namespace) => Api::namespaced(self.client.clone(), &namespace),
            None => Api::all(self.client.clone()),
        };
        let stream = pin!(watcher(api, Config::default()));
        self.do_watch(cancel, stream, chan).await;
    }

    pub async fn do_watch<K>(
        &self,
        cancel: CancellationToken,
        mut stream: Pin<&mut (impl Stream<Item = Result<K, kube::runtime::watcher::Error>> + Send)>,
        chan: mpsc::Sender<K>,
    ) {
        loop {
            select! {
              event = stream.try_next() => {
                match event {
                  Ok(event) => {
                    let _ = match event {
                      Some(event) => chan.send(event).await,
                      None => Ok(()),
                    };
                  },
                  Err(err) => warn!("Error processing kubernetes event: {}", err),
                }
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
        info!("Stopped watching kubernetes resources");
    }
}

#[cfg(test)]
impl KubernetesClient {
    pub fn new_dummy_for_tests() -> Self {
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

            fn call(&mut self, _: Request<B>) -> BoxFuture {
                Box::pin(async { Ok(Response::new(axum::body::Body::empty())) })
            }
        }

        Self {
            client: Client::new(DummyService, config.default_namespace),
        }
    }
}

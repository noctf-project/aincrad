use std::{pin::pin, sync::Arc};

use fluct::Error;
use futures::TryStreamExt;
use k8s_common::crd::CTFProxyRoute;
use kube::{
    Api, Client,
    runtime::{
        WatchStreamExt,
        watcher::{Config, Event, watcher},
    },
};
use tracing::{info, warn};

use crate::{
    config::{PortRange, ServiceContext},
    netfilter::NetfilterOp,
    store::routes::ProxyStore,
};

pub struct RoutesService {
    client: Client,
    store: Arc<ProxyStore>,
    system_namespace: Option<String>,
    netfilter_tx: Option<tokio::sync::mpsc::Sender<NetfilterOp>>,
}

impl RoutesService {
    pub fn new(
        client: Client,
        port_ranges: Vec<PortRange>,
        system_namespace: Option<String>,
        netfilter_tx: Option<tokio::sync::mpsc::Sender<NetfilterOp>>,
    ) -> Self {
        Self {
            client,
            store: Arc::new(ProxyStore::new(port_ranges)),
            system_namespace,
            netfilter_tx,
        }
    }

    /// Returns the underlying routes store.
    pub fn store(&self) -> Arc<ProxyStore> {
        self.store.clone()
    }

    /// Retrieves an active TCP route by listening port.
    pub fn get_tcp_route(&self, port: u16) -> Option<Arc<CTFProxyRoute>> {
        self.store.get_tcp_route(port)
    }

    /// Retrieves an active named/SNI route by hostname.
    pub fn get_named_route(&self, hostname: &str) -> Option<Arc<CTFProxyRoute>> {
        self.store.get_named_route(hostname)
    }

    /// Returns all active TCP ports currently mapped to routes.
    pub fn get_active_ports(&self) -> Vec<u16> {
        self.store.active_tcp_ports()
    }

    /// Processes a single Kubernetes watcher event for `CTFProxyRoute`.
    pub fn handle_event(&self, event: Event<CTFProxyRoute>) {
        match event {
            Event::Init => {
                self.store.clear();
                info!("Cleared CTFProxyRoute store on watcher init");
                if let Some(tx) = &self.netfilter_tx {
                    let _ = tx.try_send(NetfilterOp::Flush);
                }
            }
            Event::Apply(data) | Event::InitApply(data) => {
                let name = data.metadata.name.clone().unwrap_or_default();
                if !self.store.insert(data.clone()) {
                    tracing::debug!("Skipping CTFProxyRoute {name}: generation unchanged");
                    return;
                }
                info!("Applying CTFProxyRoute: {name}");
                if let (Ok(k8s_common::crd::ProxyRouteKey::Tcp(port)), Some(tx)) =
                    (data.route_key(), &self.netfilter_tx)
                {
                    let _ = tx.try_send(NetfilterOp::Add(port));
                }
            }
            Event::Delete(data) => {
                if let Some(name) = data.metadata.name {
                    info!("Deleting CTFProxyRoute: {name}");
                    self.store.remove(&name);
                    if let (Ok(k8s_common::crd::ProxyRouteKey::Tcp(port)), Some(tx)) =
                        (name.parse(), &self.netfilter_tx)
                    {
                        let _ = tx.try_send(NetfilterOp::Remove(port));
                    }
                }
            }
            Event::InitDone => {}
        }
    }

    /// Runs the watcher event loop listening for `CTFProxyRoute` changes.
    pub async fn run(&self, ctx: Arc<ServiceContext>) -> Result<(), Error> {
        let cancel = &ctx.shutdown;
        let api: Api<CTFProxyRoute> = match &self.system_namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::default_namespaced(self.client.clone()),
        };

        info!(
            system_namespace = ?self.system_namespace,
            "Starting CTFProxyRoute watcher"
        );

        let mut stream = pin!(watcher(api, Config::default()).default_backoff());

        loop {
            tokio::select! {
                res = stream.try_next() => {
                    match res {
                        Ok(Some(event)) => self.handle_event(event),
                        Ok(None) => {
                            info!("CTFProxyRoute stream ended");
                            break;
                        }
                        Err(err) => {
                            warn!("Error in CTFProxyRoute watcher stream: {err}");
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    info!("CTFProxyRoute watcher cancelled");
                    break;
                }
            }
        }

        info!("Stopped CTFProxyRoute watcher");
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn create_dummy_kube_client() -> Client {
    use axum::http::{Request, Response, Uri};
    use tower::Service;

    let config = kube::Config::new(Uri::from_static("http://localhost:8080"));
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

    Client::new(DummyService, config.default_namespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::CTFProxyRouteSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_service() -> RoutesService {
        RoutesService::new(
            create_dummy_kube_client(),
            vec![PortRange(20000..=30000)],
            None,
            None,
        )
    }

    #[tokio::test]
    async fn test_routes_service_event_lifecycle() {
        let svc = make_service();

        let tcp_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20005".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".into(),
                ..Default::default()
            },
        };

        let named_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "whoami:80".into(),
                ..Default::default()
            },
        };

        // Apply events
        svc.handle_event(Event::Apply(tcp_route.clone()));
        svc.handle_event(Event::Apply(named_route.clone()));

        assert_eq!(svc.get_active_ports(), vec![20005]);
        assert_eq!(
            svc.get_tcp_route(20005).unwrap().spec.backend,
            "10.0.0.1:80"
        );
        assert_eq!(
            svc.get_named_route("whoami").unwrap().spec.backend,
            "whoami:80"
        );

        // Delete events
        svc.handle_event(Event::Delete(tcp_route));
        assert!(svc.get_tcp_route(20005).is_none());
        assert!(svc.get_active_ports().is_empty());

        svc.handle_event(Event::Delete(named_route));
        assert!(svc.get_named_route("whoami").is_none());
    }

    #[tokio::test]
    async fn test_routes_service_event_init_clears() {
        let svc = make_service();

        let tcp_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20005".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".into(),
                ..Default::default()
            },
        };

        let named_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "whoami:80".into(),
                ..Default::default()
            },
        };

        // Populate store
        svc.handle_event(Event::Apply(tcp_route.clone()));
        svc.handle_event(Event::Apply(named_route.clone()));

        assert_eq!(svc.get_active_ports(), vec![20005]);
        assert!(svc.get_tcp_route(20005).is_some());
        assert!(svc.get_named_route("whoami").is_some());

        // Event::Init should clear all routes
        svc.handle_event(Event::Init);

        assert!(svc.get_active_ports().is_empty());
        assert!(svc.get_tcp_route(20005).is_none());
        assert!(svc.get_named_route("whoami").is_none());

        // Subsequent InitApply should repopulate correctly
        svc.handle_event(Event::InitApply(tcp_route));
        svc.handle_event(Event::InitDone);

        assert_eq!(svc.get_active_ports(), vec![20005]);
        assert!(svc.get_tcp_route(20005).is_some());
    }

    #[tokio::test]
    async fn test_routes_service_netfilter_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let svc = RoutesService::new(
            create_dummy_kube_client(),
            vec![PortRange(20000..=30000)],
            None,
            Some(tx),
        );

        let valid_tcp = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20005".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".into(),
                ..Default::default()
            },
        };

        let named_route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("rwhoami".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "whoami:80".into(),
                ..Default::default()
            },
        };

        // Apply valid TCP route -> triggers Add(20005)
        svc.handle_event(Event::Apply(valid_tcp.clone()));
        assert_eq!(rx.try_recv(), Ok(NetfilterOp::Add(20005)));

        // Apply named route -> not a TCP port, no message sent
        svc.handle_event(Event::Apply(named_route.clone()));
        assert!(rx.try_recv().is_err());

        // Delete valid TCP route -> triggers Remove(20005)
        svc.handle_event(Event::Delete(valid_tcp));
        assert_eq!(rx.try_recv(), Ok(NetfilterOp::Remove(20005)));

        // Delete named route -> not a TCP port, no message sent
        svc.handle_event(Event::Delete(named_route));
        assert!(rx.try_recv().is_err());

        // Init -> triggers Flush
        svc.handle_event(Event::Init);
        assert_eq!(rx.try_recv(), Ok(NetfilterOp::Flush));
    }

    #[tokio::test]
    async fn test_routes_service_skips_unchanged_generation() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let svc = RoutesService::new(
            create_dummy_kube_client(),
            vec![PortRange(20000..=30000)],
            None,
            Some(tx),
        );

        let mut route = CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20005".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".into(),
                policy: Default::default(),
            },
        };

        // First apply -> triggers NetfilterOp::Add(20005)
        svc.handle_event(Event::Apply(route.clone()));
        assert_eq!(rx.try_recv(), Ok(NetfilterOp::Add(20005)));

        // Second apply with identical generation (e.g. metadata/label/status change) -> skipped!
        route.metadata.annotations = Some(std::collections::BTreeMap::from([(
            "touched".to_string(),
            "true".to_string(),
        )]));
        svc.handle_event(Event::Apply(route.clone()));
        assert!(
            rx.try_recv().is_err(),
            "must skip netfilter Add when generation is unchanged"
        );

        // Third apply with generation bump (spec change) -> triggers NetfilterOp::Add(20005)
        route.metadata.generation = Some(2);
        route.spec.backend = "10.0.0.2:80".into();
        svc.handle_event(Event::Apply(route.clone()));
        assert_eq!(rx.try_recv(), Ok(NetfilterOp::Add(20005)));
    }
}

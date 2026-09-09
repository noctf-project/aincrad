#[cfg(test)]
pub mod tests {
    use k8s_common::crd::{
        CTFInstance, CTFInstanceSpec, CTFTemplate, CTFTemplateSpec, CTFTemplateSpecPod,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::Client;
    use std::sync::Arc;

    use crate::reconcilers::template::ResolvedTemplate;

    pub fn dummy_kube_client() -> Client {
        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());
        struct DummyService;
        type BoxFuture = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            axum::http::Response<axum::body::Body>,
                            std::convert::Infallible,
                        >,
                    > + Send,
            >,
        >;
        impl<B: Send + 'static> tower::Service<axum::http::Request<B>> for DummyService {
            type Response = axum::http::Response<axum::body::Body>;
            type Error = std::convert::Infallible;
            type Future = BoxFuture;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: axum::http::Request<B>) -> Self::Future {
                let uri = req.uri().to_string();
                let method = req.method().clone();

                Box::pin(async move { respond_like_dummy(&method, &uri) })
            }
        }

        Client::new(DummyService, config.default_namespace)
    }

    pub fn error_kube_client(status_code: u16) -> Client {
        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());
        struct ErrorService(u16);
        type BoxFuture = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            axum::http::Response<axum::body::Body>,
                            std::convert::Infallible,
                        >,
                    > + Send,
            >,
        >;
        impl<B: Send + 'static> tower::Service<axum::http::Request<B>> for ErrorService {
            type Response = axum::http::Response<axum::body::Body>;
            type Error = std::convert::Infallible;
            type Future = BoxFuture;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: axum::http::Request<B>) -> Self::Future {
                let code = self.0;
                Box::pin(async move {
                    let status = serde_json::json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": "internal server error",
                        "reason": "InternalError",
                        "code": code
                    });
                    let body_str = serde_json::to_string(&status).unwrap();
                    Ok(axum::http::Response::builder()
                        .status(
                            axum::http::StatusCode::from_u16(code)
                                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
                        )
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body_str))
                        .unwrap())
                })
            }
        }

        Client::new(ErrorService(status_code), config.default_namespace)
    }

    pub fn dummy_instance(name: &str, _gen_annotation: Option<&str>) -> CTFInstance {
        let annotations = std::collections::BTreeMap::new();
        CTFInstance {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                uid: Some("uid-12345".to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: CTFInstanceSpec {
                template: "whoami-template".to_string(),
                ..Default::default()
            },
            status: None,
        }
    }

    pub fn dummy_resolved_template(target_g: i64) -> ResolvedTemplate {
        ResolvedTemplate {
            metadata: ObjectMeta {
                name: Some("whoami-template".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(target_g),
                ..Default::default()
            },
            spec: CTFTemplateSpec {
                pods: vec![CTFTemplateSpecPod {
                    name: "web".to_string(),
                    allow_internet: false,
                    replicas: 1,
                    patch_spec: None,
                    spec: k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "app".to_string(),
                            image: Some("nginx:latest".to_string()),
                            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                                container_port: 80,
                                ..Default::default()
                            }]),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                }],
                routes: vec![],
                params: vec![],
            },
            pod_patchers: Arc::new(std::collections::HashMap::new()),
            params_map: std::collections::BTreeMap::new(),
        }
    }

    /// Creates a dummy Context with template store + allocator for tests.
    /// Returns (store, Arc<Context>) so store can be populated before use.
    pub fn dummy_context() -> (
        kube::runtime::reflector::Store<CTFTemplate>,
        Arc<crate::Context>,
    ) {
        dummy_ctx(dummy_kube_client(), Vec::new())
    }

    /// Creates a dummy Context whose template includes the given routes.
    pub fn dummy_context_with_routes(
        routes: Vec<k8s_common::crd::RouteSpec>,
    ) -> (
        kube::runtime::reflector::Store<CTFTemplate>,
        Arc<crate::Context>,
    ) {
        dummy_ctx(dummy_kube_client(), routes)
    }

    /// Builds a dummy Context using a caller-provided kube client and template routes.
    pub fn dummy_ctx(
        client: kube::Client,
        routes: Vec<k8s_common::crd::RouteSpec>,
    ) -> (
        kube::runtime::reflector::Store<CTFTemplate>,
        Arc<crate::Context>,
    ) {
        use crate::routing::PortMap;
        use k8s_common::PortRange;

        let (template_store, _) = kube::runtime::reflector::store();
        let port_map = Arc::new(PortMap::new(
            vec![PortRange(20000..=20010)],
            vec![PortRange(30000..=30010)],
        ));
        let ctx = crate::Context::new_stub_with_port_map(
            client,
            port_map,
            "seed",
            "c.noctf.dev",
            4433,
            "aincrad-system",
            std::collections::BTreeMap::new(),
        );

        // Populate template cache with a default template
        let tmpl = CTFTemplate {
            metadata: ObjectMeta {
                name: Some("whoami-template".into()),
                namespace: Some("default".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: CTFTemplateSpec {
                pods: vec![CTFTemplateSpecPod {
                    name: "web".into(),
                    allow_internet: false,
                    replicas: 1,
                    patch_spec: None,
                    spec: k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "web".into(),
                            image: Some("nginx:latest".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                }],
                routes,
                params: vec![],
            },
            status: None,
        };
        ctx.caches.templates.update(&tmpl);

        (template_store, Arc::new(ctx))
    }

    /// Returns a kube client that mirrors `dummy_kube_client` and records
    /// "(method path)" for every request it serves.
    pub fn recording_kube_client() -> (kube::Client, Arc<std::sync::Mutex<Vec<String>>>) {
        use std::sync::Mutex;
        use tower::service_fn;

        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log_task = log.clone();

        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());

        let service = service_fn(move |req: axum::http::Request<kube::client::Body>| {
            let log = log_task.clone();
            async move {
                log.lock()
                    .unwrap()
                    .push(format!("{} {}", req.method(), req.uri()));
                respond_like_dummy(req.method(), req.uri().path())
            }
        });

        let client = kube::Client::new(service, config.default_namespace);
        (client, log)
    }

    fn respond_like_dummy(
        method: &axum::http::Method,
        path: &str,
    ) -> Result<axum::http::Response<axum::body::Body>, std::convert::Infallible> {
        let is_get = method == axum::http::Method::GET;

        let clean_path = path.split('?').next().unwrap_or(path);

        if is_get {
            if clean_path.contains("ctftemplates") {
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

            if clean_path.ends_with("/replicasets")
                || clean_path.ends_with("/services")
                || clean_path.ends_with("/networkpolicies")
                || clean_path.ends_with("/tlsroutes")
                || clean_path.ends_with("/ctfinstances")
            {
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
            if method == axum::http::Method::DELETE
                && (clean_path.ends_with("/replicasets")
                    || clean_path.ends_with("/services")
                    || clean_path.ends_with("/networkpolicies")
                    || clean_path.ends_with("/tlsroutes")
                    || clean_path.ends_with("/ctfinstances"))
            {
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

            let (api_version, kind) = if path.contains("networkpolicies") {
                ("networking.k8s.io/v1", "NetworkPolicy")
            } else if path.contains("replicasets") {
                ("apps/v1", "ReplicaSet")
            } else if path.contains("tlsroutes") {
                ("gateway.networking.k8s.io/v1alpha2", "TLSRoute")
            } else if path.contains("ctftemplates") {
                ("aincrad.noctf.dev/v1", "CTFTemplate")
            } else if path.contains("ctfinstances") {
                ("aincrad.noctf.dev/v1", "CTFInstance")
            } else {
                ("v1", "Service")
            };

            let clean_path = path.split('?').next().unwrap_or(path);
            let resource_name = clean_path.rsplit('/').next().unwrap_or("dummy");
            let mut body = serde_json::json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": {
                    "name": resource_name,
                    "namespace": "default",
                    "labels": {
                        "aincrad.noctf.dev/namespace": "default",
                        "aincrad.noctf.dev/instance": "chal-1",
                        "aincrad.noctf.dev/resource": "web"
                    }
                }
            });
            if kind == "CTFInstance" {
                body["spec"] = serde_json::json!({ "template": "whoami-template" });
            } else if kind == "CTFTemplate" {
                body["spec"] = serde_json::json!({ "pods": [], "routes": [] });
            }
            let body_str = serde_json::to_string(&body).unwrap();
            Ok(axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body_str))
                .unwrap())
        }
    }
}

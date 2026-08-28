#[cfg(test)]
pub mod tests {
    use k8s_common::crd::{CTFInstance, CTFInstanceSpec, CTFTemplateSpec, CTFTemplateSpecPod};
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
                let path = req.uri().path().to_string();
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

                        if path.ends_with("/replicasets")
                            || path.ends_with("/services")
                            || path.ends_with("/networkpolicies")
                            || path.ends_with("/ctfinstances")
                            || path.ends_with("/ctfproxyroutes")
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
                        let (api_version, kind) = if path.contains("networkpolicies") {
                            ("networking.k8s.io/v1", "NetworkPolicy")
                        } else if path.contains("replicasets") {
                            ("apps/v1", "ReplicaSet")
                        } else if path.contains("ctfproxyroutes") {
                            ("aincrad.noctf.dev/v1", "CTFProxyRoute")
                        } else if path.contains("ctfinstances") {
                            ("aincrad.noctf.dev/v1", "CTFInstance")
                        } else {
                            ("v1", "Service")
                        };

                        let mut body = serde_json::json!({
                            "apiVersion": api_version,
                            "kind": kind,
                            "metadata": {
                                "name": "dummy",
                                "namespace": "default"
                            }
                        });
                        if kind == "CTFInstance" {
                            body["spec"] = serde_json::json!({ "template": "whoami-template" });
                        } else if kind == "CTFProxyRoute" {
                            body["spec"] = serde_json::json!({
                                "backend": "web.default.svc.cluster.local:80"
                            });
                        }
                        let body_str = serde_json::to_string(&body).unwrap();
                        Ok(axum::http::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body_str))
                            .unwrap())
                    }
                })
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
                    patch: None,
                    spec: k8s_openapi::api::core::v1::PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: "app".to_string(),
                            image: Some("nginx:latest".to_string()),
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
}

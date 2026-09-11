pub mod auth;
pub mod handlers;
pub mod models;

use axum::{
    Router, middleware,
    routing::{get, post, put},
};
use kube::Client;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::ApiConfig;
use auth::rfc9421_auth_middleware;
use handlers::{
    ApiState, delete_instance, get_instance, list_instances, put_instance, renew_instance,
    restart_instance,
};
use models::{
    ApiErrorResponse, InstanceResponse, PutInstanceRequest, RenewInstanceRequest,
    RenewInstanceResponse,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::put_instance,
        handlers::get_instance,
        handlers::restart_instance,
        handlers::renew_instance,
        handlers::delete_instance,
        handlers::list_instances,
    ),
    components(
        schemas(
            PutInstanceRequest,
            InstanceResponse,
            RenewInstanceRequest,
            RenewInstanceResponse,
            ApiErrorResponse,
        )
    ),
    tags(
        (name = "Instances", description = "Sandbox instance lifecycle management")
    )
)]
pub struct ApiDoc;

use parking_lot::RwLock;

/// Middleware that gates access to Swagger UI based on dynamic ApiConfig.
async fn swagger_gate_middleware(
    axum::extract::State(config): axum::extract::State<Arc<RwLock<Arc<ApiConfig>>>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !config.read().swagger {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

/// Builds the Axum router for Cardinal's embedded API.
pub fn router(client: Client, config: Arc<RwLock<Arc<ApiConfig>>>) -> Router {
    let state = ApiState {
        client,
        config: config.clone(),
    };

    let v1_routes = Router::new()
        .route("/namespaces/{namespace}/instances", get(list_instances))
        .route(
            "/namespaces/{namespace}/instances/{id}",
            put(put_instance).get(get_instance).delete(delete_instance),
        )
        .route(
            "/namespaces/{namespace}/instances/{id}/restart",
            post(restart_instance),
        )
        .route(
            "/namespaces/{namespace}/instances/{id}/renew",
            post(renew_instance),
        )
        .layer(middleware::from_fn_with_state(
            config.clone(),
            rfc9421_auth_middleware,
        ));

    let swagger_routes = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/swagger-ui/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            config.clone(),
            swagger_gate_middleware,
        ));

    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/v1", v1_routes)
        .merge(swagger_routes);

    router.with_state(state)
}

/// Starts the embedded API server task.
pub async fn start_server(
    client: Client,
    config: Arc<RwLock<Arc<ApiConfig>>>,
    listen_addr: std::net::SocketAddr,
) -> Result<(), crate::Error> {
    let app = router(client, config);

    tracing::info!(
        addr = %listen_addr,
        "Starting embedded HTTP API server"
    );

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| {
            crate::Error::Custom(format!("Failed to bind API server to {listen_addr}: {e}"))
        })?;

    axum::serve(listener, app)
        .await
        .map_err(|e| crate::Error::Custom(format!("API server error: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, ApiKeyConfig};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let mut keys = BTreeMap::new();
        keys.insert(
            "test-key".to_string(),
            ApiKeyConfig {
                secret: "test-secret-12345678".to_string(),
                namespaces: vec!["challenges".to_string()],
            },
        );

        let config = ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: true,
            keys,
        };

        let (client, _) = crate::test_utils::tests::recording_kube_client();
        router(client, Arc::new(RwLock::new(Arc::new(config))))
    }

    #[tokio::test]
    async fn test_healthz_is_public() {
        let app = test_app();
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_unauthenticated_protected_endpoint_rejected() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/namespaces/challenges/instances/test-1")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_swagger_dynamic_enable_disable() {
        let config = ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: false,
            keys: BTreeMap::new(),
        };

        let shared_config = Arc::new(RwLock::new(Arc::new(config)));
        let (client, _) = crate::test_utils::tests::recording_kube_client();
        let app = router(client, shared_config.clone());

        // When swagger is false: returns 404 Not Found with empty body
        let req = Request::builder()
            .uri("/swagger-ui/")
            .body(Body::empty())
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());

        // Enable swagger dynamically
        let new_config = ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: true,
            keys: BTreeMap::new(),
        };
        *shared_config.write() = Arc::new(new_config);

        // When swagger is true: returns 200 OK
        let req = Request::builder()
            .uri("/swagger-ui/")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forbidden_namespace_rejected() {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let app = test_app();
        let now = chrono::Utc::now().timestamp();
        let body = b"";
        let uri = "/v1/namespaces/kube-system/instances/test-1";

        let digest_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            Sha256::digest(body),
        );
        let content_digest = format!("sha-256=:{digest_b64}:");
        let params_str = format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created={now};keyid=\"test-key\""
        );
        let sig_input = format!("sig1={params_str}");

        let sig_base = format!(
            "\"@method\": GET\n\"@target-uri\": {uri}\n\"@authority\": localhost\n\"content-digest\": {content_digest}\n\"@signature-params\": {params_str}"
        );

        let mut mac = HmacSha256::new_from_slice(b"test-secret-12345678").unwrap();
        mac.update(sig_base.as_bytes());
        let sig_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            mac.finalize().into_bytes(),
        );
        let signature = format!("sig1=:{sig_b64}:");

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost")
            .header("content-digest", content_digest)
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        // test-key is restricted to "challenges" namespace, so "kube-system" must return 403 Forbidden
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_dynamic_config_reload() {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let config = ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: false,
            keys: BTreeMap::new(),
        };

        let shared_config = Arc::new(RwLock::new(Arc::new(config)));
        let (client, _) = crate::test_utils::tests::recording_kube_client();
        let app = router(client, shared_config.clone());

        let sign_for_key = |key_id: &str, secret: &str| {
            let now = chrono::Utc::now().timestamp();
            let body = b"";
            let uri = "/v1/namespaces/challenges/instances/test-1";

            let digest_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                Sha256::digest(body),
            );
            let content_digest = format!("sha-256=:{digest_b64}:");
            let params_str = format!(
                "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created={now};keyid=\"{key_id}\""
            );
            let sig_input = format!("sig1={params_str}");
            let sig_base = format!(
                "\"@method\": GET\n\"@target-uri\": {uri}\n\"@authority\": localhost\n\"content-digest\": {content_digest}\n\"@signature-params\": {params_str}"
            );

            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(sig_base.as_bytes());
            let sig_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                mac.finalize().into_bytes(),
            );
            let signature = format!("sig1=:{sig_b64}:");

            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "localhost")
                .header("content-digest", content_digest)
                .header("signature-input", sig_input)
                .header("signature", signature)
                .body(Body::empty())
                .unwrap()
        };

        // Before reload, rotated-key is unknown
        let req = sign_for_key("rotated-key", "new-secret-1234");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Dynamically update config
        let mut keys = BTreeMap::new();
        keys.insert(
            "rotated-key".to_string(),
            ApiKeyConfig {
                secret: "new-secret-1234".to_string(),
                namespaces: vec!["challenges".to_string()],
            },
        );
        let new_config = ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: false,
            keys,
        };
        *shared_config.write() = Arc::new(new_config);

        // After reload, rotated-key is recognized immediately
        let req = sign_for_key("rotated-key", "new-secret-1234");
        let res = app.oneshot(req).await.unwrap();
        assert_ne!(res.status(), StatusCode::UNAUTHORIZED);
    }
}

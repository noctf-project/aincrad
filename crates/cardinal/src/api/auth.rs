use axum::{
    Json,
    body::Body,
    extract::{OriginalUri, RawPathParams, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use httpsig::prelude::{HttpSignatureHeaders, SharedKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::models::ApiErrorResponse;
use crate::config::ApiConfig;

use parking_lot::RwLock;

/// Middleware that verifies RFC 9421 / RFC 9530 HTTP Message Signatures using `httpsig`.
///
/// Requires:
/// - `Content-Digest`: valid RFC 9530 digest matching the request body.
/// - `Signature-Input`: valid RFC 9421 parameters including `keyid` and `created`.
/// - `Signature`: valid RFC 9421 HMAC-SHA256 signature.
/// - Clock skew check: `|now - created| <= config.max_clock_skew_seconds`.
/// - Namespace check: matching key must be authorized for the target namespace in the path.
pub async fn rfc9421_auth_middleware(
    State(config_lock): State<Arc<RwLock<Arc<ApiConfig>>>>,
    raw_params: RawPathParams,
    OriginalUri(original_uri): OriginalUri,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let config = config_lock.read().clone();
    let path = original_uri.path().to_string();

    // Extract namespace from Axum's routed path parameters
    let target_ns = raw_params
        .iter()
        .find(|(k, _)| *k == "namespace")
        .map(|(_, v)| v);

    let Some(ns) = target_ns else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                error: "Not found".to_string(),
            }),
        )
            .into_response());
    };

    // Buffer body to allow verification and reconstruct request
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    error: format!("Failed to read request body: {e}"),
                }),
            )
                .into_response()
        })?;

    // Perform signature verification using the original unstripped URI
    let verified_key_id = match verify_signature(&config, &parts, &original_uri, &body_bytes) {
        Ok(kid) => kid,
        Err(err) => {
            tracing::warn!(error = %err, path = %path, "RFC 9421 auth failed");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiErrorResponse {
                    error: format!("Unauthorized: {err}"),
                }),
            )
                .into_response());
        }
    };

    // Check namespace authorization
    if let Some(key_cfg) = config.keys.get(&verified_key_id)
        && !key_cfg.allows_namespace(ns)
    {
        tracing::warn!(
            key_id = %verified_key_id,
            namespace = %ns,
            "Key is not authorized for namespace"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiErrorResponse {
                error: "Forbidden".to_string(),
            }),
        )
            .into_response());
    }

    // Reconstruct request and attach verified key ID to extensions
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(VerifiedKeyId(verified_key_id));

    Ok(next.run(req).await)
}

#[derive(Clone, Debug)]
pub struct VerifiedKeyId(pub String);

fn verify_signature(
    config: &ApiConfig,
    parts: &axum::http::request::Parts,
    original_uri: &axum::http::Uri,
    body_bytes: &[u8],
) -> Result<String, String> {
    // Parse Signature-Input and Signature headers via httpsig
    let sig_header = parts
        .headers
        .get("signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "missing Signature header".to_string())?;

    let sig_input_header = parts
        .headers
        .get("signature-input")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| "missing Signature-Input header".to_string())?;

    let headers_map = HttpSignatureHeaders::try_parse(sig_header, sig_input_header)
        .map_err(|e| format!("failed to parse signature headers: {e}"))?;

    let (_sig_name, sig_headers) = headers_map
        .into_iter()
        .next()
        .ok_or_else(|| "no valid signature found in headers".to_string())?;

    let params = sig_headers.signature_params();
    let key_id = params
        .keyid
        .clone()
        .ok_or_else(|| "missing 'keyid' in signature parameters".to_string())?;

    // Verify created timestamp and clock skew
    let created_ts = params
        .created
        .ok_or_else(|| "missing 'created' timestamp in signature parameters".to_string())?;

    let now = chrono::Utc::now().timestamp() as u64;
    let diff = now.abs_diff(created_ts);

    if diff > config.max_clock_skew_seconds {
        return Err(format!(
            "timestamp skew ({diff}s) exceeds max allowed ({}s)",
            config.max_clock_skew_seconds
        ));
    }

    // Verify Content-Digest (RFC 9530) if present or if body is non-empty
    let has_content_digest_header = parts.headers.contains_key("content-digest");
    if !body_bytes.is_empty() || has_content_digest_header {
        let content_digest = parts
            .headers
            .get("content-digest")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| "missing Content-Digest header for request body".to_string())?;

        let expected_digest = format!(
            "sha-256=:{}:",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                Sha256::digest(body_bytes)
            )
        );

        if content_digest != expected_digest {
            return Err("content-digest mismatch".to_string());
        }
    }

    // Verify minimum required covered components
    let mut has_method = false;
    let mut has_uri_or_path = false;
    let mut has_query = false;
    let mut has_authority = false;
    let mut has_content_digest = false;

    for comp in &params.covered_components {
        match &comp.name {
            httpsig::prelude::message_component::HttpMessageComponentName::Derived(
                httpsig::prelude::message_component::DerivedComponentName::Method,
            ) => has_method = true,
            httpsig::prelude::message_component::HttpMessageComponentName::Derived(
                httpsig::prelude::message_component::DerivedComponentName::TargetUri
                | httpsig::prelude::message_component::DerivedComponentName::Path,
            ) => has_uri_or_path = true,
            httpsig::prelude::message_component::HttpMessageComponentName::Derived(
                httpsig::prelude::message_component::DerivedComponentName::Query,
            ) => has_query = true,
            httpsig::prelude::message_component::HttpMessageComponentName::Derived(
                httpsig::prelude::message_component::DerivedComponentName::Authority,
            ) => has_authority = true,
            httpsig::prelude::message_component::HttpMessageComponentName::HttpField(name)
                if name.eq_ignore_ascii_case("host") =>
            {
                has_authority = true
            }
            httpsig::prelude::message_component::HttpMessageComponentName::HttpField(name)
                if name.eq_ignore_ascii_case("content-digest") =>
            {
                has_content_digest = true
            }
            _ => {}
        }
    }

    if !has_method {
        return Err("missing mandatory '@method' in covered components".to_string());
    }
    if !has_uri_or_path {
        return Err(
            "missing mandatory target component ('@target-uri' or '@path') in covered components"
                .to_string(),
        );
    }
    if original_uri.query().is_some()
        && !has_query
        && !params.covered_components.iter().any(|c| {
            matches!(
                c.name,
                httpsig::prelude::message_component::HttpMessageComponentName::Derived(
                    httpsig::prelude::message_component::DerivedComponentName::TargetUri
                )
            )
        })
    {
        return Err(
            "missing mandatory '@query' in covered components for URI with query parameters"
                .to_string(),
        );
    }
    if !has_authority {
        return Err(
            "missing mandatory authority component ('@authority' or 'host') in covered components"
                .to_string(),
        );
    }
    if !body_bytes.is_empty() && !has_content_digest {
        return Err(
            "missing mandatory 'content-digest' in covered components for request body".to_string(),
        );
    }

    // Dynamically build canonical signature base from covered components in user's specified order
    let mut sig_lines = Vec::with_capacity(params.covered_components.len() + 1);
    for comp in &params.covered_components {
        match &comp.name {
            httpsig::prelude::message_component::HttpMessageComponentName::Derived(derived) => {
                let val = match derived {
                    httpsig::prelude::message_component::DerivedComponentName::Method => {
                        parts.method.as_str().to_string()
                    }
                    httpsig::prelude::message_component::DerivedComponentName::TargetUri => {
                        original_uri.to_string()
                    }
                    httpsig::prelude::message_component::DerivedComponentName::Path => {
                        original_uri.path().to_string()
                    }
                    httpsig::prelude::message_component::DerivedComponentName::Query => {
                        original_uri
                            .query()
                            .map(|q| format!("?{q}"))
                            .unwrap_or_else(|| "?".to_string())
                    }
                    httpsig::prelude::message_component::DerivedComponentName::Authority => parts
                        .headers
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string())
                        .or_else(|| original_uri.authority().map(|a| a.as_str().to_string()))
                        .unwrap_or_default(),
                    _ => {
                        return Err(format!("unsupported derived component: {derived}"));
                    }
                };
                sig_lines.push(format!("\"{derived}\": {val}"));
            }
            httpsig::prelude::message_component::HttpMessageComponentName::HttpField(
                header_name,
            ) => {
                let val = parts
                    .headers
                    .get(header_name)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| format!("missing covered header: '{header_name}'"))?;
                sig_lines.push(format!("\"{header_name}\": {val}"));
            }
        }
    }

    sig_lines.push(format!("\"@signature-params\": {}", params));
    let sig_base = sig_lines.join("\n");

    // Resolve key from config
    let key_cfg = config
        .keys
        .get(&key_id)
        .ok_or_else(|| format!("unknown keyid '{key_id}'"))?;

    let secret_bytes = key_cfg
        .resolve_secret()
        .map_err(|e| format!("failed to resolve secret for keyid '{key_id}': {e}"))?;

    // Verify HMAC-SHA256 signature using httpsig's SharedKey
    let shared_key = SharedKey::HmacSha256(secret_bytes);
    let signature_bytes = sig_headers.signature();

    let raw_sig = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature_bytes.to_string(),
    )
    .map_err(|e| format!("failed to decode signature: {e}"))?;

    shared_key
        .verify(sig_base.as_bytes(), &raw_sig)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    Ok(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, ApiKeyConfig};
    use httpsig::prelude::SigningKey;
    use std::collections::BTreeMap;

    fn test_config() -> ApiConfig {
        let mut keys = BTreeMap::new();
        keys.insert(
            "test-key".to_string(),
            ApiKeyConfig {
                secret: "test-secret-12345678".to_string(),
                namespaces: vec!["challenges".to_string()],
            },
        );
        keys.insert(
            "global-key".to_string(),
            ApiKeyConfig {
                secret: "global-secret-xyz".to_string(),
                namespaces: vec![],
            },
        );

        ApiConfig {
            max_clock_skew_seconds: 15,
            swagger: false,
            keys,
        }
    }

    fn sign_request(
        secret: &str,
        key_id: &str,
        method: &str,
        uri: &str,
        body: &[u8],
        timestamp: u64,
    ) -> (String, String, String) {
        let digest_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            Sha256::digest(body),
        );
        let content_digest = format!("sha-256=:{digest_b64}:");

        let params_str = format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created={timestamp};keyid=\"{key_id}\""
        );
        let sig_input = format!("sig1={params_str}");

        let sig_base = format!(
            "\"@method\": {method}\n\"@target-uri\": {uri}\n\"@authority\": localhost\n\"content-digest\": {content_digest}\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(secret.as_bytes().to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();

        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        (content_digest, sig_input, signature)
    }

    #[test]
    fn test_rfc9421_valid_signature() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"{\"template\":\"pwn\"}";

        let (cd, si, sig) = sign_request(
            "test-secret-12345678",
            "test-key",
            "PUT",
            "/v1/namespaces/challenges/instances/test-1",
            body,
            now,
        );

        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/v1/namespaces/challenges/instances/test-1")
            .header("host", "localhost")
            .header("content-digest", cd)
            .header("signature-input", si)
            .header("signature", sig)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let verified = verify_signature(&cfg, &parts, &parts.uri, body);
        assert_eq!(verified.unwrap(), "test-key");
    }

    #[test]
    fn test_rfc9421_tampered_body_fails() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"{\"template\":\"pwn\"}";

        let (cd, si, sig) = sign_request(
            "test-secret-12345678",
            "test-key",
            "PUT",
            "/v1/namespaces/challenges/instances/test-1",
            body,
            now,
        );

        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/v1/namespaces/challenges/instances/test-1")
            .header("host", "localhost")
            .header("content-digest", cd)
            .header("signature-input", si)
            .header("signature", sig)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let tampered_body = b"{\"template\":\"tampered\"}";
        let res = verify_signature(&cfg, &parts, &parts.uri, tampered_body);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("content-digest mismatch"));
    }

    #[test]
    fn test_rfc9421_expired_timestamp_fails() {
        let cfg = test_config();
        let stale_time = chrono::Utc::now().timestamp() as u64 - 30;
        let body = b"{}";

        let (cd, si, sig) = sign_request(
            "test-secret-12345678",
            "test-key",
            "PUT",
            "/v1/namespaces/challenges/instances/test-1",
            body,
            stale_time,
        );

        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/v1/namespaces/challenges/instances/test-1")
            .header("host", "localhost")
            .header("content-digest", cd)
            .header("signature-input", si)
            .header("signature", sig)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let res = verify_signature(&cfg, &parts, &parts.uri, body);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("exceeds max allowed"));
    }

    #[test]
    fn test_rfc9421_unknown_keyid_fails() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"{}";

        let (cd, si, sig) = sign_request(
            "random-secret",
            "non-existent-key",
            "PUT",
            "/v1/namespaces/challenges/instances/test-1",
            body,
            now,
        );

        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/v1/namespaces/challenges/instances/test-1")
            .header("host", "localhost")
            .header("content-digest", cd)
            .header("signature-input", si)
            .header("signature", sig)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let res = verify_signature(&cfg, &parts, &parts.uri, body);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("unknown keyid"));
    }

    #[test]
    fn test_rfc9421_get_without_content_digest_succeeds() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let empty_body = b"";
        let uri = "/v1/namespaces/challenges/instances";

        // Client covers @method, @target-uri, and @authority (no content-digest)
        let params_str = format!(
            "(\"@method\" \"@target-uri\" \"@authority\");created={now};keyid=\"test-key\""
        );
        let sig_input = format!("sig1={params_str}");
        let sig_base = format!(
            "\"@method\": GET\n\"@target-uri\": {uri}\n\"@authority\": localhost\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(b"test-secret-12345678".to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost")
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let verified = verify_signature(&cfg, &parts, &parts.uri, empty_body);
        assert_eq!(verified.unwrap(), "test-key");
    }

    #[test]
    fn test_rfc9421_post_missing_content_digest_fails() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"{\"key\":\"val\"}";
        let uri = "/v1/namespaces/challenges/instances/test-1";

        // Client omits content-digest from covered components on a non-empty request
        let params_str = format!(
            "(\"@method\" \"@target-uri\" \"@authority\");created={now};keyid=\"test-key\""
        );
        let sig_input = format!("sig1={params_str}");
        let sig_base = format!(
            "\"@method\": POST\n\"@target-uri\": {uri}\n\"@authority\": localhost\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(b"test-secret-12345678".to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", "localhost")
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let res = verify_signature(&cfg, &parts, &parts.uri, body);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("missing Content-Digest header"));
    }

    #[test]
    fn test_rfc9421_path_and_query_signature() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"{\"action\":\"restart\"}";
        let path = "/v1/namespaces/challenges/instances/test-1/restart";
        let uri = "/v1/namespaces/challenges/instances/test-1/restart?dryRun=true";

        let digest_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            Sha256::digest(body),
        );
        let content_digest = format!("sha-256=:{digest_b64}:");

        // Client covers @method, @path, @query, @authority, and content-digest (RFC 9421)
        let params_str = format!(
            "(\"@method\" \"@path\" \"@query\" \"@authority\" \"content-digest\");created={now};keyid=\"test-key\""
        );
        let sig_input = format!("sig1={params_str}");
        let sig_base = format!(
            "\"@method\": POST\n\"@path\": {path}\n\"@query\": ?dryRun=true\n\"@authority\": localhost\n\"content-digest\": {content_digest}\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(b"test-secret-12345678".to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", "localhost")
            .header("content-digest", content_digest)
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let verified = verify_signature(&cfg, &parts, &parts.uri, body);
        assert_eq!(verified.unwrap(), "test-key");
    }

    #[test]
    fn test_rfc9421_query_required_when_query_params_present() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"";
        let path = "/v1/namespaces/challenges/instances";
        let uri = "/v1/namespaces/challenges/instances?label=web";

        let params_str =
            format!("(\"@method\" \"@path\" \"@authority\");created={now};keyid=\"test-key\"");
        let sig_input = format!("sig1={params_str}");
        let sig_base = format!(
            "\"@method\": GET\n\"@path\": {path}\n\"@authority\": localhost\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(b"test-secret-12345678".to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost")
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let res = verify_signature(&cfg, &parts, &parts.uri, body);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("missing mandatory '@query'"));
    }

    #[test]
    fn test_rfc9421_request_target_rejected() {
        let cfg = test_config();
        let now = chrono::Utc::now().timestamp() as u64;
        let body = b"";
        let uri = "/v1/namespaces/challenges/instances";

        let params_str = format!(
            "(\"@method\" \"@request-target\" \"@authority\");created={now};keyid=\"test-key\""
        );
        let sig_input = format!("sig1={params_str}");
        let sig_base = format!(
            "\"@method\": GET\n\"@request-target\": {uri}\n\"@authority\": localhost\n\"@signature-params\": {params_str}"
        );

        let key = SharedKey::HmacSha256(b"test-secret-12345678".to_vec());
        let sig_bytes = key.sign(sig_base.as_bytes()).unwrap();
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes);
        let signature = format!("sig1=:{sig_b64}:");

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost")
            .header("signature-input", sig_input)
            .header("signature", signature)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let res = verify_signature(&cfg, &parts, &parts.uri, body);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .contains("missing mandatory target component")
        );
    }
}

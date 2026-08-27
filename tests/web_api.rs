//! Integration tests for the web API.
//!
//! Uses `tower::ServiceExt::oneshot` to drive the axum router in-process
//! without starting a real TCP server.
//!
//! Run with:
//!   cargo test --features web --test web_api

#![cfg(feature = "web")]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt; // for .oneshot()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a WebState with a temp directory.
fn make_state() -> k7s_server::web::state::WebState {
    let dir = std::env::temp_dir().join(format!("k7s-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    k7s_server::web::state::WebState::new(dir, "127.0.0.1:0".parse().unwrap())
}

/// Get the auth token from state.
fn auth_token(state: &k7s_server::web::state::WebState) -> &str {
    &state.web_token
}

/// Extract response body as string.
async fn body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Extract response body as JSON value.
async fn body_json(response: axum::response::Response) -> k7s_deps::serde_json::Value {
    let s = body_string(response).await;
    k7s_deps::serde_json::from_str(&s).unwrap_or(k7s_deps::serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// Health endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn api_health_endpoint_returns_ok() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert_eq!(body, "ok");
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_endpoint_without_token_returns_401() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/list_contexts")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_endpoint_with_wrong_token_returns_401() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/list_contexts")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_endpoint_with_valid_token_returns_ok() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/list_contexts")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Status endpoint
// ---------------------------------------------------------------------------

/// `/api/status` used to be public; it leaks the active context and API
/// server address, so it now sits behind the token gate like everything
/// else that isn't `/health`.
#[tokio::test]
async fn status_endpoint_requires_auth() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_returns_disconnected_when_no_cluster() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    // Response is wrapped in {ok, data} envelope
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(true))
    );
    let data = json.get("data").expect("response should have data field");
    // Should indicate disconnected state (no cluster in test env)
    assert_eq!(
        data.get("connected").unwrap(),
        &k7s_deps::serde_json::Value::Bool(false)
    );
}

// ---------------------------------------------------------------------------
// /mcp and /api/events auth regression
// ---------------------------------------------------------------------------
//
// `/mcp` used to bypass `require_token` entirely: the router merged the MCP
// service AFTER `.layer(require_token)`, and axum layers only cover routes
// registered before the call. These tests pin the fix — an unauthenticated
// client must never reach the MCP transport or the SSE event stream (which
// fans out `shell-out:{id}` terminal output to every subscriber).

#[tokio::test]
async fn mcp_endpoint_without_token_returns_401() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/mcp")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_endpoint_with_valid_token_passes_auth() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/mcp")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request must clear the auth gate — whatever the MCP transport
    // replies with (200/400 on a minimal initialize body), it must not be
    // an auth rejection.
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn events_endpoint_without_token_returns_401() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn events_endpoint_with_valid_token_returns_200() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Prefs round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefs_round_trip() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    // Save prefs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/invoke/save_prefs")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(r#"{"prefs":{"theme":"dark","language":"zh"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok").unwrap(),
        &k7s_deps::serde_json::Value::Bool(true)
    );

    // Load prefs
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/load_prefs")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok").unwrap(),
        &k7s_deps::serde_json::Value::Bool(true)
    );
    // The prefs data should be present
    assert!(json.get("data").is_some());
}

// ---------------------------------------------------------------------------
// Not-implemented catch-all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unimplemented_endpoint_returns_ok_false() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/nonexistent_command")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // The catch-all handler returns 200 with { ok: false, error: "..." }
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok").unwrap(),
        &k7s_deps::serde_json::Value::Bool(false)
    );
    assert!(json.get("error").is_some());
}

// ---------------------------------------------------------------------------
// Import kubeconfig content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn import_kubeconfig_parses_valid_yaml() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let kubeconfig = k7s_deps::serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "test", "cluster": {"server": "https://127.0.0.1:6443"}}],
        "contexts": [{"name": "test", "context": {"cluster": "test", "user": "test"}}],
        "users": [{"name": "test", "user": {}}],
        "current-context": "test"
    });

    let body = k7s_deps::serde_json::json!({
        "filename": "test.yaml",
        "contents": k7s_deps::serde_json::to_string(&kubeconfig).unwrap()
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/import_kubeconfig_content")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(true))
    );
    // Response should contain the parsed context list
    let data = json.get("data").expect("response should have data field");
    assert!(data.get("contexts").is_some(), "data should have contexts");
    assert!(data.get("path").is_some(), "data should have path");
}

#[tokio::test]
async fn import_kubeconfig_rejects_invalid_yaml() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let body = k7s_deps::serde_json::json!({
        "filename": "bad.yaml",
        "contents": "not: valid: yaml: [[["
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/import_kubeconfig_content")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
    assert!(json.get("error").is_some());
}

// ---------------------------------------------------------------------------
// Connect without cluster
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_without_kubeconfig_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/connect")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(r#"{"context":"nonexistent-context"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    // Should fail since the context doesn't exist in the test env
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
    assert!(json.get("error").is_some());
}

// ---------------------------------------------------------------------------
// Resource endpoints without connection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_yaml_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/get_yaml")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"pods","namespace":"default","name":"test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

#[tokio::test]
async fn get_events_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/get_events")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"pods","namespace":"default","name":"test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

#[tokio::test]
async fn get_properties_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/get_properties")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"pods","namespace":"default","name":"test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

#[tokio::test]
async fn get_secret_data_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/get_secret_data")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(r#"{"namespace":"default","name":"my-secret"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

// ---------------------------------------------------------------------------
// Mutation endpoints without connection (should fail gracefully)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_yaml_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/apply_yaml")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"configmaps","namespace":"default","name":"test","yaml":"apiVersion: v1\nkind: ConfigMap"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
    assert!(json.get("error").is_some());
}

#[tokio::test]
async fn delete_resource_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/delete_resource")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"pods","namespace":"default","name":"test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

#[tokio::test]
async fn scale_resource_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/scale_resource")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(
                    r#"{"kind":"deployments","namespace":"default","name":"test","replicas":3}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

// ---------------------------------------------------------------------------
// SSE events endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_endpoint_returns_sse() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "content-type should be SSE: {content_type}"
    );
}

// ---------------------------------------------------------------------------
// Default kubeconfig path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_kubeconfig_path_returns_value() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/default_kubeconfig_path")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(true))
    );
    assert!(json.get("data").is_some(), "should return the default path");
}

// ---------------------------------------------------------------------------
// List endpoints without connection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_endpoints_without_connection_returns_error() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/list_endpoints")
                .method("POST")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json.get("ok"),
        Some(&k7s_deps::serde_json::Value::Bool(false))
    );
}

// ---------------------------------------------------------------------------
// Registry dispatch — the dynamic /invoke/{cmd} route

/// The dynamic catch-all resolves registry commands with the same envelope
/// the hand-written handlers used: `{ok: true, data}` on success.
#[tokio::test]
async fn invoke_registry_dispatches_known_command() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state.clone());

    // default_kubeconfig_path is a registry command with no arguments.
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/invoke/default_kubeconfig_path")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", auth_token(&state)),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert!(body.get("data").is_some());
}

/// Unknown commands come back as `{ok: false, error}` — not a bare 404 — so
/// the frontend's error path stays uniform.
#[tokio::test]
async fn invoke_registry_rejects_unknown_command() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state.clone());

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/invoke/definitely_not_a_command")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", auth_token(&state)),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .contains("unknown command"));
}

/// Malformed arguments surface the registry's deserialization error instead
/// of a transport-level rejection.
#[tokio::test]
async fn invoke_registry_reports_bad_arguments() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state.clone());

    // get_yaml needs kind/namespace/name strings; send wrong types.
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/invoke/get_yaml")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", auth_token(&state)),
                )
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"kind": 42}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_json(response).await;
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .contains("bad arguments"));
}

/// `/api/version` reports the server crate version behind the auth gate.
#[tokio::test]
async fn version_endpoint_reports_version() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state.clone());

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/version")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", auth_token(&state)),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(true));
    let data = body.get("data").unwrap();
    assert!(data.get("version").and_then(|v| v.as_str()).is_some());
    assert_eq!(data.get("bin").and_then(|v| v.as_str()), Some("k7s-web"));
}

/// Without a token the version endpoint is rejected like other /api routes.
#[tokio::test]
async fn version_endpoint_requires_token() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

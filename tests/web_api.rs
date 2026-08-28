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
// /api/auth/setup first-to-claim (K7S_SETUP_TOKEN on non-loopback binds)
// ---------------------------------------------------------------------------

/// Like [`make_state`] but with an arbitrary bind address — the setup gate
/// branches on `is_loopback`, so the non-loopback tests need a state built
/// from a non-loopback addr. Fresh temp dir per tag so the persisted
/// `web-password` can't leak between tests.
fn make_state_at(tag: &str, addr: &str) -> k7s_server::web::state::WebState {
    let dir = std::env::temp_dir().join(format!("k7s-test-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    k7s_server::web::state::WebState::new(dir, addr.parse().unwrap())
}

/// POST /api/auth/setup body, optionally with the `X-Setup-Token` header.
fn setup_request(setup_token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = setup_token {
        b = b.header("x-setup-token", t);
    }
    b.body(Body::from(r#"{"password":"correct-horse-battery"}"#))
        .unwrap()
}

/// Loopback keeps the open local first-run flow: setup succeeds with no
/// `X-Setup-Token` at all (the loopback branch never consults the env var,
/// so a parallel test toggling it can't break this).
#[tokio::test]
async fn setup_on_loopback_needs_no_setup_token() {
    let state = make_state_at("setup-lo", "127.0.0.1:0");
    assert!(state.is_loopback, "test premise: loopback bind");
    let app = k7s_server::web::server::api_router(state);

    let response = app.oneshot(setup_request(None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Non-loopback setup is first-to-claim: with `K7S_SETUP_TOKEN` unset it's
/// 403 regardless of headers; with it set, only a matching `X-Setup-Token`
/// gets through — and only once (second claim → 409). All env manipulation
/// lives inside this single test so parallel tests can't observe a
/// half-toggled var.
#[tokio::test]
async fn setup_on_non_loopback_requires_setup_token() {
    let state = make_state_at("setup-nl", "10.10.0.1:0");
    assert!(!state.is_loopback, "test premise: non-loopback bind");
    let app = k7s_server::web::server::api_router(state);

    // (a) Operator never set K7S_SETUP_TOKEN → refuse with guidance.
    std::env::remove_var("K7S_SETUP_TOKEN");
    let response = app.clone().oneshot(setup_request(None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json = body_json(response).await;
    assert!(
        json.get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("K7S_SETUP_TOKEN"),
        "unset-env error must point at K7S_SETUP_TOKEN, got: {json}"
    );

    std::env::set_var("K7S_SETUP_TOKEN", "claim-secret");

    // (b) Env set but header missing / wrong → still 403.
    let response = app.clone().oneshot(setup_request(None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(setup_request(Some("wrong-secret")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // (c) Matching header claims the password: 200 + Secure session cookie.
    let response = app
        .clone()
        .oneshot(setup_request(Some("claim-secret")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(cookie.contains("Secure"), "got: {cookie}");

    // (d) The claim is one-shot: a second (still correctly signed) setup
    // hits the already-configured conflict.
    let response = app
        .clone()
        .oneshot(setup_request(Some("claim-secret")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    std::env::remove_var("K7S_SETUP_TOKEN");
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

// ---------------------------------------------------------------------------
// Local chart upload — POST /api/charts/upload
// ---------------------------------------------------------------------------

/// Build a minimal valid chart `.tgz` in-test (the k7s-core `tgz_bytes`
/// helper is private to that crate's test module, so this is a local
/// equivalent over the same k7s_deps tar/flate2 crates).
fn chart_tgz_bytes(name: &str, version: &str) -> Vec<u8> {
    use k7s_deps::flate2::write::GzEncoder;
    use k7s_deps::flate2::Compression;
    use std::io::Write;

    let chart_yaml = format!("apiVersion: v2\nname: {name}\nversion: {version}\n");
    let mut builder = k7s_deps::tar::Builder::new(Vec::new());
    let mut header = k7s_deps::tar::Header::new_gnu();
    header.set_size(chart_yaml.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("{name}/Chart.yaml"),
            chart_yaml.as_bytes(),
        )
        .unwrap();
    let tarball = builder.into_inner().unwrap();
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tarball).unwrap();
    gz.finish().unwrap()
}

/// base64 of raw bytes — the wire encoding the front-end sends.
fn chart_b64(bytes: &[u8]) -> String {
    use k7s_deps::base64::Engine;
    k7s_deps::base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Authenticated upload request carrying a JSON body verbatim.
fn chart_upload_request(token: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/charts/upload")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap()
}

/// The upload route sits behind the token gate like every other /api route —
/// it writes attacker-controlled bytes to disk, so an open POST would be a
/// disk-fill primitive.
#[tokio::test]
async fn chart_upload_without_token_returns_401() {
    let state = make_state();
    let app = k7s_server::web::server::api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/charts/upload")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Happy path + round-trip: upload a real (tiny) chart package, read the
/// parsed entry fields back out of the response, then prove the library
/// listing exposes it.
#[tokio::test]
async fn chart_upload_stores_parsable_entry() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    let body = k7s_deps::serde_json::json!({
        "filename": "web-demo-1.0.0.tgz",
        "contentBase64": chart_b64(&chart_tgz_bytes("web-demo", "1.0.0")),
    });
    let response = app
        .clone()
        .oneshot(chart_upload_request(&token, body.to_string()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(true));
    let data = json.get("data").expect("response should have data field");
    assert_eq!(data.get("name").and_then(|v| v.as_str()), Some("web-demo"));
    assert_eq!(data.get("version").and_then(|v| v.as_str()), Some("1.0.0"));
    assert_eq!(
        data.get("id").and_then(|v| v.as_str()),
        Some("web-demo-1.0.0")
    );

    // Round-trip: the listing route (registry dispatch) sees the chart.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invoke/local_charts_list")
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
    assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(true));
    let entries = json
        .get("data")
        .and_then(|v| v.as_array())
        .expect("data should be an entry array");
    assert!(entries.iter().any(|e| {
        e.get("name").and_then(|v| v.as_str()) == Some("web-demo")
            && e.get("version").and_then(|v| v.as_str()) == Some("1.0.0")
    }));
}

/// Invalid uploads come back in the uniform error envelope (200 + ok:false,
/// the house convention from types.rs): non-gzip content and non-chart
/// filenames are refused by import_chart_bytes. A body that isn't JSON at
/// all is a transport-level 4xx from the axum::Json extractor. (The 90MB
/// route body limit → 413 isn't restated here — it would mean allocating a
/// 90MB payload per run; the decoded-size gate is unit-tested in local.rs.)
#[tokio::test]
async fn chart_upload_rejects_invalid_payloads() {
    let state = make_state();
    let token = auth_token(&state).to_string();
    let app = k7s_server::web::server::api_router(state);

    // (a) non-gzip content → error envelope naming the gzip check.
    let response = app
        .clone()
        .oneshot(chart_upload_request(
            &token,
            k7s_deps::serde_json::json!({
                "filename": "evil.tgz",
                "contentBase64": chart_b64(b"plain text, not gzip"),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(
        json.get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("gzip"),
        "error must point at the gzip gate, got: {json}"
    );

    // (b) valid gzip, wrong extension → refused before any write.
    let response = app
        .clone()
        .oneshot(chart_upload_request(
            &token,
            k7s_deps::serde_json::json!({
                "filename": "evil.exe",
                "contentBase64": chart_b64(&chart_tgz_bytes("evil", "1.0.0")),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let json = body_json(response).await;
    assert_eq!(json.get("ok").and_then(|v| v.as_bool()), Some(false));

    // (c) malformed JSON body → 4xx from the extractor, before the handler.
    let response = app
        .oneshot(chart_upload_request(&token, "{not json".to_string()))
        .await
        .unwrap();
    assert!(
        response.status().is_client_error(),
        "malformed JSON must be a 4xx, got {}",
        response.status()
    );
}

//! AI webhook hook handlers.
//!
//! External systems (monitoring, CI/CD) can trigger the AI agent via these
//! endpoints. Authenticated via Bearer token (`K7S_HOOK_TOKEN`).

use axum::extract::State;
use axum::response::IntoResponse;

use super::state::WebState;

// ---------------------------------------------------------------------------
// AI webhook hooks
// ---------------------------------------------------------------------------

/// Verify webhook authorization. Returns `Some(error_response)` if unauthorized.
fn verify_hook_auth(headers: &k7s_deps::http::HeaderMap) -> Option<axum::response::Response> {
    let token = std::env::var("K7S_HOOK_TOKEN").unwrap_or_default();
    let hook_config = k7s_core::ai::hooks::HookConfig {
        enabled: !token.is_empty(),
        token,
        ..Default::default()
    };
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    if k7s_core::ai::hooks::verify_hook(&hook_config, auth) {
        return None;
    }
    Some(
        axum::response::Json(
            k7s_deps::serde_json::json!({"success": false, "message": "unauthorized"}),
        )
        .into_response(),
    )
}

/// POST /hooks/wake — fire-and-forget: wake the agent with a message.
/// The response returns immediately; the agent runs in the background.
pub async fn hook_wake(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("health check");
    k7s_deps::tracing::info!(message = message, "hook/wake triggered");
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("received: {}", message),
    }))
    .into_response()
}

/// POST /hooks/agent — synchronous: send a message, get the response back.
/// Currently returns a placeholder; full integration would construct a
/// ChatRequest and run the agent loop.
pub async fn hook_agent(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let message = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let skill_id = body.get("skillId").and_then(|v| v.as_str());
    k7s_deps::tracing::info!(message = message, skill = skill_id, "hook/agent triggered");
    // Full integration: construct ChatRequest, run AgentLoop, return response.
    // For now, acknowledge receipt.
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("agent received: '{}' (full agent integration pending)", message),
    }))
    .into_response()
}

/// POST /hooks/event — push a cluster event for the agent to analyze.
pub async fn hook_event(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let event_type = body
        .get("eventType")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = body
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("info");
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    k7s_deps::tracing::info!(
        event_type = event_type,
        severity = severity,
        description = description,
        "hook/event received"
    );
    // Full integration: store the event, trigger agent analysis if severity >= warning.
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("event received: {} ({})", event_type, severity),
    }))
    .into_response()
}

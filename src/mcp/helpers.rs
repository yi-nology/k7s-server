//! Helper functions used by tool implementations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use k7s_deps::tokio::sync::mpsc;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};
use serde::Serialize;

use k7s_core::error::AppError;
use k7s_core::kube::{
    manager::{ClientManager, ForwardDto},
    ResourceKind,
};
use k7s_deps::kube::Client;

// ---------------------------------------------------------------------------
// Error / result helpers
// ---------------------------------------------------------------------------

/// Convert an `AppError` (or anything `Display`-able) into a tool error the
/// AI client shows inline. `McpError::internal_error` would also work, but
/// marking these as "the tool ran" lets the model see the message rather
/// than a protocol-level error code.
pub fn tool_error(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Helper: serialise `value` to pretty JSON and wrap it as a single
/// text-content `CallToolResult`. AI clients that understand `structuredContent`
/// (MCP `2026-07-28`) also see the same JSON there.
pub fn json_result<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let text = k7s_deps::serde_json::to_string_pretty(value).map_err(|e| tool_error(e))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// Refuse writes for kinds whose YAML must never be applied (mirrors
/// `commands::ensure_writable` so the MCP and the Tauri shell can't drift).
pub fn ensure_writable(kind: &str) -> Result<(), AppError> {
    if kind == ResourceKind::Helm.id() {
        return Err(AppError::Other(
            "Helm releases are read-only here -- use `helm upgrade` to change one".into(),
        ));
    }
    if kind == "secrets" {
        return Err(AppError::Other("editing Secrets is disabled".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unique-id utilities
// ---------------------------------------------------------------------------

static SEQ: AtomicU64 = AtomicU64::new(1);

pub fn shell_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Lightweight unique-ish suffix. We don't need cryptographic uniqueness --
/// just enough that two consecutive tool calls produce different ids and
/// can't collide with each other or with a stale session.
pub fn uuid_like(counter: &mut u64) -> u64 {
    *counter = SEQ.fetch_add(1, Ordering::Relaxed);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ *counter
}

// ---------------------------------------------------------------------------
// Port-forward helper
// ---------------------------------------------------------------------------

/// Shared by the pod and Service port-forward paths. By the time the Service
/// has been resolved to a pod, it's just a pod forward.
pub async fn spawn_forward(
    manager: Arc<ClientManager>,
    client: Client,
    namespace: String,
    pod: String,
    service: Option<(String, u16)>,
    remote_port: u16,
    local_port: u16,
) -> Result<ForwardDto, AppError> {
    use k7s_deps::tokio::sync::oneshot;
    let (ready_tx, ready_rx) = oneshot::channel::<Result<u16, String>>();
    let (err_tx, mut err_rx) = mpsc::channel::<String>(8);

    let ns = namespace.clone();
    let p = pod.clone();
    let task = k7s_deps::tokio::spawn(async move {
        k7s_core::kube::portforward::run_port_forward(
            client,
            ns,
            p,
            remote_port,
            local_port,
            ready_tx,
            err_tx,
        )
        .await;
    });

    // Block until the listener is bound (or report the bind error).
    // `local_port` is passed through to the port-forward task; 0 means
    // "ask the OS for a free port".
    let chosen_local = ready_rx
        .await
        .map_err(|_| AppError::Other("port-forward task ended before binding".into()))?
        .map_err(AppError::Kube)?;

    let (service_name, service_port) = match service {
        Some((name, port)) => (Some(name), (port != remote_port).then_some(port)),
        None => (None, None),
    };
    let label = service_name.clone().unwrap_or_else(|| pod.clone());
    let id = format!("pf-{label}-{}", uuid_like(&mut shell_seq()));
    let dto = ForwardDto {
        id: id.clone(),
        namespace,
        pod,
        service: service_name,
        remote_port,
        service_port,
        local_port: chosen_local,
        error: None,
    };
    manager.add_forward(dto.clone(), task).await;

    // Relay per-connection failures onto the forward. This task is owned
    // by the manager, so it'll be aborted on `manager.reset()`.
    let manager_for_err = manager.clone();
    let id_for_err = id.clone();
    k7s_deps::tokio::spawn(async move {
        while let Some(err) = err_rx.recv().await {
            manager_for_err.set_forward_error(&id_for_err, err).await;
        }
    });

    Ok(dto)
}

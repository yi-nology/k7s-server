//! Pod-level tool bodies: logs, exec, pod diagnosis, and pod file
//! operations.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, DeleteParams};
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};

use k7s_core::error::AppError;
use k7s_core::kube::{manager::ClientManager, pod_files, restart};

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

pub(crate) async fn get_logs(
    manager: &Arc<ClientManager>,
    p: LogsParams,
) -> Result<CallToolResult, McpError> {
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    let logs = kube_api::pod_logs(
        manager,
        &p.namespace,
        &p.pod,
        container,
        p.tail,
        p.since_seconds,
        p.previous,
    )
    .await
    .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(logs)]))
}

pub(crate) async fn restart_pod(
    manager: &Arc<ClientManager>,
    p: NameNamespaceParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let api: Api<Pod> = Api::namespaced(client, &p.namespace);
    let pod = api
        .get(&p.name)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    if !restart::has_controller(&pod) {
        return Err(tool_error(AppError::Other(format!(
            "{} has no controller -- deleting it would not recreate it. Use Delete instead.",
            p.name
        ))));
    }
    api.delete(&p.name, &DeleteParams::default())
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "pod {}/{} deleted for restart",
        p.namespace, p.name
    ))]))
}

pub(crate) async fn diagnose_pod(
    manager: &Arc<ClientManager>,
    p: DiagnosePodParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let diagnosis = k7s_core::kube::pod_diagnosis::diagnose_pod(client, &p.namespace, &p.pod)
        .await
        .map_err(tool_error)?;
    json_result(&diagnosis)
}

// -----------------------------------------------------------------------
// One-shot exec
// -----------------------------------------------------------------------

pub(crate) async fn exec_command(
    manager: &Arc<ClientManager>,
    p: ExecParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), p.command];
    let out = kube_api::exec_capture(&client, &p.namespace, &p.pod, container, argv)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
}

// -----------------------------------------------------------------------
// Pod file operations
// -----------------------------------------------------------------------

pub(crate) async fn pod_list_files(
    manager: &Arc<ClientManager>,
    p: PodFileParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    let entries = pod_files::list_dir(client, &p.namespace, &p.pod, container, &p.path)
        .await
        .map_err(tool_error)?;
    json_result(&entries)
}

pub(crate) async fn pod_read_file(
    manager: &Arc<ClientManager>,
    p: PodFileParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    let text = pod_files::read_file(client, &p.namespace, &p.pod, container, &p.path)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

pub(crate) async fn pod_write_file(
    manager: &Arc<ClientManager>,
    p: PodFileWriteParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    pod_files::write_file(client, &p.namespace, &p.pod, container, &p.path, &p.content)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text("written")]))
}

pub(crate) async fn pod_download_file(
    manager: &Arc<ClientManager>,
    p: PodFileParams,
) -> Result<CallToolResult, McpError> {
    use k7s_deps::base64::Engine;
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    let bytes = pod_files::download_path(client, &p.namespace, &p.pod, container, &p.path)
        .await
        .map_err(tool_error)?;
    let b64 = k7s_deps::base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(CallToolResult::success(vec![ContentBlock::text(b64)]))
}

pub(crate) async fn pod_upload_file(
    manager: &Arc<ClientManager>,
    p: PodFileUploadParams,
) -> Result<CallToolResult, McpError> {
    use k7s_deps::base64::Engine;
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let bytes = k7s_deps::base64::engine::general_purpose::STANDARD
        .decode(&p.tar_b64)
        .map_err(|e| tool_error(AppError::Other(format!("base64 decode: {e}"))))?;
    let container = if p.container.is_empty() {
        None
    } else {
        Some(p.container.as_str())
    };
    pod_files::upload_path(client, &p.namespace, &p.pod, container, &p.dest_dir, &bytes)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        "uploaded",
    )]))
}

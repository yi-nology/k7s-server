//! Workload tool bodies: scale, rollout restart / status, CronJob triggers,
//! and HPA status.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use k7s_deps::kube::api::{Patch, PatchParams};
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};

use k7s_core::error::AppError;
use k7s_core::kube::{manager::ClientManager, restart};

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

pub(crate) async fn scale_resource(
    manager: &Arc<ClientManager>,
    p: ScaleParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, &p.kind, &p.namespace, manager)
        .await
        .map_err(tool_error)?;
    let patch = Patch::Merge(k7s_deps::serde_json::json!({ "spec": { "replicas": p.replicas } }));
    api.patch(&p.name, &PatchParams::default(), &patch)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "{} {}/{} scaled to {}",
        p.kind, p.namespace, p.name, p.replicas
    ))]))
}

pub(crate) async fn restart_rollout(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    if !restart::is_rollout_kind(&p.kind) {
        return Err(tool_error(AppError::Other(format!(
            "{} cannot be rollout-restarted",
            p.kind
        ))));
    }
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, &p.kind, &p.namespace, manager)
        .await
        .map_err(tool_error)?;
    let now = k7s_deps::chrono::Utc::now().to_rfc3339();
    let patch = Patch::Merge(restart::restart_patch(&now));
    api.patch(&p.name, &PatchParams::default(), &patch)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "rollout restart issued for {} {}/{}",
        p.kind, p.namespace, p.name
    ))]))
}

pub(crate) async fn rollout_status(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let status = kube_api::rollout_status(manager, &p.kind, &p.namespace, &p.name)
        .await
        .map_err(tool_error)?;
    json_result(&status)
}

pub(crate) async fn trigger_cronjob(
    manager: &Arc<ClientManager>,
    p: NameNamespaceNameParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let job_name = kube_api::trigger_cronjob(&client, &p.namespace, &p.name)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "created job {}/{}",
        p.namespace, job_name
    ))]))
}

pub(crate) async fn hpa_status(
    manager: &Arc<ClientManager>,
    p: HpaStatusParams,
) -> Result<CallToolResult, McpError> {
    let result = k7s_core::ai::tools::impls::hpa_status_impl(manager, &p.namespace)
        .await
        .map_err(tool_error)?;
    json_result(&result)
}

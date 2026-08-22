//! Helm tool bodies: release operations (install / upgrade / uninstall /
//! rollback / history) and chart repository management.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};

use k7s_core::kube::{helm_market, helm_ops, manager::ClientManager};

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

// === Helm tools ===
// Helm operation and chart repository tools

// -----------------------------------------------------------------------
// Helm operations (install / upgrade / uninstall / rollback / history)
// -----------------------------------------------------------------------

pub(crate) async fn helm_install(
    manager: &Arc<ClientManager>,
    p: HelmInstallParams,
) -> Result<CallToolResult, McpError> {
    let sink = manager.sink();
    let op = helm_ops::HelmOp::Install(helm_ops::InstallArgs {
        release: p.release,
        chart: p.chart,
        version: p.version,
        namespace: p.namespace,
        kubeconfig: None,
        values: p.values,
        dry_run: p.dry_run,
        create_namespace: p.create_namespace,
    });
    let result = helm_ops::run_op(op, sink).await.map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn helm_upgrade(
    manager: &Arc<ClientManager>,
    p: HelmUpgradeParams,
) -> Result<CallToolResult, McpError> {
    let sink = manager.sink();
    let op = helm_ops::HelmOp::Upgrade(helm_ops::UpgradeArgs {
        release: p.release,
        chart: p.chart,
        version: p.version,
        namespace: p.namespace,
        kubeconfig: None,
        values: p.values,
        dry_run: p.dry_run,
        reuse_values: p.reuse_values,
        rollback_on_failure: p.rollback_on_failure,
    });
    let result = helm_ops::run_op(op, sink).await.map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn helm_uninstall(
    manager: &Arc<ClientManager>,
    p: HelmUninstallParams,
) -> Result<CallToolResult, McpError> {
    let sink = manager.sink();
    let op = helm_ops::HelmOp::Uninstall(helm_ops::UninstallArgs {
        release: p.release,
        namespace: p.namespace,
        kubeconfig: None,
        keep_history: p.keep_history,
    });
    let result = helm_ops::run_op(op, sink).await.map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn helm_rollback(
    manager: &Arc<ClientManager>,
    p: HelmRollbackParams,
) -> Result<CallToolResult, McpError> {
    let sink = manager.sink();
    let op = helm_ops::HelmOp::Rollback(helm_ops::RollbackArgs {
        release: p.release,
        namespace: p.namespace,
        revision: p.revision,
        kubeconfig: None,
    });
    let result = helm_ops::run_op(op, sink).await.map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn helm_history(
    p: HelmHistoryParams,
) -> Result<CallToolResult, McpError> {
    let rows = helm_ops::release_history(&p.release, &p.namespace, None)
        .await
        .map_err(tool_error)?;
    json_result(&rows)
}

pub(crate) async fn helm_manifest_revision(
    manager: &Arc<ClientManager>,
    p: HelmManifestRevisionParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let manifest =
        k7s_core::kube::helm::helm_manifest_revision(client, &p.namespace, &p.name, p.revision)
            .await
            .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(manifest)]))
}

pub(crate) async fn helm_values_revision(
    manager: &Arc<ClientManager>,
    p: HelmValuesRevisionParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let values =
        k7s_core::kube::helm::helm_values_revision(client, &p.namespace, &p.name, p.revision)
            .await
            .map_err(tool_error)?;
    json_result(&values)
}

pub(crate) async fn helm_show_values(
    p: HelmShowValuesParams,
) -> Result<CallToolResult, McpError> {
    let values = helm_ops::render_default_values(&p.chart, &p.version, None)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(values)]))
}

// -----------------------------------------------------------------------
// Helm chart repository management
// -----------------------------------------------------------------------

pub(crate) async fn helm_list_repos() -> Result<CallToolResult, McpError> {
    let repos = helm_market::list_repos().map_err(tool_error)?;
    json_result(&repos)
}

pub(crate) async fn helm_search_charts(
    p: HelmSearchParams,
) -> Result<CallToolResult, McpError> {
    let charts = helm_market::search_charts(&p.query).map_err(tool_error)?;
    json_result(&charts)
}

pub(crate) async fn helm_add_repo(p: HelmRepoParams) -> Result<CallToolResult, McpError> {
    let repo = helm_market::add_repo(&p.name, &p.url, &p.description).map_err(tool_error)?;
    json_result(&repo)
}

pub(crate) async fn helm_remove_repo(p: HelmRepoNameParams) -> Result<CallToolResult, McpError> {
    helm_market::remove_repo(&p.name).map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text("removed")]))
}

pub(crate) async fn helm_update_repo(p: HelmRepoNameParams) -> Result<CallToolResult, McpError> {
    let repo = helm_market::update_repo_index(&p.name)
        .await
        .map_err(tool_error)?;
    json_result(&repo)
}

// -----------------------------------------------------------------------
// Unified Helm release operation
// -----------------------------------------------------------------------

pub(crate) async fn helm_release(
    manager: &Arc<ClientManager>,
    p: HelmReleaseParams,
) -> Result<CallToolResult, McpError> {
    match p.action.as_str() {
        "install" => {
            let params = HelmInstallParams {
                release: p.release.unwrap_or_default(),
                chart: p.chart.unwrap_or_default(),
                version: p.version.clone().unwrap_or_default(),
                namespace: p.namespace.clone().unwrap_or_default(),
                values: p.values.unwrap_or_default(),
                dry_run: false,
                create_namespace: false,
            };
            helm_install(manager, params).await
        }
        "upgrade" => {
            let params = HelmUpgradeParams {
                release: p.release.unwrap_or_default(),
                chart: p.chart.unwrap_or_default(),
                version: p.version.clone().unwrap_or_default(),
                namespace: p.namespace.clone().unwrap_or_default(),
                values: p.values.unwrap_or_default(),
                dry_run: false,
                reuse_values: false,
                rollback_on_failure: false,
            };
            helm_upgrade(manager, params).await
        }
        "uninstall" => {
            let params = HelmUninstallParams {
                release: p.release.unwrap_or_default(),
                namespace: p.namespace.clone().unwrap_or_default(),
                keep_history: false,
            };
            helm_uninstall(manager, params).await
        }
        "rollback" => {
            let params = HelmRollbackParams {
                release: p.release.unwrap_or_default(),
                namespace: p.namespace.clone().unwrap_or_default(),
                revision: p.revision,
            };
            helm_rollback(manager, params).await
        }
        _ => Err(McpError::invalid_params(
            format!(
                "unknown action '{}': use install|upgrade|uninstall|rollback",
                p.action
            ),
            None,
        )),
    }
}

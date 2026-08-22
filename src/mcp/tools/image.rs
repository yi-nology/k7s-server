//! Image tool bodies: registry queries and skopeo-based image sync /
//! import for air-gapped clusters.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use rmcp::model::{CallToolResult, ErrorData as McpError};

use k7s_core::error::AppError;
use k7s_core::kube::{image_archive, image_sync, imagerepo, manager::ClientManager};

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::params::*;

// -----------------------------------------------------------------------
// Image registry queries
// -----------------------------------------------------------------------

pub(crate) async fn image_registry_tags(
    p: ImageRegistryRepoParams,
) -> Result<CallToolResult, McpError> {
    let reg = imagerepo::list_registries()
        .map_err(tool_error)?
        .into_iter()
        .find(|r| r.name == p.name)
        .ok_or_else(|| {
            tool_error(AppError::NotFound(format!(
                "registry '{}' not found",
                p.name
            )))
        })?;
    let tags = imagerepo::list_tags(&reg, &p.repo)
        .await
        .map_err(tool_error)?;
    json_result(&tags)
}

pub(crate) async fn image_registry_manifest(
    p: ImageRegistryManifestParams,
) -> Result<CallToolResult, McpError> {
    let reg = imagerepo::list_registries()
        .map_err(tool_error)?
        .into_iter()
        .find(|r| r.name == p.name)
        .ok_or_else(|| {
            tool_error(AppError::NotFound(format!(
                "registry '{}' not found",
                p.name
            )))
        })?;
    let manifest = imagerepo::manifest(&reg, &p.repo, &p.tag)
        .await
        .map_err(tool_error)?;
    json_result(&manifest)
}

// -----------------------------------------------------------------------
// Image sync / import (air-gapped clusters)
// -----------------------------------------------------------------------

pub(crate) async fn image_sync_status() -> Result<CallToolResult, McpError> {
    let avail = image_sync::check_skopeo().await;
    json_result(&avail)
}

pub(crate) async fn image_copy(
    manager: &Arc<ClientManager>,
    p: ImageCopyParams,
) -> Result<CallToolResult, McpError> {
    let sink = manager.sink();
    let src_creds = if p.src_creds.is_empty() {
        None
    } else {
        Some(p.src_creds.as_str())
    };
    let result = image_sync::copy_image(
        &p.source,
        &p.dest_registry,
        &p.dest_repo,
        &p.dest_tag,
        src_creds,
        p.insecure_src,
        p.insecure_dest,
        sink,
    )
    .await
    .map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn image_inspect_archive(
    p: ImageArchiveParams,
) -> Result<CallToolResult, McpError> {
    let info = image_archive::inspect_archive(&p.tar_path)
        .await
        .map_err(tool_error)?;
    json_result(&info)
}

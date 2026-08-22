//! Shell tool bodies: interactive pod/node shells, shell I/O, and
//! port-forwards.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, DeleteParams, ListParams, PostParams};
use k7s_deps::kube::ResourceExt;
use k7s_deps::tokio::sync::mpsc;
use k7s_deps::tokio::task::JoinHandle;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};
use serde::Serialize;

use k7s_core::error::AppError;
use k7s_core::kube::{
    manager::{ClientManager, ForwardDto, ShellSession},
    nodeshell,
    portforward,
};

use crate::mcp::helpers::{json_result, shell_seq, spawn_forward, tool_error, uuid_like};
use crate::mcp::kube_api;
use crate::mcp::params::*;

// === Shell tools ===
// Shell, exec, port-forward, pod-file, and convenience tools

// -----------------------------------------------------------------------
// Port-forwarding
// -----------------------------------------------------------------------

pub(crate) async fn start_port_forward(
    manager: &Arc<ClientManager>,
    p: StartPortForwardParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    portforward::ensure_pod(client.clone(), &p.namespace, &p.pod)
        .await
        .map_err(tool_error)?;
    let dto = spawn_forward(
        manager.clone(),
        client,
        p.namespace,
        p.pod,
        None,
        p.remote_port,
        p.local_port,
    )
    .await
    .map_err(tool_error)?;
    json_result(&dto)
}

pub(crate) async fn start_service_port_forward(
    manager: &Arc<ClientManager>,
    p: StartServiceForwardParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let (pod, target_port) =
        portforward::resolve_service(client.clone(), &p.namespace, &p.service, p.service_port)
            .await
            .map_err(tool_error)?;
    let dto = spawn_forward(
        manager.clone(),
        client,
        p.namespace,
        pod,
        Some((p.service, p.service_port)),
        target_port,
        p.local_port,
    )
    .await
    .map_err(tool_error)?;
    json_result(&dto)
}

pub(crate) async fn stop_port_forward(
    manager: &Arc<ClientManager>,
    p: StopForwardParams,
) -> Result<CallToolResult, McpError> {
    manager.remove_forward(&p.id).await;
    Ok(CallToolResult::success(vec![ContentBlock::text("stopped")]))
}

pub(crate) async fn list_port_forwards(
    manager: &Arc<ClientManager>,
) -> Result<CallToolResult, McpError> {
    let list: Vec<ForwardDto> = manager.list_forwards().await;
    json_result(&list)
}

// -----------------------------------------------------------------------
// Interactive shells
// -----------------------------------------------------------------------

pub(crate) async fn start_shell(
    manager: &Arc<ClientManager>,
    p: StartShellParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let id = format!("sh-{}-{}", p.pod, uuid_like(&mut shell_seq()),);
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>(8);
    let id_for_task = id.clone();
    let ns = p.namespace.clone();
    let pod = p.pod.clone();
    let container = p.container.clone();
    let sink = manager.sink();
    let task: JoinHandle<()> = k7s_deps::tokio::spawn(async move {
        k7s_core::kube::exec::run_shell(
            client,
            sink,
            id_for_task,
            ns,
            pod,
            container,
            String::new(),
            input_rx,
            resize_rx,
        )
        .await;
    });
    manager
        .add_shell(
            id.clone(),
            ShellSession {
                task,
                input_tx,
                resize_tx,
            },
        )
        .await;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ShellStarted {
        shell_id: String,
        namespace: String,
        pod: String,
        container: String,
    }
    json_result(&ShellStarted {
        shell_id: id,
        namespace: p.namespace,
        pod: p.pod,
        container: p.container,
    })
}

pub(crate) async fn shell_input(
    manager: &Arc<ClientManager>,
    p: ShellInputParams,
) -> Result<CallToolResult, McpError> {
    manager.shell_input(&p.shell_id, p.data.into_bytes()).await;
    Ok(CallToolResult::success(vec![ContentBlock::text("ok")]))
}

pub(crate) async fn shell_resize(
    manager: &Arc<ClientManager>,
    p: ShellResizeParams,
) -> Result<CallToolResult, McpError> {
    manager.shell_resize(&p.shell_id, p.cols, p.rows).await;
    Ok(CallToolResult::success(vec![ContentBlock::text("ok")]))
}

pub(crate) async fn stop_shell(
    manager: &Arc<ClientManager>,
    p: StopShellParams,
) -> Result<CallToolResult, McpError> {
    manager.remove_shell(&p.shell_id).await;
    Ok(CallToolResult::success(vec![ContentBlock::text("stopped")]))
}

pub(crate) async fn start_node_shell(
    manager: &Arc<ClientManager>,
    p: DrainParams,
) -> Result<CallToolResult, McpError> {
    let _ = p.timeout_secs; // Currently unused; future: surface to the user as a wait budget.
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let api: Api<Pod> = Api::namespaced(client.clone(), nodeshell::DEBUG_NAMESPACE);

    // Sweep prior debug pods for this node so a fresh session never
    // collides on a name or leaves a stale privileged pod behind.
    if let Ok(old) = api
        .list(&ListParams::default().labels(&nodeshell::node_selector(&p.node)))
        .await
    {
        for pod in old.items {
            let dp = DeleteParams {
                grace_period_seconds: Some(0),
                ..Default::default()
            };
            let _ = api.delete(&pod.name_any(), &dp).await;
        }
    }

    let pod_name = nodeshell::pod_name(&p.node, uuid_like(&mut shell_seq()));
    let image = nodeshell::DEFAULT_IMAGE.to_string();
    api.create(
        &PostParams::default(),
        &nodeshell::debug_pod_spec(&p.node, &image, &pod_name),
    )
    .await
    .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;

    // Wait for Running (up to 90s) using the shared helper, which also
    // handles the 404-cache-lag window right after create that an inline
    // poll loop would miss. On timeout the helper returns an error; we do
    // the best-effort pod cleanup (the helper deliberately does not delete,
    // leaving teardown to the caller).
    if let Err(e) = nodeshell::await_debug_pod(&api, &pod_name).await {
        let _ = api
            .delete(
                &pod_name,
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..Default::default()
                },
            )
            .await;
        return Err(tool_error(e));
    }

    let id = format!("nsh-{pod_name}");
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>(8);
    let id_for_task = id.clone();
    let pod_for_task = pod_name.clone();
    let sink = manager.sink();
    let task = k7s_deps::tokio::spawn(async move {
        k7s_core::kube::exec::run_argv(
            client,
            sink,
            id_for_task,
            nodeshell::DEBUG_NAMESPACE.to_string(),
            pod_for_task,
            "debug".to_string(),
            nodeshell::nsenter_cmd(),
            input_rx,
            resize_rx,
        )
        .await;
    });
    manager
        .add_shell(
            id.clone(),
            ShellSession {
                task,
                input_tx,
                resize_tx,
            },
        )
        .await;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct NodeShellStarted {
        shell_id: String,
        namespace: String,
        pod: String,
    }
    json_result(&NodeShellStarted {
        shell_id: id,
        namespace: nodeshell::DEBUG_NAMESPACE.to_string(),
        pod: pod_name,
    })
}

pub(crate) async fn stop_node_shell(
    manager: &Arc<ClientManager>,
    p: StopShellParams,
) -> Result<CallToolResult, McpError> {
    manager.remove_shell(&p.shell_id).await;
    if let Some(client) = manager.client().await {
        let api: Api<Pod> = Api::namespaced(client, nodeshell::DEBUG_NAMESPACE);
        // The shell_id is "nsh-<pod-name>"; strip the prefix to delete
        // the right pod.
        let pod = p
            .shell_id
            .strip_prefix("nsh-")
            .unwrap_or(&p.shell_id)
            .to_string();
        let _ = api
            .delete(
                &pod,
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..Default::default()
                },
            )
            .await;
    }
    Ok(CallToolResult::success(vec![ContentBlock::text("stopped")]))
}

// -----------------------------------------------------------------------
// Unified port-forward operation
// -----------------------------------------------------------------------

pub(crate) async fn port_forward(
    manager: &Arc<ClientManager>,
    p: PortForwardParams,
) -> Result<CallToolResult, McpError> {
    match p.action.as_str() {
        "start" => {
            let params = StartPortForwardParams {
                namespace: p.namespace.clone().unwrap_or_default(),
                pod: p.pod.unwrap_or_default(),
                remote_port: p.container_port.unwrap_or(0),
                local_port: p.local_port.unwrap_or(0),
            };
            start_port_forward(manager, params).await
        }
        "stop" => {
            let params = StopForwardParams {
                id: p.id.unwrap_or_default(),
            };
            stop_port_forward(manager, params).await
        }
        "list" => list_port_forwards(manager).await,
        _ => Err(McpError::invalid_params(
            format!("unknown action '{}': use start|stop|list", p.action),
            None,
        )),
    }
}

//! Cluster-level tool bodies: connection, generic resource read/write,
//! kinds discovery, node operations, and cluster-wide diagnostics.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use k7s_deps::kube::api::{DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};
use serde::Serialize;

use k7s_core::core::shell_common::validate_apply_yaml;
use k7s_core::error::AppError;
use k7s_core::kube::{
    client as kube_client,
    drain,
    endpoints,
    manager::{ClientManager, ImportedContext},
    templates,
};

use crate::mcp::helpers::{ensure_writable, json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

// === Connection tools ===

/// List the contexts visible in the default kubeconfig. The AI can call
/// this on startup to show the user what's available; `connect` then
/// picks one.
pub(crate) async fn list_contexts() -> Result<CallToolResult, McpError> {
    let contexts = kube_client::list_contexts().unwrap_or_default();
    json_result(&contexts)
}

/// Build a kube client for a context and probe the API server. Tears
/// down any previous connection first.
pub(crate) async fn connect(
    manager: &Arc<ClientManager>,
    p: ConnectParams,
) -> Result<CallToolResult, McpError> {
    // Resolve context: empty means "use current-context".
    let context = if p.context.is_empty() {
        kube_client::list_contexts()
            .ok()
            .and_then(|cs| cs.into_iter().find(|c| c.current).map(|c| c.name))
            .ok_or_else(|| {
                McpError::invalid_params(
                    "no context supplied and no current-context in kubeconfig",
                    None,
                )
            })?
    } else {
        p.context
    };

    // Shared connection sequence: reset -> build client -> probe version ->
    // discover CRDs. The MCP shell may have an imported kubeconfig in memory.
    let imported = manager.import_kubeconfig(&context).await;
    let import_path = manager.import_path(&context).await;
    let cr = k7s_core::core::shell_common::connect_core(&manager, imported, import_path, &context)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    // MCP has no watchers — just record the connection.
    manager
        .set_connected(
            cr.client,
            k7s_core::kube::manager::ConnectionInfo {
                context: context.clone(),
                server: cr.server.clone(),
                version: cr.version.clone(),
            },
            0,
        )
        .await;

    let info = kube_client::ClusterInfo {
        context: context.clone(),
        cluster_name: context,
        server: cr.server,
        version: cr.version,
    };
    json_result(&info)
}

/// Drop the current connection and all of its long-lived sessions.
pub(crate) async fn disconnect(manager: &Arc<ClientManager>) -> Result<CallToolResult, McpError> {
    manager.reset().await;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        "disconnected",
    )]))
}

/// Current connection status. `connected: false` means tools that need
/// a client (everything except `list_contexts`) will return a
/// "not connected" error.
pub(crate) async fn status(manager: &Arc<ClientManager>) -> Result<CallToolResult, McpError> {
    let m = manager;
    let info = m.connection_info().await;
    let client_alive = m.client().await.is_some();
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Status {
        connected: bool,
        context: Option<String>,
        server: Option<String>,
        version: Option<String>,
    }
    json_result(&Status {
        connected: client_alive && info.is_some(),
        context: info.as_ref().map(|i| i.context.clone()),
        server: info.as_ref().map(|i| i.server.clone()),
        version: info.as_ref().map(|i| i.version.clone()),
    })
}

// === Read tools ===

pub(crate) async fn list_resources(
    manager: &Arc<ClientManager>,
    p: ListResourcesParams,
) -> Result<CallToolResult, McpError> {
    let manager = manager;
    let items = kube_api::list_resources(
        manager,
        &p.kind,
        if p.namespace.is_empty() {
            None
        } else {
            Some(&p.namespace)
        },
        if p.label_selector.is_empty() {
            None
        } else {
            Some(p.label_selector.as_str())
        },
    )
    .await
    .map_err(tool_error)?;
    json_result(&items)
}

pub(crate) async fn get_resource(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let yaml = kube_api::get_resource_yaml(manager, &p.kind, &p.namespace, &p.name)
        .await
        .map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(yaml)]))
}

pub(crate) async fn describe_resource(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let props = kube_api::describe_resource(manager, &p.kind, &p.namespace, &p.name)
        .await
        .map_err(tool_error)?;
    json_result(&props)
}

pub(crate) async fn get_events(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let events = kube_api::get_events(manager, &p.kind, &p.namespace, &p.name)
        .await
        .map_err(tool_error)?;
    json_result(&events)
}

// === Write tools ===

pub(crate) async fn apply_yaml(
    manager: &Arc<ClientManager>,
    p: ApplyYamlParams,
) -> Result<CallToolResult, McpError> {
    ensure_writable(&p.kind).map_err(tool_error)?;
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let obj: DynamicObject = k7s_deps::yaml_serde::from_str(&p.yaml)
        .map_err(|e| tool_error(AppError::Other(e.to_string())))?;
    let namespaced = kube_api::kind_is_namespaced(&p.kind, manager).await;
    validate_apply_yaml(&obj, &p.kind, &p.name, &p.namespace, namespaced).map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, &p.kind, &p.namespace, manager)
        .await
        .map_err(tool_error)?;
    api.replace(&p.name, &PostParams::default(), &obj)
        .await
        .map(|_| ())
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "{} {}/{} applied",
        p.kind, p.namespace, p.name
    ))]))
}

pub(crate) async fn dry_run_yaml(
    manager: &Arc<ClientManager>,
    p: ApplyYamlParams,
) -> Result<CallToolResult, McpError> {
    ensure_writable(&p.kind).map_err(tool_error)?;
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let obj: DynamicObject = k7s_deps::yaml_serde::from_str(&p.yaml)
        .map_err(|e| tool_error(AppError::Other(e.to_string())))?;
    let namespaced = kube_api::kind_is_namespaced(&p.kind, manager).await;
    validate_apply_yaml(&obj, &p.kind, &p.name, &p.namespace, namespaced).map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, &p.kind, &p.namespace, manager)
        .await
        .map_err(tool_error)?;

    let mut current = api
        .get(&p.name)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    current.metadata.managed_fields = None;

    let pp = PostParams {
        dry_run: true,
        ..Default::default()
    };
    let mut proposed = api
        .replace(&p.name, &pp, &obj)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    proposed.metadata.managed_fields = None;

    let current_yaml = k7s_deps::yaml_serde::to_string(&current)
        .map_err(|e| tool_error(AppError::Other(e.to_string())))?;
    let proposed_yaml = k7s_deps::yaml_serde::to_string(&proposed)
        .map_err(|e| tool_error(AppError::Other(e.to_string())))?;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Diff {
        current: String,
        proposed: String,
    }
    json_result(&Diff {
        current: current_yaml,
        proposed: proposed_yaml,
    })
}

pub(crate) async fn delete_resource(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, &p.kind, &p.namespace, manager)
        .await
        .map_err(tool_error)?;
    api.delete(&p.name, &DeleteParams::default())
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text("deleted")]))
}

pub(crate) async fn set_cordon(
    manager: &Arc<ClientManager>,
    p: CordonParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let (api, _is_helm) = kube_api::dynamic_api(client, "nodes", "", manager)
        .await
        .map_err(tool_error)?;
    let patch = Patch::Merge(
        k7s_deps::serde_json::json!({ "spec": { "unschedulable": p.unschedulable } }),
    );
    api.patch(&p.name, &PatchParams::default(), &patch)
        .await
        .map_err(|e| tool_error(AppError::Kube(e.to_string())))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "node {} {}",
        p.name,
        if p.unschedulable {
            "cordoned"
        } else {
            "uncordoned"
        }
    ))]))
}

pub(crate) async fn drain_node(
    manager: &Arc<ClientManager>,
    p: DrainParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    drain::cordon(client.clone(), &p.node)
        .await
        .map_err(tool_error)?;
    let manager = manager.clone();
    let sink = manager.sink();
    // Same background pattern as the Tauri `drain_node` -- the user gets
    // a "started" message rather than blocking the tool call.
    let node = p.node.clone();
    let timeout = p.timeout_secs.map(std::time::Duration::from_secs);
    let _ = manager
        .push_task(k7s_deps::tokio::spawn(async move {
            drain::run_drain(client, sink, node).await;
        }))
        .await;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "drain started for node {}{}",
        p.node,
        timeout
            .map(|t| format!(" (timeout: {}s)", t.as_secs()))
            .unwrap_or_default()
    ))]))
}

// -----------------------------------------------------------------------
// Convenience getters
// -----------------------------------------------------------------------

pub(crate) async fn default_kubeconfig_path() -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        kube_client::default_kubeconfig_path(),
    )]))
}

pub(crate) async fn list_builtin_kinds() -> Result<CallToolResult, McpError> {
    let kinds: Vec<&'static str> = vec![
        "pods",
        "deployments",
        "replicasets",
        "statefulsets",
        "daemonsets",
        "jobs",
        "cronjobs",
        "services",
        "ingresses",
        "ingressclasses",
        "configmaps",
        "secrets",
        "serviceaccounts",
        "persistentvolumeclaims",
        "persistentvolumes",
        "storageclasses",
        "nodes",
        "namespaces",
        "events",
        "helm",
    ];
    json_result(&kinds)
}

pub(crate) async fn list_custom_kinds(
    manager: &Arc<ClientManager>,
) -> Result<CallToolResult, McpError> {
    // Read the manager's custom-kinds map by re-running discovery is
    // the simplest path; the kinds are already cached on connect.
    let client = match manager.client().await {
        Some(c) => c,
        None => {
            return Ok(CallToolResult::success(vec![ContentBlock::text("[]")]));
        }
    };
    let custom = k7s_core::kube::discovery::discover(&client).await;
    let out: Vec<_> = custom
        .into_iter()
        .map(|c| {
            k7s_deps::serde_json::json!({
                "id": c.id,
                "group": c.group,
                "version": c.version,
                "kind": c.kind,
                "namespaced": c.namespaced,
            })
        })
        .collect();
    json_result(&out)
}

// -----------------------------------------------------------------------
// Multi-document YAML apply / dry-run
// -----------------------------------------------------------------------

pub(crate) async fn apply_yaml_bundle(
    manager: &Arc<ClientManager>,
    p: YamlBundleParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let results = templates::multi_apply(&p.yaml, client, manager)
        .await
        .map_err(tool_error)?;
    json_result(&results)
}

pub(crate) async fn dry_run_yaml_bundle(
    manager: &Arc<ClientManager>,
    p: YamlBundleParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let results = templates::multi_dry_run(&p.yaml, client)
        .await
        .map_err(tool_error)?;
    json_result(&results)
}

// -----------------------------------------------------------------------
// API resources discovery + Endpoints
// -----------------------------------------------------------------------

pub(crate) async fn list_api_resources(
    manager: &Arc<ClientManager>,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let rows = kube_api::list_api_resources(&client)
        .await
        .map_err(tool_error)?;
    json_result(&rows)
}

pub(crate) async fn list_endpoints(
    manager: &Arc<ClientManager>,
    p: ListEndpointsParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let rows = if !p.service.is_empty() {
        endpoints::list_for_service(&client, &p.namespace, &p.service)
            .await
            .map_err(tool_error)?
    } else if !p.namespace.is_empty() {
        endpoints::list_namespaced(&client, &p.namespace)
            .await
            .map_err(tool_error)?
    } else {
        endpoints::list_all(&client).await.map_err(tool_error)?
    };
    json_result(&rows)
}

// -----------------------------------------------------------------------
// Import kubeconfig content
// -----------------------------------------------------------------------

pub(crate) async fn import_kubeconfig(
    manager: &Arc<ClientManager>,
    p: ImportKubeconfigParams,
) -> Result<CallToolResult, McpError> {
    let kc = k7s_deps::kube::config::Kubeconfig::from_yaml(&p.contents)
        .map_err(|e| tool_error(AppError::Kubeconfig(format!("parse kubeconfig: {e}"))))?;
    for ctx in &kc.contexts {
        let cluster = ctx
            .context
            .as_ref()
            .map(|c| c.cluster.clone())
            .unwrap_or_default();
        manager
            .add_import(
                ctx.name.clone(),
                ImportedContext {
                    path: p.filename.clone(),
                    cluster,
                    kubeconfig: Some(kc.clone()),
                },
            )
            .await;
    }
    let mut merged = kube_client::list_contexts().unwrap_or_default();
    let existing: std::collections::HashSet<String> =
        merged.iter().map(|c| c.name.clone()).collect();
    let imports = manager.imports().await;
    for (name, imp) in imports {
        if !existing.contains(&name) {
            merged.push(kube_client::ContextInfo {
                name,
                cluster: imp.cluster,
                current: false,
            });
        }
    }
    json_result(&merged)
}

// -----------------------------------------------------------------------
// Phase 4 -- Enhanced AI integration tools (cluster diagnostics)
// -----------------------------------------------------------------------

pub(crate) async fn diagnose_cluster(
    manager: &Arc<ClientManager>,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let mut issues: Vec<k7s_deps::serde_json::Value> = Vec::new();

    // Check nodes
    let nodes =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::core::v1::Node>::all(client.clone())
            .list(&Default::default())
            .await
            .map_err(tool_error)?;
    for node in &nodes.items {
        let name = node.metadata.name.clone().unwrap_or_default();
        let conditions = node.status.as_ref().and_then(|s| s.conditions.as_ref());
        if let Some(conds) = conditions {
            for c in conds {
                if c.type_ == "Ready" && c.status != "True" {
                    issues.push(k7s_deps::serde_json::json!({
                        "severity": "critical", "kind": "Node", "name": name,
                        "issue": "NotReady", "message": c.message.as_deref().unwrap_or("")
                    }));
                }
                if (c.type_ == "DiskPressure" || c.type_ == "MemoryPressure")
                    && c.status == "True"
                {
                    issues.push(k7s_deps::serde_json::json!({
                        "severity": "warning", "kind": "Node", "name": name,
                        "issue": c.type_, "message": c.message.as_deref().unwrap_or("")
                    }));
                }
            }
        }
    }

    // Check pods
    let pods =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::core::v1::Pod>::all(client.clone())
            .list(&Default::default())
            .await
            .map_err(tool_error)?;
    let mut failed_count = 0;
    for pod in &pods.items {
        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .unwrap_or("");
        if phase == "Failed" {
            failed_count += 1;
        }
        if let Some(statuses) = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
        {
            for cs in statuses {
                if let Some(state) = &cs.state {
                    if let Some(waiting) = &state.waiting {
                        if let Some(reason) = &waiting.reason {
                            if reason == "CrashLoopBackOff"
                                || reason == "ImagePullBackOff"
                                || reason == "ErrImagePull"
                            {
                                issues.push(k7s_deps::serde_json::json!({
                                    "severity": "critical", "kind": "Pod",
                                    "name": format!("{}/{}", pod.metadata.namespace.as_deref().unwrap_or(""), pod.metadata.name.as_deref().unwrap_or("?")),
                                    "issue": reason,
                                    "message": waiting.message.as_deref().unwrap_or("")
                                }));
                            }
                        }
                    }
                }
            }
        }
    }
    if failed_count > 0 {
        issues.push(k7s_deps::serde_json::json!({
            "severity": "warning", "kind": "Pods", "name": "cluster-wide",
            "issue": "FailedPods", "message": format!("{failed_count} pods in Failed phase")
        }));
    }

    // Check deployments
    let deployments =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::apps::v1::Deployment>::all(
            client.clone(),
        )
        .list(&Default::default())
        .await
        .map_err(tool_error)?;
    for dep in &deployments.items {
        let name = dep.metadata.name.clone().unwrap_or_default();
        let ns = dep.metadata.namespace.clone().unwrap_or_default();
        let spec_replicas = dep.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
        let ready = dep
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
        if ready < spec_replicas {
            issues.push(k7s_deps::serde_json::json!({
                "severity": "warning", "kind": "Deployment",
                "name": format!("{ns}/{name}"),
                "issue": "Unavailable",
                "message": format!("{ready}/{spec_replicas} replicas ready")
            }));
        }
    }

    json_result(&k7s_deps::serde_json::json!({
        "totalIssues": issues.len(),
        "issues": issues
    }))
}

pub(crate) async fn suggest_fix(
    manager: &Arc<ClientManager>,
    p: GetResourceParams,
) -> Result<CallToolResult, McpError> {
    let kind_id = p.kind.to_lowercase();
    let ns = if p.namespace.is_empty() {
        "default"
    } else {
        &p.namespace
    };

    // Get the resource YAML
    let yaml = kube_api::get_resource_yaml(manager, &kind_id, ns, &p.name)
        .await
        .map_err(tool_error)?;
    let val: k7s_deps::serde_json::Value = k7s_deps::yaml_serde::from_str(&yaml)
        .map_err(|e| tool_error(AppError::Other(e.to_string())))?;

    // Get events
    let events = kube_api::get_events(manager, &kind_id, ns, &p.name)
        .await
        .unwrap_or_default();

    let mut suggestions: Vec<k7s_deps::serde_json::Value> = Vec::new();

    // Check container statuses for common issues
    if let Some(statuses) = val
        .pointer("/status/containerStatuses")
        .and_then(|s| s.as_array())
    {
        for cs in statuses {
            let state = cs.get("state");
            if let Some(waiting) = state.and_then(|s| s.get("waiting")) {
                let reason = waiting.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                match reason {
                    "CrashLoopBackOff" => {
                        suggestions.push(k7s_deps::serde_json::json!({
                            "action": "check_logs", "description": "Container is crash-looping. Check logs for the exit reason.",
                            "command": format!("kubectl logs {}/{} --previous", ns, p.name)
                        }));
                        suggestions.push(k7s_deps::serde_json::json!({
                            "action": "rollback", "description": "If this started after a recent change, rollback to the previous revision."
                        }));
                    }
                    "ImagePullBackOff" | "ErrImagePull" => {
                        suggestions.push(k7s_deps::serde_json::json!({
                            "action": "check_image", "description": "Image pull failed. Verify the image name, tag, and registry credentials."
                        }));
                    }
                    "OOMKilled" | _
                        if cs
                            .pointer("/state/terminated/reason")
                            .and_then(|r| r.as_str())
                            == Some("OOMKilled") =>
                    {
                        suggestions.push(k7s_deps::serde_json::json!({
                            "action": "increase_memory", "description": "Container was OOMkilled. Increase memory limits in the pod spec."
                        }));
                    }
                    _ => {}
                }
            }
        }
    }

    // Check for warning events
    let warning_events: Vec<_> = events.iter().filter(|e| e.ty == "Warning").collect();
    if !warning_events.is_empty() {
        suggestions.push(k7s_deps::serde_json::json!({
            "action": "check_events",
            "description": format!("{} warning event(s) found. Most recent: {}", warning_events.len(), warning_events.first().map(|e| e.message.as_str()).unwrap_or(""))
        }));
    }

    if suggestions.is_empty() {
        suggestions.push(k7s_deps::serde_json::json!({
            "action": "none", "description": "No obvious issues detected. The resource appears healthy."
        }));
    }

    json_result(&k7s_deps::serde_json::json!({
        "kind": kind_id, "name": p.name, "namespace": ns,
        "suggestions": suggestions
    }))
}

pub(crate) async fn find_resources_by_label(
    manager: &Arc<ClientManager>,
    p: FindByLabelParams,
) -> Result<CallToolResult, McpError> {
    let kind_id = p.kind.to_lowercase();
    let ns = p.namespace.as_deref();
    let results = kube_api::list_resources(manager, &kind_id, ns, Some(&p.selector))
        .await
        .map_err(tool_error)?;
    json_result(&k7s_deps::serde_json::json!({ "count": results.len(), "items": results }))
}

pub(crate) async fn cluster_health(
    manager: &Arc<ClientManager>,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;

    let nodes =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::core::v1::Node>::all(client.clone())
            .list(&Default::default())
            .await
            .map_err(tool_error)?;
    let pods =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::core::v1::Pod>::all(client.clone())
            .list(&Default::default())
            .await
            .map_err(tool_error)?;
    let deployments =
        k7s_deps::kube::Api::<k7s_deps::k8s_openapi::api::apps::v1::Deployment>::all(
            client.clone(),
        )
        .list(&Default::default())
        .await
        .map_err(tool_error)?;

    let ready_nodes = nodes
        .items
        .iter()
        .filter(|n| {
            n.status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                .unwrap_or(false)
        })
        .count();

    let running_pods = pods
        .items
        .iter()
        .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
        .count();

    let total_nodes = nodes.items.len();
    let total_pods = pods.items.len();

    json_result(&k7s_deps::serde_json::json!({
        "nodes": { "ready": ready_nodes, "total": total_nodes },
        "pods": { "running": running_pods, "total": total_pods },
        "deployments": deployments.items.len(),
    }))
}

// === New tools (shared impls layer) ===

pub(crate) async fn batch_get(
    manager: &Arc<ClientManager>,
    p: BatchGetParams,
) -> Result<CallToolResult, McpError> {
    let result = k7s_core::ai::tools::impls::batch_get_impl(manager, &p.requests)
        .await
        .map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn diff_resources(
    manager: &Arc<ClientManager>,
    p: DiffResourcesParams,
) -> Result<CallToolResult, McpError> {
    let result = k7s_core::ai::tools::impls::diff_resources_impl(
        manager,
        &p.kind,
        &p.namespace_a,
        &p.name_a,
        &p.namespace_b,
        &p.name_b,
    )
    .await
    .map_err(tool_error)?;
    json_result(&result)
}

// -----------------------------------------------------------------------
// Unified kind discovery
// -----------------------------------------------------------------------

pub(crate) async fn list_kinds(
    manager: &Arc<ClientManager>,
    p: ListKindsParams,
) -> Result<CallToolResult, McpError> {
    match p.scope.as_str() {
        "builtin" => list_builtin_kinds().await,
        "custom" => list_custom_kinds(manager).await,
        "all" => {
            let builtin = vec![
                k7s_deps::serde_json::json!({"id": "pods", "name": "Pods"}),
                k7s_deps::serde_json::json!({"id": "deployments", "name": "Deployments"}),
                k7s_deps::serde_json::json!({"id": "services", "name": "Services"}),
                k7s_deps::serde_json::json!({"id": "nodes", "name": "Nodes"}),
                k7s_deps::serde_json::json!({"id": "namespaces", "name": "Namespaces"}),
                k7s_deps::serde_json::json!({"id": "configmaps", "name": "ConfigMaps"}),
                k7s_deps::serde_json::json!({"id": "secrets", "name": "Secrets"}),
                k7s_deps::serde_json::json!({"id": "statefulsets", "name": "StatefulSets"}),
                k7s_deps::serde_json::json!({"id": "daemonsets", "name": "DaemonSets"}),
                k7s_deps::serde_json::json!({"id": "jobs", "name": "Jobs"}),
                k7s_deps::serde_json::json!({"id": "cronjobs", "name": "CronJobs"}),
                k7s_deps::serde_json::json!({"id": "ingresses", "name": "Ingresses"}),
                k7s_deps::serde_json::json!({"id": "persistentvolumeclaims", "name": "PVCs"}),
            ];
            json_result(&k7s_deps::serde_json::json!({
                "builtin": builtin,
            }))
        }
        _ => Err(McpError::invalid_params(
            format!("unknown scope '{}': use builtin|custom|all", p.scope),
            None,
        )),
    }
}

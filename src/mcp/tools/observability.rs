//! Observability tool bodies: Prometheus / AlertManager / Grafana queries,
//! saved queries, `kubectl top` snapshots, and cost estimates.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::sync::Arc;

use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};

use k7s_core::error::AppError;
use k7s_core::kube::{
    alerting, grafana, manager::ClientManager, metrics::parse_cpu_millis,
    metrics::parse_mem_bytes, metrics_config, saved_queries,
};

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

// === Monitoring tools ===
// Monitoring, image registry, image sync, and enhanced AI integration tools

// -----------------------------------------------------------------------
// Monitoring: Prometheus / AlertManager / Grafana
// -----------------------------------------------------------------------

pub(crate) async fn prometheus_query(
    p: PrometheusQueryParams,
) -> Result<CallToolResult, McpError> {
    let result = metrics_config::query(&p.name, &p.promql)
        .await
        .map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn prometheus_query_range(
    p: PrometheusQueryRangeParams,
) -> Result<CallToolResult, McpError> {
    let result =
        metrics_config::query_range(&p.name, &p.promql, p.start_ms, p.end_ms, p.step_seconds)
            .await
            .map_err(tool_error)?;
    json_result(&result)
}

pub(crate) async fn alertmanager_alerts(
    p: InstanceNameParams,
) -> Result<CallToolResult, McpError> {
    let alerts = alerting::list_alerts(&p.name).await.map_err(tool_error)?;
    json_result(&alerts)
}

pub(crate) async fn alertmanager_silences(
    p: InstanceNameParams,
) -> Result<CallToolResult, McpError> {
    let silences = alerting::list_silences(&p.name).await.map_err(tool_error)?;
    json_result(&silences)
}

pub(crate) async fn grafana_dashboard_url(
    p: GrafanaDashboardParams,
) -> Result<CallToolResult, McpError> {
    let url = grafana::dashboard_url(&p.name, &p.uid, p.from_ms, p.to_ms).map_err(tool_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(url)]))
}

pub(crate) async fn saved_query_run(
    p: SavedQueryRunParams,
) -> Result<CallToolResult, McpError> {
    let query = saved_queries::list()
        .map_err(tool_error)?
        .into_iter()
        .find(|q| q.name == p.name)
        .ok_or_else(|| {
            tool_error(AppError::NotFound(format!(
                "saved query '{}' not found",
                p.name
            )))
        })?;
    let result = saved_queries::run_saved(&query, &p.instance, p.force_refresh)
        .await
        .map_err(tool_error)?;
    json_result(&result)
}

// -----------------------------------------------------------------------
// Silences (create / delete) and alert rules
// -----------------------------------------------------------------------

pub(crate) async fn create_silence(
    p: CreateSilenceParams,
) -> Result<CallToolResult, McpError> {
    let ends_at = (k7s_deps::chrono::Utc::now()
        + k7s_deps::chrono::Duration::hours(p.duration_hours.unwrap_or(4)))
    .to_rfc3339();
    let request = alerting::CreateSilenceRequest {
        matchers: p
            .matchers
            .iter()
            .map(|m| alerting::SilenceMatcher {
                name: m.name.clone(),
                value: m.value.clone(),
                is_regex: m.is_regex.unwrap_or(false),
            })
            .collect(),
        comment: p.comment.unwrap_or_default(),
        created_by: "k7s-mcp".to_string(),
        starts_at: String::new(),
        ends_at,
    };
    let id = alerting::create_silence(&p.instance, &request)
        .await
        .map_err(tool_error)?;
    json_result(&k7s_deps::serde_json::json!({ "silenceId": id }))
}

pub(crate) async fn delete_silence(
    p: DeleteSilenceParams,
) -> Result<CallToolResult, McpError> {
    alerting::delete_silence(&p.instance, &p.silence_id)
        .await
        .map_err(tool_error)?;
    json_result(&k7s_deps::serde_json::json!({ "deleted": true }))
}

pub(crate) async fn list_alert_rules(
    p: InstanceNameParams,
) -> Result<CallToolResult, McpError> {
    let groups = alerting::prometheus_rules(&p.name)
        .await
        .map_err(tool_error)?;
    json_result(&groups)
}

pub(crate) async fn grafana_search(p: GrafanaSearchParams) -> Result<CallToolResult, McpError> {
    let results = grafana::search_dashboards(&p.name, &p.query)
        .await
        .map_err(tool_error)?;
    json_result(&results)
}

// -----------------------------------------------------------------------
// Unified Prometheus query
// -----------------------------------------------------------------------

pub(crate) async fn prometheus_query_unified(
    p: PrometheusUnifiedParams,
) -> Result<CallToolResult, McpError> {
    if p.range.unwrap_or(false) {
        let params = PrometheusQueryRangeParams {
            name: p.instance.unwrap_or_default(),
            promql: p.query,
            start_ms: p.start.unwrap_or_default().parse().unwrap_or(0),
            end_ms: p.end.unwrap_or_default().parse().unwrap_or(0),
            step_seconds: p.step.unwrap_or_default().parse().unwrap_or(60),
        };
        prometheus_query_range(params).await
    } else {
        let params = PrometheusQueryParams {
            name: p.instance.unwrap_or_default(),
            promql: p.query,
        };
        prometheus_query(params).await
    }
}

// -----------------------------------------------------------------------
// Unified AlertManager silence operation
// -----------------------------------------------------------------------

pub(crate) async fn silence(p: SilenceUnifiedParams) -> Result<CallToolResult, McpError> {
    match p.action.as_str() {
        "create" => {
            let params = CreateSilenceParams {
                instance: p.instance.unwrap_or_default(),
                matchers: p.matchers.unwrap_or_default(),
                comment: p.comment,
                duration_hours: p.duration_hours,
            };
            create_silence(params).await
        }
        "delete" => {
            let params = DeleteSilenceParams {
                instance: p.instance.unwrap_or_default(),
                silence_id: p.silence_id.unwrap_or_default(),
            };
            delete_silence(params).await
        }
        _ => Err(McpError::invalid_params(
            format!("unknown action '{}': use create|delete", p.action),
            None,
        )),
    }
}

// -----------------------------------------------------------------------
// kubectl top snapshots
// -----------------------------------------------------------------------

pub(crate) async fn top_pods(
    manager: &Arc<ClientManager>,
    p: TopPodsParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let ns = if p.namespace.is_empty() {
        None
    } else {
        Some(p.namespace.as_str())
    };
    let rows = kube_api::top_pods(&client, ns).await.map_err(tool_error)?;
    json_result(&rows)
}

pub(crate) async fn top_nodes(manager: &Arc<ClientManager>) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let rows = kube_api::top_nodes(&client).await.map_err(tool_error)?;
    json_result(&rows)
}

// -----------------------------------------------------------------------
// Cost estimates
// -----------------------------------------------------------------------

pub(crate) async fn cost_estimate(
    manager: &Arc<ClientManager>,
    p: NamespaceParam,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager).await.map_err(tool_error)?;
    let pods: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        k7s_deps::kube::Api::namespaced(client, &p.namespace);
    let list = pods.list(&Default::default()).await.map_err(tool_error)?;

    let mut total_cpu_millis: i64 = 0;
    let mut total_mem_bytes: i64 = 0;
    let mut pod_costs: Vec<k7s_deps::serde_json::Value> = Vec::new();

    for pod in &list.items {
        let name = pod.metadata.name.clone().unwrap_or_default();
        let mut cpu_millis: i64 = 0;
        let mut mem_bytes: i64 = 0;
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                if let Some(res) = &container.resources {
                    if let Some(reqs) = &res.requests {
                        if let Some(cpu) = reqs.get("cpu") {
                            cpu_millis += parse_cpu_millis(&cpu.0);
                        }
                        if let Some(mem) = reqs.get("memory") {
                            mem_bytes += parse_mem_bytes(&mem.0);
                        }
                    }
                }
            }
        }
        total_cpu_millis += cpu_millis;
        total_mem_bytes += mem_bytes;
        pod_costs.push(k7s_deps::serde_json::json!({
            "name": name,
            "cpuMillis": cpu_millis,
            "memBytes": mem_bytes,
        }));
    }

    // Rough cloud pricing: $0.03/vCPU-hour, $0.004/GB-hour
    let cpu_hours = total_cpu_millis as f64 / 1000.0 / 3600.0 * 730.0; // monthly
    let mem_gb_hours = total_mem_bytes as f64 / 1_073_741_824.0 / 3600.0 * 730.0;
    let estimated_monthly_usd = cpu_hours * 0.03 + mem_gb_hours * 0.004;

    json_result(&k7s_deps::serde_json::json!({
        "namespace": p.namespace,
        "podCount": list.items.len(),
        "totalCpuMillis": total_cpu_millis,
        "totalMemBytes": total_mem_bytes,
        "estimatedMonthlyUsd": (estimated_monthly_usd * 100.0).round() / 100.0,
        "pods": pod_costs,
    }))
}

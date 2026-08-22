//! Security tool bodies: RBAC queries and audits, NetworkPolicy audits,
//! K8s audit-log search, and SBOM generation.
//!
//! Every function here is the body of a `#[tool]` method on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer); the method in
//! `server.rs` is a one-line wrapper that forwards the parsed parameters.

use std::path::Path;
use std::sync::Arc;

use rmcp::model::{CallToolResult, ErrorData as McpError};

use k7s_core::kube::manager::ClientManager;

use crate::mcp::helpers::{json_result, tool_error};
use crate::mcp::kube_api;
use crate::mcp::params::*;

// -----------------------------------------------------------------------
// RBAC
// -----------------------------------------------------------------------

pub(crate) async fn rbac_who_can(
    manager: &Arc<ClientManager>,
    p: RbacWhoCanParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;

    // Check ClusterRoleBindings
    let crbs: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::rbac::v1::ClusterRoleBinding> =
        k7s_deps::kube::Api::all(client.clone());
    let crb_list = crbs.list(&Default::default()).await.map_err(tool_error)?;

    let mut matches: Vec<k7s_deps::serde_json::Value> = Vec::new();
    for crb in &crb_list {
        let role_ref = crb.role_ref.name.clone();
        let subjects: Vec<String> = crb
            .subjects
            .as_ref()
            .map(|subs| {
                subs.iter()
                    .map(|s| format!("{}:{}", s.kind, s.name))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !subjects.is_empty() {
            matches.push(k7s_deps::serde_json::json!({
                "binding": crb.metadata.name.clone().unwrap_or_default(),
                "type": "ClusterRoleBinding",
                "role": role_ref,
                "subjects": subjects,
            }));
        }
    }

    // Check RoleBindings in namespace
    if !p.namespace.is_empty() {
        let rbs: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::rbac::v1::RoleBinding> =
            k7s_deps::kube::Api::namespaced(client, &p.namespace);
        let rb_list = rbs.list(&Default::default()).await.map_err(tool_error)?;
        for rb in &rb_list {
            let role_ref = rb.role_ref.name.clone();
            let subjects: Vec<String> = rb
                .subjects
                .as_ref()
                .map(|subs| {
                    subs.iter()
                        .map(|s| format!("{}:{}", s.kind, s.name))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !subjects.is_empty() {
                matches.push(k7s_deps::serde_json::json!({
                    "binding": rb.metadata.name.clone().unwrap_or_default(),
                    "type": "RoleBinding",
                    "namespace": p.namespace,
                    "role": role_ref,
                    "subjects": subjects,
                }));
            }
        }
    }

    json_result(&k7s_deps::serde_json::json!({
        "verb": p.verb,
        "resource": p.resource,
        "namespace": p.namespace,
        "matches": matches,
    }))
}

pub(crate) async fn security_audit(
    manager: &Arc<ClientManager>,
    _p: SecurityAuditParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let report = k7s_core::kube::security::security_audit::run_audit(client)
        .await
        .map_err(tool_error)?;
    json_result(&report)
}

pub(crate) async fn rbac_permission_matrix(
    manager: &Arc<ClientManager>,
    _p: RbacPermissionMatrixParams,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let matrix = k7s_core::kube::security::rbac_matrix::build_rbac_matrix(client)
        .await
        .map_err(tool_error)?;
    json_result(&matrix)
}

pub(crate) async fn network_policy_audit(
    manager: &Arc<ClientManager>,
    p: NamespaceParam,
) -> Result<CallToolResult, McpError> {
    let client = kube_api::require_client(manager)
        .await
        .map_err(tool_error)?;
    let nps: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::networking::v1::NetworkPolicy> =
        k7s_deps::kube::Api::namespaced(client.clone(), &p.namespace);
    let list = nps.list(&Default::default()).await.map_err(tool_error)?;

    let pods: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        k7s_deps::kube::Api::namespaced(client, &p.namespace);
    let pod_list = pods.list(&Default::default()).await.map_err(tool_error)?;

    let mut policies: Vec<k7s_deps::serde_json::Value> = Vec::new();
    for np in &list {
        let name = np.metadata.name.clone().unwrap_or_default();
        let pod_selector = np
            .spec
            .as_ref()
            .map(|s| &s.pod_selector)
            .map(|ps| {
                ps.as_ref()
                    .and_then(|s| s.match_labels.as_ref())
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let ingress_rules = np
            .spec
            .as_ref()
            .and_then(|s| s.ingress.as_ref())
            .map(|r| r.len())
            .unwrap_or(0);
        let egress_rules = np
            .spec
            .as_ref()
            .and_then(|s| s.egress.as_ref())
            .map(|r| r.len())
            .unwrap_or(0);
        policies.push(k7s_deps::serde_json::json!({
            "name": name,
            "podSelector": pod_selector,
            "ingressRules": ingress_rules,
            "egressRules": egress_rules,
        }));
    }

    let _isolated_pod_count = pod_list.items.len(); // simplified
    json_result(&k7s_deps::serde_json::json!({
        "namespace": p.namespace,
        "policies": policies,
        "totalPods": pod_list.items.len(),
        "note": "Pods without matching NetworkPolicies are isolated by default when any policy exists in the namespace.",
    }))
}

// -----------------------------------------------------------------------
// Audit logs
// -----------------------------------------------------------------------

pub(crate) async fn audit_search(p: AuditSearchParams) -> Result<CallToolResult, McpError> {
    let query = k7s_core::kube::observability::audit::AuditQuery {
        namespace: String::new(),
        instance: p.instance,
        resource: p.resource.unwrap_or_default(),
        user: p.user.unwrap_or_default(),
        since_seconds: p.since_seconds.unwrap_or(3600),
        limit: p.limit.unwrap_or(200) as usize,
    };
    let events = k7s_core::kube::observability::audit::query_audit_events(&query)
        .await
        .map_err(tool_error)?;
    json_result(&events)
}

// -----------------------------------------------------------------------
// SBOM tools
// -----------------------------------------------------------------------

pub(crate) async fn sbom_generate_image(
    data_dir: &Path,
    p: SbomGenerateParams,
) -> Result<CallToolResult, McpError> {
    let format = k7s_core::kube::security::sbom::SbomFormat::parse(&p.format)
        .unwrap_or(k7s_core::kube::security::sbom::SbomFormat::CycloneDx);
    let prefs = k7s_core::core::prefs::read_prefs(data_dir);
    let engine = k7s_core::kube::security::sbom::SbomEngine::with_prefs(
        prefs.scanner_trivy_path.as_deref(),
        prefs.scanner_grype_path.as_deref(),
        prefs.scanner_timeout.as_deref(),
    );
    let sbom = engine
        .generate_with_vulns(&p.image_ref, &format)
        .await
        .map_err(tool_error)?;
    let storage = k7s_core::kube::security::sbom_storage::SbomStorage::new(data_dir);
    let _ = storage.save(&sbom);
    json_result(&k7s_deps::serde_json::json!({
        "id": sbom.id,
        "components": sbom.components.len(),
        "vulnerabilities": sbom.vulnerabilities.len(),
        "tool": sbom.metadata.tool,
    }))
}

pub(crate) async fn sbom_list_history(data_dir: &Path) -> Result<CallToolResult, McpError> {
    let storage = k7s_core::kube::security::sbom_storage::SbomStorage::new(data_dir);
    let list = storage.list().map_err(tool_error)?;
    json_result(&list)
}

pub(crate) async fn sbom_get(
    data_dir: &Path,
    p: SbomGetParams,
) -> Result<CallToolResult, McpError> {
    let storage = k7s_core::kube::security::sbom_storage::SbomStorage::new(data_dir);
    let sbom = storage.load(&p.id).map_err(tool_error)?;
    // Serialize via serde to get consistent camelCase keys
    json_result(&k7s_deps::serde_json::to_value(&sbom).map_err(tool_error)?)
}

// -----------------------------------------------------------------------
// Unified SBOM operation
// -----------------------------------------------------------------------

pub(crate) async fn sbom_unified(
    data_dir: &Path,
    p: SbomUnifiedParams,
) -> Result<CallToolResult, McpError> {
    match p.action.as_str() {
        "generate" => {
            let params = SbomGenerateParams {
                image_ref: p.image.unwrap_or_default(),
                format: String::new(),
            };
            sbom_generate_image(data_dir, params).await
        }
        "list" => sbom_list_history(data_dir).await,
        "get" => {
            let params = SbomGetParams {
                id: p.id.unwrap_or_default(),
            };
            sbom_get(data_dir, params).await
        }
        _ => Err(McpError::invalid_params(
            format!("unknown action '{}': use generate|list|get", p.action),
            None,
        )),
    }
}

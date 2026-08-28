//! Input/output parameter types for MCP tools.
//!
//! Every type that flows into a `#[tool]` is a `JsonSchema + Deserialize` struct.
//! Field-level `#[schemars(description = "...")]` annotations become the
//! parameter description in the tool's input schema, which the AI client
//! surfaces to the model. Keep them short and concrete.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core resource parameter types
// ---------------------------------------------------------------------------

/// Optional `kind` filter for `list_resources`. Most of the time the caller
/// knows the kind they want; we accept "any built-in" by leaving it empty.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListResourcesParams {
    /// The kind id (e.g. `pods`, `deployments`, `services`, `nodes`, ...) or
    /// `group/plural` for a CRD. Required.
    pub kind: String,
    /// Namespace to scope the list. Ignored for cluster-scoped kinds
    /// (nodes, namespaces, persistentvolumes, ...). Empty string lists across
    /// all namespaces.
    #[serde(default)]
    pub namespace: String,
    /// Standard k8s label selector, e.g. `app=nginx,tier=frontend`.
    #[serde(default)]
    pub label_selector: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetResourceParams {
    pub kind: String,
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplyYamlParams {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    /// Full object YAML. resourceVersion must match (the same contract the
    /// Tauri apply enforces -- a stale value yields a 409 you can see).
    pub yaml: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScaleParams {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub replicas: i32,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CordonParams {
    pub name: String,
    pub unschedulable: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NameNamespaceParams {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosePodParams {
    /// Namespace of the Pod.
    pub namespace: String,
    /// Name of the Pod to diagnose.
    pub pod: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogsParams {
    pub namespace: String,
    pub pod: String,
    #[serde(default)]
    pub container: String,
    /// Lines to return from the end of the log. None -> server default (often
    /// all available). Tip: use a small number for a quick look, leave
    /// empty when investigating.
    #[serde(default)]
    pub tail: Option<i64>,
    /// Only return logs newer than this many seconds.
    #[serde(default)]
    pub since_seconds: Option<i64>,
    /// Read the previous terminated container's logs (after a crash).
    #[serde(default)]
    pub previous: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartShellParams {
    pub namespace: String,
    pub pod: String,
    pub container: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShellInputParams {
    /// The id returned by `start_shell` or `start_node_shell`.
    pub shell_id: String,
    /// Keystrokes. Will be wrapped in a JSON string and shipped as-is;
    /// use base64 / raw UTF-8 if the shell needs escape sequences the
    /// tool-calling protocol might mangle.
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShellResizeParams {
    pub shell_id: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StopShellParams {
    pub shell_id: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartPortForwardParams {
    pub namespace: String,
    pub pod: String,
    pub remote_port: u16,
    /// Local port to bind. 0 -> pick a free port.
    #[serde(default)]
    pub local_port: u16,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartServiceForwardParams {
    pub namespace: String,
    pub service: String,
    pub service_port: u16,
    /// Local port to bind. 0 -> pick a free port.
    #[serde(default)]
    pub local_port: u16,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StopForwardParams {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectParams {
    /// kubeconfig context to connect to. If empty, uses the current-context.
    #[serde(default)]
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrainParams {
    pub node: String,
    #[serde(default)]
    /// How long to wait for the drain before giving up. None -> no timeout
    /// (the MCP caller polls `list_port_forwards`-style events itself, in
    /// this case by re-listing the node's pods).
    pub timeout_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Helm op parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmInstallParams {
    pub release: String,
    pub chart: String,
    #[serde(default)]
    pub version: String,
    pub namespace: String,
    #[serde(default)]
    pub values: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub create_namespace: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmUpgradeParams {
    pub release: String,
    pub chart: String,
    #[serde(default)]
    pub version: String,
    pub namespace: String,
    #[serde(default)]
    pub values: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub reuse_values: bool,
    #[serde(default)]
    pub rollback_on_failure: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmUninstallParams {
    pub release: String,
    pub namespace: String,
    #[serde(default)]
    pub keep_history: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmRollbackParams {
    pub release: String,
    pub namespace: String,
    #[serde(default)]
    pub revision: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmHistoryParams {
    pub release: String,
    pub namespace: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmShowValuesParams {
    pub chart: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmManifestRevisionParams {
    pub namespace: String,
    pub name: String,
    pub revision: i64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmValuesRevisionParams {
    pub namespace: String,
    pub name: String,
    pub revision: i64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct HelmSearchParams {
    #[serde(default)]
    pub query: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmRepoParams {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmRepoNameParams {
    pub name: String,
}

// ---------------------------------------------------------------------------
// Local chart library parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmRenderPreviewParams {
    /// Chart reference: `repo/name`, an OCI URL, or a local path (helm
    /// natively accepts all three). Required.
    pub chart: String,
    /// Chart version. Empty = latest.
    #[serde(default)]
    pub version: String,
    /// values.yaml content to override the chart defaults. Empty = chart
    /// defaults.
    #[serde(default)]
    pub values: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmChartIdParams {
    /// The `id` of a chart in the local library, as returned by
    /// `helm_local_charts`. Required.
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmChartDepsParams {
    /// The `id` of a chart in the local library, as returned by
    /// `helm_local_charts`. Required.
    pub id: String,
    /// Which `helm dependency` subcommand: `list` (offline), `build` or
    /// `update` (both fetch dependency charts from their repos).
    pub action: String,
}

// ---------------------------------------------------------------------------
// Exec / rollout / top / cronjob parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecParams {
    pub namespace: String,
    pub pod: String,
    #[serde(default)]
    pub container: String,
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopPodsParams {
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NameNamespaceNameParams {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct YamlBundleParams {
    pub yaml: String,
}

// ---------------------------------------------------------------------------
// Endpoints / Pod files / import kubeconfig parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListEndpointsParams {
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub service: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodFileParams {
    pub namespace: String,
    pub pod: String,
    #[serde(default)]
    pub container: String,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodFileWriteParams {
    pub namespace: String,
    pub pod: String,
    #[serde(default)]
    pub container: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodFileUploadParams {
    pub namespace: String,
    pub pod: String,
    #[serde(default)]
    pub container: String,
    pub dest_dir: String,
    pub tar_b64: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportKubeconfigParams {
    pub contents: String,
    #[serde(default)]
    pub filename: String,
}

// ---------------------------------------------------------------------------
// Monitoring parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusQueryParams {
    pub name: String,
    pub promql: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusQueryRangeParams {
    pub name: String,
    pub promql: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub step_seconds: i64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceNameParams {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaDashboardParams {
    pub name: String,
    pub uid: String,
    pub from_ms: i64,
    pub to_ms: i64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageRegistryRepoParams {
    pub name: String,
    pub repo: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageRegistryManifestParams {
    pub name: String,
    pub repo: String,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SavedQueryRunParams {
    pub name: String,
    pub instance: String,
    #[serde(default)]
    pub force_refresh: bool,
}

// ---------------------------------------------------------------------------
// Image sync / import parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageCopyParams {
    /// Any skopeo transport: `docker://nginx:1.25`, `docker-archive:/tmp/x.tar`, `oci:...`, `dir:...`.
    pub source: String,
    /// Name of the configured destination registry (resolved from image-registries config).
    pub dest_registry: String,
    pub dest_repo: String,
    pub dest_tag: String,
    /// Source credentials as `user:pass`. Empty/None for anonymous public images.
    #[serde(default)]
    pub src_creds: String,
    /// Skip TLS verification on the source (self-signed registries).
    #[serde(default)]
    pub insecure_src: bool,
    /// Skip TLS verification on the destination.
    #[serde(default)]
    pub insecure_dest: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageArchiveParams {
    /// Path to a local `docker save` tarball.
    pub tar_path: String,
}

// ---------------------------------------------------------------------------
// Phase 4 -- Enhanced AI integration parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindByLabelParams {
    pub kind: String,
    pub selector: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SilenceMatcherInput {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub is_regex: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateSilenceParams {
    pub instance: String,
    pub matchers: Vec<SilenceMatcherInput>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub duration_hours: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSilenceParams {
    pub instance: String,
    pub silence_id: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchParams {
    pub instance: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub since_seconds: Option<i64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaSearchParams {
    pub name: String,
    pub query: String,
}

// ---------------------------------------------------------------------------
// SBOM parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SbomGenerateParams {
    /// Container image reference (e.g. `nginx:1.25`, `docker.io/library/alpine:latest`).
    pub image_ref: String,
    /// Output format: `cyclonedx` (default) or `spdx`.
    #[serde(default)]
    pub format: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SbomGetParams {
    /// The SBOM id returned by `sbom_generate_image`.
    pub id: String,
}

// ---------------------------------------------------------------------------
// New tool parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchGetParams {
    pub requests: Vec<k7s_deps::serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffResourcesParams {
    pub kind: String,
    #[serde(default)]
    pub namespace_a: String,
    pub name_a: String,
    #[serde(default)]
    pub namespace_b: String,
    pub name_b: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HpaStatusParams {
    pub namespace: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceParam {
    pub namespace: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RbacWhoCanParams {
    pub verb: String,
    pub resource: String,
    #[serde(default)]
    pub namespace: String,
}

// Consolidated tool params

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HelmReleaseParams {
    pub action: String,
    #[serde(default)]
    pub release: Option<String>,
    #[serde(default)]
    pub chart: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub values: Option<String>,
    #[serde(default)]
    pub revision: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardParams {
    pub action: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub pod: Option<String>,
    #[serde(default)]
    pub container_port: Option<u16>,
    #[serde(default)]
    pub local_port: Option<u16>,
    #[serde(default)]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusUnifiedParams {
    pub query: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub range: Option<bool>,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
    #[serde(default)]
    pub step: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SbomUnifiedParams {
    pub action: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SilenceUnifiedParams {
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub matchers: Option<Vec<SilenceMatcherInput>>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub duration_hours: Option<i64>,
    #[serde(default)]
    pub silence_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListKindsParams {
    pub scope: String,
}

// ---------------------------------------------------------------------------
// Security audit parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAuditParams {}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RbacPermissionMatrixParams {}

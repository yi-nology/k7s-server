//! The MCP server itself.
//!
//! One struct (`K7sMcpServer`) that holds an `Arc<ClientManager>` and exposes
//! the same Kubernetes plumbing the desktop/web shells use, but as a set of
//! MCP `#[tool]` methods. The macros (`#[tool_router]` / `#[tool_handler]`)
//! generate the JSON schema for inputs and wire each method into the tool
//! dispatch table.
//!
//! The `#[tool]` methods below are thin one-line wrappers: the rmcp macros
//! require every tool to be a method on the `#[tool_router]` impl block, so
//! each method just forwards its parsed parameters to the matching
//! `pub(crate)` function in [`super::tools`] (grouped by domain there).

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorData as McpError, ServerCapabilities, ServerInfo};
use rmcp::transport::stdio;
use rmcp::{tool, tool_handler, tool_router, ServiceExt};

use k7s_core::core::events::mcp_sink;
use k7s_core::core::CoreState;
use k7s_core::kube::manager::ClientManager;

// Parameter structs and helpers are in sibling modules.
use super::params::*;
use super::tools::{cluster, helm, image, observability, pod, security, shell, workload};

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

/// The MCP server. Cloning is cheap: it holds an `Arc<CoreState>` (which
/// wraps an `Arc<ClientManager>`) and a `ToolRouter` (the rmcp-side dispatch
/// table the `#[tool_router]` macro builds).
#[derive(Clone)]
pub struct K7sMcpServer {
    core: Arc<CoreState>,
    /// The `#[tool_router]` macro generates `Self::tool_router()` that
    /// returns a fully populated `ToolRouter<Self>`; we cache it here so
    /// every method call hits the same instance.
    tool_router: ToolRouter<Self>,
}

impl K7sMcpServer {
    /// Build a fresh server. `data_dir` is a small writable scratch dir the
    /// server uses to stash future persistent prefs (currently unused -- the
    /// MCP shell has no Settings dialog to read them from).
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        let manager = Arc::new(ClientManager::new(mcp_sink()));
        // `CoreState::new` already returns `Arc<Self>` -- wrap once, not twice.
        let core = CoreState::new(manager, data_dir);
        Self {
            core,
            tool_router: Self::tool_router(),
        }
    }

    /// Direct access to the manager, for the stdio loop. Tool methods go
    /// through `self.client()` and `self.manager()`.
    pub fn manager(&self) -> Arc<ClientManager> {
        self.core.manager.clone()
    }

    pub fn client(&self) -> Arc<CoreState> {
        self.core.clone()
    }
}

#[tool_router]
impl K7sMcpServer {
    // === Connection tools ===

    /// List the contexts visible in the default kubeconfig. The AI can call
    /// this on startup to show the user what's available; `connect` then
    /// picks one.
    #[tool(
        description = "List contexts in the default kubeconfig. Returns the context name, the cluster it points at, and whether it's the current-context."
    )]
    async fn list_contexts(&self) -> Result<CallToolResult, McpError> {
        cluster::list_contexts().await
    }

    /// Build a kube client for a context and probe the API server. Tears
    /// down any previous connection first.
    #[tool(
        description = "Connect to a kubeconfig context. Tears down any existing connection, builds a client, probes the API server version. Returns the cluster identity (context, server, version)."
    )]
    async fn connect(
        &self,
        Parameters(p): Parameters<ConnectParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::connect(&self.manager(), p).await
    }

    /// Drop the current connection and all of its long-lived sessions.
    #[tool(
        description = "Disconnect from the current cluster. Aborts watchers, log streams, shells, and port-forwards. The next tool call will need `connect` again."
    )]
    async fn disconnect(&self) -> Result<CallToolResult, McpError> {
        cluster::disconnect(&self.manager()).await
    }

    /// Current connection status. `connected: false` means tools that need
    /// a client (everything except `list_contexts`) will return a
    /// "not connected" error.
    #[tool(
        description = "Show the current connection: context, server, API server version. Returns { connected: false } when nothing is connected."
    )]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        cluster::status(&self.manager()).await
    }

    // === Read tools ===

    #[tool(
        description = "List resources of a kind. For cluster-scoped kinds (nodes, namespaces, ...) namespace is ignored. Returns objects with { kind, namespace, name, summary } where summary is a one-line status like \"Running (3m)\"."
    )]
    async fn list_resources(
        &self,
        Parameters(p): Parameters<ListResourcesParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::list_resources(&self.manager(), p).await
    }

    #[tool(
        description = "Fetch one resource as YAML. Secret data is redacted; Helm release 'YAML' is the rendered manifest. managedFields is dropped so the YAML is round-trippable."
    )]
    async fn get_resource(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::get_resource(&self.manager(), p).await
    }

    #[tool(
        description = "Build the Properties panel for a resource: status, conditions, labels, selectors, container list, volume mounts, and a few other kind-specific sections. Returns the same JSON shape the UI uses."
    )]
    async fn describe_resource(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::describe_resource(&self.manager(), p).await
    }

    #[tool(
        description = "Read events filtered to a single object (kind+namespace+name). Returns [{ type, reason, message, count, age }, ...] in time order, matching what the UI's Events tab shows."
    )]
    async fn get_events(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::get_events(&self.manager(), p).await
    }

    #[tool(
        description = "Read the last N lines of a pod's logs (one-shot; not a stream). Use `container` to pick a specific container in a multi-container pod, `previous: true` to read the prior terminated container, `sinceSeconds` for a time window. Returns the raw log text."
    )]
    async fn get_logs(
        &self,
        Parameters(p): Parameters<LogsParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::get_logs(&self.manager(), p).await
    }

    // === Write tools ===

    #[tool(
        description = "Apply a YAML manifest to the cluster (server-side replace). Fails for Secret (read-only) and Helm release. Returns the server's response on success, or a verbatim API error on failure."
    )]
    async fn apply_yaml(
        &self,
        Parameters(p): Parameters<ApplyYamlParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::apply_yaml(&self.manager(), p).await
    }

    #[tool(
        description = "Server-side dry run of an apply. Returns { current, proposed } -- both as YAML -- so you can diff what would change after defaulting and mutating webhooks run. Read-only; nothing is written."
    )]
    async fn dry_run_yaml(
        &self,
        Parameters(p): Parameters<ApplyYamlParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::dry_run_yaml(&self.manager(), p).await
    }

    #[tool(
        description = "Delete a resource by kind/namespace/name. Refuses Helm release (read-only)."
    )]
    async fn delete_resource(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::delete_resource(&self.manager(), p).await
    }

    #[tool(
        description = "Scale a workload by patching spec.replicas. Works for Deployment, StatefulSet, ReplicaSet."
    )]
    async fn scale_resource(
        &self,
        Parameters(p): Parameters<ScaleParams>,
    ) -> Result<CallToolResult, McpError> {
        workload::scale_resource(&self.manager(), p).await
    }

    #[tool(
        description = "Cordon (unschedulable=true) or uncordon a node. Cordoning only blocks new pods; existing pods keep running. For full removal, use drain_node."
    )]
    async fn set_cordon(
        &self,
        Parameters(p): Parameters<CordonParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::set_cordon(&self.manager(), p).await
    }

    #[tool(
        description = "Delete a pod to force a restart (the controller will recreate it). For Deployments use restart_rollout. Refuses to delete a pod with no controller, since deletion alone wouldn't recreate it."
    )]
    async fn restart_pod(
        &self,
        Parameters(p): Parameters<NameNamespaceParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::restart_pod(&self.manager(), p).await
    }

    #[tool(
        description = "Diagnose why a Pod is unhealthy. Inspects container statuses for common failure patterns (OOMKilled, CrashLoopBackOff, ImagePullBackOff, segfault, etc.) and returns a structured diagnosis with exit codes, reasons, severity, and a human-readable summary. Use this when investigating why a Pod terminated, is stuck, or is restarting."
    )]
    async fn diagnose_pod(
        &self,
        Parameters(p): Parameters<DiagnosePodParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::diagnose_pod(&self.manager(), p).await
    }

    #[tool(
        description = "Trigger a rollout restart by patching the workload's pod-template annotation. The controller rolls through its normal update strategy. Works for Deployment, StatefulSet, DaemonSet, ReplicaSet."
    )]
    async fn restart_rollout(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        workload::restart_rollout(&self.manager(), p).await
    }

    #[tool(
        description = "Cordon the node, then evict its pods in the background. Returns immediately; track progress by listing pods on the node or re-describing the node. timeout_secs is a hint, not a hard stop -- the eviction task runs to completion."
    )]
    async fn drain_node(
        &self,
        Parameters(p): Parameters<DrainParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::drain_node(&self.manager(), p).await
    }

    // === Shell tools ===
    // Shell, exec, port-forward, pod-file, and convenience tools

    // -----------------------------------------------------------------------
    // Port-forwarding
    // -----------------------------------------------------------------------

    #[tool(
        description = "Forward a pod's port to localhost. local_port=0 lets the OS pick a free port. Returns { id, localPort, remotePort, pod, namespace } so you can connect to the local endpoint."
    )]
    async fn start_port_forward(
        &self,
        Parameters(p): Parameters<StartPortForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::start_port_forward(&self.manager(), p).await
    }

    #[tool(
        description = "Forward a Service port (resolves to a backing pod). Same return shape as start_port_forward; the chosen pod is exposed in the result."
    )]
    async fn start_service_port_forward(
        &self,
        Parameters(p): Parameters<StartServiceForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::start_service_port_forward(&self.manager(), p).await
    }

    #[tool(description = "Stop a port-forward by its id. Idempotent.")]
    async fn stop_port_forward(
        &self,
        Parameters(p): Parameters<StopForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::stop_port_forward(&self.manager(), p).await
    }

    #[tool(
        description = "List all active port-forwards. Each entry includes the local port (what you connect to) and the pod/service it points at."
    )]
    async fn list_port_forwards(&self) -> Result<CallToolResult, McpError> {
        shell::list_port_forwards(&self.manager()).await
    }

    // -----------------------------------------------------------------------
    // Interactive shells
    // -----------------------------------------------------------------------

    #[tool(
        description = "Open an interactive shell in a pod container. Returns { shellId, namespace, pod, container } -- the shell runs in the background; use shell_input to send keystrokes and shell_resize for terminal size."
    )]
    async fn start_shell(
        &self,
        Parameters(p): Parameters<StartShellParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::start_shell(&self.manager(), p).await
    }

    #[tool(
        description = "Send keystrokes to a shell started with start_shell or start_node_shell. The data is shipped as raw bytes; embed escape sequences the same way you'd type them."
    )]
    async fn shell_input(
        &self,
        Parameters(p): Parameters<ShellInputParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::shell_input(&self.manager(), p).await
    }

    #[tool(
        description = "Resize a shell's terminal. Call after the host's terminal is resized so apps that query the size (top, vim, less) behave."
    )]
    async fn shell_resize(
        &self,
        Parameters(p): Parameters<ShellResizeParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::shell_resize(&self.manager(), p).await
    }

    #[tool(description = "Stop a shell (pod or node). Idempotent.")]
    async fn stop_shell(
        &self,
        Parameters(p): Parameters<StopShellParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::stop_shell(&self.manager(), p).await
    }

    #[tool(
        description = "Open a root shell on a node (privileged debug pod). Requires cluster RBAC that lets you create privileged pods in the node-debug namespace. Returns { shellId, namespace, pod } -- use shell_input / shell_resize / stop_shell on it. The pod is automatically created, waited on (up to 90s for the image pull), and deleted when you stop the session."
    )]
    async fn start_node_shell(
        &self,
        Parameters(p): Parameters<DrainParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::start_node_shell(&self.manager(), p).await
    }

    #[tool(description = "Stop a node shell and delete its debug pod. Idempotent.")]
    async fn stop_node_shell(
        &self,
        Parameters(p): Parameters<StopShellParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::stop_node_shell(&self.manager(), p).await
    }

    // -----------------------------------------------------------------------
    // Convenience getters
    // -----------------------------------------------------------------------

    #[tool(
        description = "Default path to kubectl's kubeconfig, used to pre-point the import dialog in the UI. Read-only."
    )]
    async fn default_kubeconfig_path(&self) -> Result<CallToolResult, McpError> {
        cluster::default_kubeconfig_path().await
    }

    #[tool(
        description = "Built-in kind ids the MCP server knows how to resolve. Custom kinds (CRDs) are not in this list -- discover them with list_custom_kinds."
    )]
    async fn list_builtin_kinds(&self) -> Result<CallToolResult, McpError> {
        cluster::list_builtin_kinds().await
    }

    #[tool(
        description = "List the CRD-backed kinds discovered on connect. These are the kinds you can pass to list_resources / get_resource / describe_resource beyond the built-in ones."
    )]
    async fn list_custom_kinds(&self) -> Result<CallToolResult, McpError> {
        cluster::list_custom_kinds(&self.manager()).await
    }

    // -----------------------------------------------------------------------
    // One-shot exec, rollout status, top, cronjob trigger
    // -----------------------------------------------------------------------

    #[tool(
        description = "Run a single command in a pod container and return its stdout (kubectl exec). Non-interactive, non-TTY. The command runs via /bin/sh -c; stderr is merged into stdout."
    )]
    async fn exec_command(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::exec_command(&self.manager(), p).await
    }

    #[tool(
        description = "Inspect a workload's rollout state (kubectl rollout status). Returns replica counts, conditions, and a `done` flag. Accepts deployments, statefulsets, daemonsets, replicasets."
    )]
    async fn rollout_status(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        workload::rollout_status(&self.manager(), p).await
    }

    #[tool(
        description = "Snapshot of per-pod CPU/memory usage from metrics.k8s.io (kubectl top pods). Requires metrics-server."
    )]
    async fn top_pods(
        &self,
        Parameters(p): Parameters<TopPodsParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::top_pods(&self.manager(), p).await
    }

    #[tool(
        description = "Snapshot of per-node CPU/memory usage and capacity (kubectl top nodes). Requires metrics-server."
    )]
    async fn top_nodes(&self) -> Result<CallToolResult, McpError> {
        observability::top_nodes(&self.manager()).await
    }

    #[tool(
        description = "Manually trigger a CronJob by creating a Job from its spec (kubectl create job --from=cronjob/<name>). Returns the new Job's name."
    )]
    async fn trigger_cronjob(
        &self,
        Parameters(p): Parameters<NameNamespaceNameParams>,
    ) -> Result<CallToolResult, McpError> {
        workload::trigger_cronjob(&self.manager(), p).await
    }

    // -----------------------------------------------------------------------
    // Multi-document YAML apply / dry-run
    // -----------------------------------------------------------------------

    #[tool(
        description = "Apply a multi-document YAML bundle (documents separated by ---). Each doc is applied via server-side apply; stops at the first error and returns per-document status."
    )]
    async fn apply_yaml_bundle(
        &self,
        Parameters(p): Parameters<YamlBundleParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::apply_yaml_bundle(&self.manager(), p).await
    }

    #[tool(
        description = "Dry-run a multi-document YAML bundle without writing anything. Returns per-document proposed YAML and any error."
    )]
    async fn dry_run_yaml_bundle(
        &self,
        Parameters(p): Parameters<YamlBundleParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::dry_run_yaml_bundle(&self.manager(), p).await
    }

    // -----------------------------------------------------------------------
    // API resources discovery + Endpoints
    // -----------------------------------------------------------------------

    #[tool(
        description = "Discover every resource the API server serves (kubectl api-resources). Returns name, group, version, kind, namespaced, verbs for each."
    )]
    async fn list_api_resources(&self) -> Result<CallToolResult, McpError> {
        cluster::list_api_resources(&self.manager()).await
    }

    #[tool(
        description = "List EndpointSlices. Optional namespace scopes the list; optional service filters to one Service's slices. Without filters, lists cluster-wide."
    )]
    async fn list_endpoints(
        &self,
        Parameters(p): Parameters<ListEndpointsParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::list_endpoints(&self.manager(), p).await
    }

    // -----------------------------------------------------------------------
    // Pod file operations
    // -----------------------------------------------------------------------

    #[tool(
        description = "List a directory inside a pod container. Returns file/dir/symlink entries with size, mtime, and POSIX mode."
    )]
    async fn pod_list_files(
        &self,
        Parameters(p): Parameters<PodFileParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::pod_list_files(&self.manager(), p).await
    }

    #[tool(description = "Read a file's text contents from a pod container (UTF-8 lossy).")]
    async fn pod_read_file(
        &self,
        Parameters(p): Parameters<PodFileParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::pod_read_file(&self.manager(), p).await
    }

    #[tool(
        description = "Write a file inside a pod container. Creates parent directories as needed."
    )]
    async fn pod_write_file(
        &self,
        Parameters(p): Parameters<PodFileWriteParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::pod_write_file(&self.manager(), p).await
    }

    #[tool(description = "Download a path from a pod container as a base64-encoded tar archive.")]
    async fn pod_download_file(
        &self,
        Parameters(p): Parameters<PodFileParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::pod_download_file(&self.manager(), p).await
    }

    #[tool(
        description = "Upload a base64-encoded tar archive into a directory inside a pod container."
    )]
    async fn pod_upload_file(
        &self,
        Parameters(p): Parameters<PodFileUploadParams>,
    ) -> Result<CallToolResult, McpError> {
        pod::pod_upload_file(&self.manager(), p).await
    }

    // -----------------------------------------------------------------------
    // Import kubeconfig content
    // -----------------------------------------------------------------------

    #[tool(
        description = "Register every context in a kubeconfig YAML blob so a later `connect` can build from it. Returns the merged context list."
    )]
    async fn import_kubeconfig(
        &self,
        Parameters(p): Parameters<ImportKubeconfigParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::import_kubeconfig(&self.manager(), p).await
    }

    // === Helm tools ===
    // Helm operation and chart repository tools

    // -----------------------------------------------------------------------
    // Helm operations (install / upgrade / uninstall / rollback / history)
    // -----------------------------------------------------------------------

    #[tool(
        description = "Install a Helm chart (helm install). Streams progress to the event sink; returns the final result. The release name is required."
    )]
    async fn helm_install(
        &self,
        Parameters(p): Parameters<HelmInstallParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_install(&self.manager(), p).await
    }

    #[tool(
        description = "Upgrade a Helm release (helm upgrade). Creates the release if absent. Supports reuseValues, rollbackOnFailure, and dryRun."
    )]
    async fn helm_upgrade(
        &self,
        Parameters(p): Parameters<HelmUpgradeParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_upgrade(&self.manager(), p).await
    }

    #[tool(
        description = "Uninstall a Helm release (helm uninstall). Set keepHistory=true to retain revisions for a later rollback."
    )]
    async fn helm_uninstall(
        &self,
        Parameters(p): Parameters<HelmUninstallParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_uninstall(&self.manager(), p).await
    }

    #[tool(
        description = "Roll back a Helm release to a previous revision (helm rollback). revision is optional -- empty rolls back to the previous one."
    )]
    async fn helm_rollback(
        &self,
        Parameters(p): Parameters<HelmRollbackParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_rollback(&self.manager(), p).await
    }

    #[tool(
        description = "Fetch the revision history for a Helm release (helm history). Returns one row per revision with status, chart, and app version."
    )]
    async fn helm_history(
        &self,
        Parameters(p): Parameters<HelmHistoryParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_history(p).await
    }

    #[tool(
        description = "Fetch the rendered Kubernetes manifest for a specific revision of a Helm release. Unlike get_resource which returns the latest revision, this lets you inspect any historical revision. Returns the raw YAML manifest."
    )]
    async fn helm_manifest_revision(
        &self,
        Parameters(p): Parameters<HelmManifestRevisionParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_manifest_revision(&self.manager(), p).await
    }

    #[tool(
        description = "Fetch the user-supplied values (config) for a specific revision of a Helm release. Returns the JSON object of value overrides the user provided at install/upgrade time."
    )]
    async fn helm_values_revision(
        &self,
        Parameters(p): Parameters<HelmValuesRevisionParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_values_revision(&self.manager(), p).await
    }

    #[tool(
        description = "Render a chart's default values.yaml (helm show values). Useful to prefill the values editor before helm_install/helm_upgrade."
    )]
    async fn helm_show_values(
        &self,
        Parameters(p): Parameters<HelmShowValuesParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_show_values(p).await
    }

    // -----------------------------------------------------------------------
    // Helm chart repository management
    // -----------------------------------------------------------------------

    #[tool(
        description = "List the user's configured Helm chart repositories, with last refresh status."
    )]
    async fn helm_list_repos(&self) -> Result<CallToolResult, McpError> {
        helm::helm_list_repos().await
    }

    #[tool(
        description = "Search across every cached Helm repo index. Empty query returns everything."
    )]
    async fn helm_search_charts(
        &self,
        Parameters(p): Parameters<HelmSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_search_charts(p).await
    }

    #[tool(description = "Add a Helm chart repository.")]
    async fn helm_add_repo(
        &self,
        Parameters(p): Parameters<HelmRepoParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_add_repo(p).await
    }

    #[tool(description = "Remove a Helm chart repository and its cached index.")]
    async fn helm_remove_repo(
        &self,
        Parameters(p): Parameters<HelmRepoNameParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_remove_repo(p).await
    }

    #[tool(
        description = "Re-fetch a Helm repo's index from its URL. Returns the updated repo entry."
    )]
    async fn helm_update_repo(
        &self,
        Parameters(p): Parameters<HelmRepoNameParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_update_repo(p).await
    }

    // -----------------------------------------------------------------------
    // Local chart library (offline)
    // -----------------------------------------------------------------------

    #[tool(
        description = "List the offline local chart library (the same charts the UI's ChartOps view shows: .tgz packages and unpacked chart dirs, with name, version, appVersion, size, and path). Works without a cluster connection."
    )]
    async fn helm_local_charts(&self) -> Result<CallToolResult, McpError> {
        helm::helm_local_charts(&self.core.data_dir).await
    }

    #[tool(
        description = "Render a chart's Kubernetes templates offline (helm template -- no cluster contact, nothing applied). chart may be repo/name, an OCI URL, or a local library path; values is values.yaml content overriding the defaults (empty = chart defaults). Returns the rendered YAML manifest. Requires the helm binary on the server host."
    )]
    async fn helm_render_preview(
        &self,
        Parameters(p): Parameters<HelmRenderPreviewParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_render_preview(p).await
    }

    #[tool(
        description = "Run helm lint on a chart from the local chart library (id from helm_local_charts). Offline -- no cluster contact. Returns helm's lint report."
    )]
    async fn helm_lint_chart(
        &self,
        Parameters(p): Parameters<HelmChartIdParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_lint_chart(&self.core.data_dir, p).await
    }

    #[tool(
        description = "Package an unpacked dir chart from the local chart library into a .tgz (helm package; writes <library>/<name>-<version>.tgz next to the source). Charts that are already packaged are refused. Requires the helm binary on the server host. Returns the new archive's library entry."
    )]
    async fn helm_package_chart(
        &self,
        Parameters(p): Parameters<HelmChartIdParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_package_chart(&self.core.data_dir, p).await
    }

    #[tool(
        description = "Run helm dependency list|build|update on a chart from the local chart library. action=list is offline (shows declared deps); build/update fetch dependency charts from their repositories into the chart's charts/ dir. Returns the command's report."
    )]
    async fn helm_chart_deps(
        &self,
        Parameters(p): Parameters<HelmChartDepsParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_chart_deps(&self.core.data_dir, p).await
    }

    // === Monitoring tools ===
    // Monitoring, image registry, image sync, and enhanced AI integration tools

    // -----------------------------------------------------------------------
    // Monitoring: Prometheus / AlertManager / Grafana
    // -----------------------------------------------------------------------

    #[tool(
        description = "Run an instant PromQL query against a configured Prometheus instance (by name)."
    )]
    async fn prometheus_query(
        &self,
        Parameters(p): Parameters<PrometheusQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::prometheus_query(p).await
    }

    #[tool(
        description = "Run a range PromQL query (start/end epoch-ms, step seconds) against a configured Prometheus instance."
    )]
    async fn prometheus_query_range(
        &self,
        Parameters(p): Parameters<PrometheusQueryRangeParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::prometheus_query_range(p).await
    }

    #[tool(description = "List active alerts from a configured AlertManager instance (by name).")]
    async fn alertmanager_alerts(
        &self,
        Parameters(p): Parameters<InstanceNameParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::alertmanager_alerts(p).await
    }

    #[tool(description = "List silences from a configured AlertManager instance (by name).")]
    async fn alertmanager_silences(
        &self,
        Parameters(p): Parameters<InstanceNameParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::alertmanager_silences(p).await
    }

    #[tool(
        description = "Build a direct Grafana dashboard URL (by instance name, dashboard uid, from/to epoch-ms)."
    )]
    async fn grafana_dashboard_url(
        &self,
        Parameters(p): Parameters<GrafanaDashboardParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::grafana_dashboard_url(p).await
    }

    // -----------------------------------------------------------------------
    // Image registry queries
    // -----------------------------------------------------------------------

    #[tool(
        description = "List tags for a repository in a configured image registry (by registry name)."
    )]
    async fn image_registry_tags(
        &self,
        Parameters(p): Parameters<ImageRegistryRepoParams>,
    ) -> Result<CallToolResult, McpError> {
        image::image_registry_tags(p).await
    }

    #[tool(description = "Fetch the manifest for a repo:tag in a configured image registry.")]
    async fn image_registry_manifest(
        &self,
        Parameters(p): Parameters<ImageRegistryManifestParams>,
    ) -> Result<CallToolResult, McpError> {
        image::image_registry_manifest(p).await
    }

    #[tool(
        description = "Run a previously-saved PromQL query (by saved-query name) against a Prometheus instance. Set forceRefresh=true to bypass the cache."
    )]
    async fn saved_query_run(
        &self,
        Parameters(p): Parameters<SavedQueryRunParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::saved_query_run(p).await
    }

    // -----------------------------------------------------------------------
    // Image sync / import (air-gapped clusters)
    // -----------------------------------------------------------------------

    #[tool(
        description = "Check whether skopeo is installed and usable. Call this before image_copy to confirm the host can sync images. Returns the resolved path and version, or an install hint."
    )]
    async fn image_sync_status(&self) -> Result<CallToolResult, McpError> {
        image::image_sync_status().await
    }

    #[tool(
        description = "Copy an image into a configured destination registry using skopeo (air-gapped / offline clusters). `source` is any skopeo transport: docker://nginx:1.25 (public registry), docker-archive:/tmp/img.tar (local docker-save tarball), oci:..., dir:.... The destination registry is resolved by name from the configured image registries (its stored credentials are used automatically). Streams copy progress to the event sink."
    )]
    async fn image_copy(
        &self,
        Parameters(p): Parameters<ImageCopyParams>,
    ) -> Result<CallToolResult, McpError> {
        image::image_copy(&self.manager(), p).await
    }

    #[tool(
        description = "Inspect a local docker-save tarball (or OCI archive) before copying it: returns the image name, tags, digest, architecture, os, and total size. Use this to confirm a tar's contents before image_copy."
    )]
    async fn image_inspect_archive(
        &self,
        Parameters(p): Parameters<ImageArchiveParams>,
    ) -> Result<CallToolResult, McpError> {
        image::image_inspect_archive(p).await
    }

    // -----------------------------------------------------------------------
    // Phase 4 -- Enhanced AI integration tools
    // -----------------------------------------------------------------------

    #[tool(
        description = "Auto-diagnose cluster issues. Checks node health, pod failures, deployment availability, recent warning events, and resource pressure. Returns a structured diagnostic report with severity levels and recommendations."
    )]
    async fn diagnose_cluster(&self) -> Result<CallToolResult, McpError> {
        cluster::diagnose_cluster(&self.manager()).await
    }

    #[tool(
        description = "Suggest fixes for a specific resource problem. Examines the resource's status, conditions, and events to propose actionable fixes (scale, restart, rollback, edit image, etc.)."
    )]
    async fn suggest_fix(
        &self,
        Parameters(p): Parameters<GetResourceParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::suggest_fix(&self.manager(), p).await
    }

    #[tool(
        description = "Find resources by label selector. Returns matching resources with their key metadata. Useful for finding all pods belonging to a deployment, or all resources with a specific label."
    )]
    async fn find_resources_by_label(
        &self,
        Parameters(p): Parameters<FindByLabelParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::find_resources_by_label(&self.manager(), p).await
    }

    #[tool(
        description = "Create an AlertManager silence to suppress matching alerts for a duration. matchers is an array of {name, value, isRegex}; durationHours sets the silence length (default 4h). Returns the silence ID."
    )]
    async fn create_silence(
        &self,
        Parameters(p): Parameters<CreateSilenceParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::create_silence(p).await
    }

    #[tool(
        description = "Expire (delete) an AlertManager silence by ID. The silence will immediately stop suppressing alerts."
    )]
    async fn delete_silence(
        &self,
        Parameters(p): Parameters<DeleteSilenceParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::delete_silence(p).await
    }

    #[tool(
        description = "List alerting rules from a Prometheus instance. Returns rule groups with their alerting rules (name, state, severity, query, duration)."
    )]
    async fn list_alert_rules(
        &self,
        Parameters(p): Parameters<InstanceNameParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::list_alert_rules(p).await
    }

    #[tool(
        description = "Search K8s audit logs from a configured Loki instance. Filters: namespace, resource, user, sinceSeconds (default 3600), limit (default 200). Returns parsed audit events with verb, resource, user, status code, and timestamps."
    )]
    async fn audit_search(
        &self,
        Parameters(p): Parameters<AuditSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        security::audit_search(p).await
    }

    #[tool(
        description = "Search Grafana dashboards by query string. Returns matching dashboards with uid, title, tags, and URL. Use grafana_dashboard_url with the returned uid to build an embeddable URL."
    )]
    async fn grafana_search(
        &self,
        Parameters(p): Parameters<GrafanaSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::grafana_search(p).await
    }

    // -----------------------------------------------------------------------
    // SBOM tools
    // -----------------------------------------------------------------------

    #[tool(
        description = "Generate an SBOM (Software Bill of Materials) for a container image. Uses trivy, grype, or a native fallback. Returns the SBOM id, component count, vulnerability count, and tool used. Optionally correlate vulnerabilities with the SBOM."
    )]
    async fn sbom_generate_image(
        &self,
        Parameters(p): Parameters<SbomGenerateParams>,
    ) -> Result<CallToolResult, McpError> {
        security::sbom_generate_image(&self.core.data_dir, p).await
    }

    #[tool(
        description = "List all SBOM scan history entries. Returns id, image reference, format, component count, vulnerability count, tool, and creation time."
    )]
    async fn sbom_list_history(&self) -> Result<CallToolResult, McpError> {
        security::sbom_list_history(&self.core.data_dir).await
    }

    #[tool(
        description = "Get the full SBOM details by ID. Returns components (name, version, type), vulnerabilities, format, and metadata."
    )]
    async fn sbom_get(
        &self,
        Parameters(p): Parameters<SbomGetParams>,
    ) -> Result<CallToolResult, McpError> {
        security::sbom_get(&self.core.data_dir, p).await
    }

    #[tool(
        description = "Get the current cluster health score (0-100, letter grade A-F) with individual check results for node readiness, pod health, deployment availability, resource pressure, PVC status, and more."
    )]
    async fn cluster_health(&self) -> Result<CallToolResult, McpError> {
        cluster::cluster_health(&self.manager()).await
    }

    // === New tools (shared impls layer) ===

    #[tool(
        description = "Batch-get multiple resources at once. Pass an array of {kind, namespace, name} objects. Returns all results in one response — much faster than calling describe_resource N times."
    )]
    async fn batch_get(
        &self,
        Parameters(p): Parameters<BatchGetParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::batch_get(&self.manager(), p).await
    }

    #[tool(
        description = "Compare two resources or two versions of the same resource. Returns whether they're identical and their YAML line counts."
    )]
    async fn diff_resources(
        &self,
        Parameters(p): Parameters<DiffResourcesParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::diff_resources(&self.manager(), p).await
    }

    #[tool(
        description = "Get HPA (HorizontalPodAutoscaler) status for a namespace. Shows min/max/current replicas and target metrics."
    )]
    async fn hpa_status(
        &self,
        Parameters(p): Parameters<HpaStatusParams>,
    ) -> Result<CallToolResult, McpError> {
        workload::hpa_status(&self.manager(), p).await
    }

    #[tool(
        description = "Audit NetworkPolicies in a namespace. Shows which pods are isolated, what ingress/egress rules exist, and identifies pods with no matching policies."
    )]
    async fn network_policy_audit(
        &self,
        Parameters(p): Parameters<NamespaceParam>,
    ) -> Result<CallToolResult, McpError> {
        security::network_policy_audit(&self.manager(), p).await
    }

    #[tool(
        description = "RBAC 'who can' query: check who can perform a verb on a resource in a namespace. Returns matching ClusterRoleBindings and RoleBindings."
    )]
    async fn rbac_who_can(
        &self,
        Parameters(p): Parameters<RbacWhoCanParams>,
    ) -> Result<CallToolResult, McpError> {
        security::rbac_who_can(&self.manager(), p).await
    }

    #[tool(
        description = "Run a comprehensive RBAC security audit of the cluster. Identifies over-privileged roles, wildcard permissions, secret access, pod exec capabilities, anonymous bindings, and other security risks. Returns an AuditReport with findings sorted by severity."
    )]
    async fn security_audit(
        &self,
        Parameters(p): Parameters<SecurityAuditParams>,
    ) -> Result<CallToolResult, McpError> {
        security::security_audit(&self.manager(), p).await
    }

    #[tool(
        description = "Build the RBAC permission matrix showing which subjects (users, groups, service accounts) can perform which actions (verb+resource) on which resources. Returns a sparse cross-tabulation of subjects vs actions with grant sources."
    )]
    async fn rbac_permission_matrix(
        &self,
        Parameters(p): Parameters<RbacPermissionMatrixParams>,
    ) -> Result<CallToolResult, McpError> {
        security::rbac_permission_matrix(&self.manager(), p).await
    }

    // === Consolidated tools (replace multiple single-purpose tools) ===

    #[tool(
        description = "Unified Helm release operation. action: install|upgrade|uninstall|rollback. Consolidates helm_install, helm_upgrade, helm_uninstall, helm_rollback into one tool."
    )]
    async fn helm_release(
        &self,
        Parameters(p): Parameters<HelmReleaseParams>,
    ) -> Result<CallToolResult, McpError> {
        helm::helm_release(&self.manager(), p).await
    }

    #[tool(
        description = "Unified port-forward operation. action: start|stop|list. Consolidates start_port_forward, start_service_port_forward, stop_port_forward, list_port_forwards."
    )]
    async fn port_forward(
        &self,
        Parameters(p): Parameters<PortForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        shell::port_forward(&self.manager(), p).await
    }

    #[tool(
        description = "Unified Prometheus query. Set range=true with start/end/step for range queries, or omit for instant queries. Consolidates prometheus_query and prometheus_query_range."
    )]
    async fn prometheus_query_unified(
        &self,
        Parameters(p): Parameters<PrometheusUnifiedParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::prometheus_query_unified(p).await
    }

    #[tool(
        description = "Unified SBOM operation. action: generate|list|get. Consolidates sbom_generate_image, sbom_list_history, sbom_get."
    )]
    async fn sbom_unified(
        &self,
        Parameters(p): Parameters<SbomUnifiedParams>,
    ) -> Result<CallToolResult, McpError> {
        security::sbom_unified(&self.core.data_dir, p).await
    }

    #[tool(
        description = "Unified AlertManager silence operation. action: create|delete. Consolidates create_silence and delete_silence."
    )]
    async fn silence(
        &self,
        Parameters(p): Parameters<SilenceUnifiedParams>,
    ) -> Result<CallToolResult, McpError> {
        observability::silence(p).await
    }

    #[tool(
        description = "Unified kind discovery. scope: builtin|custom|all. Consolidates list_builtin_kinds, list_custom_kinds, list_api_resources."
    )]
    async fn list_kinds(
        &self,
        Parameters(p): Parameters<ListKindsParams>,
    ) -> Result<CallToolResult, McpError> {
        cluster::list_kinds(&self.manager(), p).await
    }

    #[tool(
        description = "Estimate resource costs for a namespace. Lists all pods with their CPU/memory requests and calculates approximate monthly cost based on standard cloud pricing."
    )]
    async fn cost_estimate(
        &self,
        Parameters(p): Parameters<NamespaceParam>,
    ) -> Result<CallToolResult, McpError> {
        observability::cost_estimate(&self.manager(), p).await
    }
}

// ---------------------------------------------------------------------------
// ServerHandler -- rmcp boilerplate. `#[tool_handler]` synthesises the
// dispatch (list_tools / call_tool) from the `#[tool]` methods on the impl
// above; we just need to describe the server in `get_info`.
// ---------------------------------------------------------------------------

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for K7sMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info.name = "k7s-mcp".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.instructions = Some(
            "k7s MCP -- Kubernetes tooling for AI clients. \
             Call `list_contexts` then `connect` before any cluster operation; \
             use the built-in kind ids (pods, deployments, services, nodes, ...) \
             for the common resources, `list_custom_kinds` for CRDs, or \
             `list_api_resources` for the full kubectl-api-resources table. \
             Reads: `list_resources` / `get_resource` / `describe_resource` / \
             `get_events` / `get_logs` / `list_endpoints` / `top_pods` / \
             `top_nodes` / `rollout_status`. \
             Writes: `apply_yaml` / `dry_run_yaml` / `apply_yaml_bundle` / \
             `dry_run_yaml_bundle` / `delete_resource` / `scale_resource` / \
             `set_cordon` / `restart_pod` / `restart_rollout` / `drain_node` / \
             `trigger_cronjob`. \
             Helm: `helm_install` / `helm_upgrade` / `helm_uninstall` / \
             `helm_rollback` / `helm_history` / `helm_show_values` / \
             `helm_list_repos` / `helm_search_charts` / `helm_add_repo` / \
             `helm_remove_repo` / `helm_update_repo`. \
             Local chart library (offline): `helm_local_charts` / \
             `helm_render_preview` / `helm_lint_chart` / \
             `helm_package_chart` / `helm_chart_deps` (lint/preview/list are \
             offline; package/build/update need the helm binary on the host). \
             Execution: `exec_command` (one-shot) or `start_shell` (interactive); \
             `start_node_shell` for a node root shell. \
             Pod files: `pod_list_files` / `pod_read_file` / `pod_write_file` / \
             `pod_download_file` / `pod_upload_file`. \
             Port-forwards: `start_port_forward` / `start_service_port_forward`. \
             Monitoring (instances configured in the UI): `prometheus_query` / \
             `prometheus_query_range` / `alertmanager_alerts` / \
             `alertmanager_silences` / `grafana_dashboard_url` / \
             `image_registry_tags` / `image_registry_manifest` / `saved_query_run`. \
             Image import (air-gapped clusters): `image_sync_status` / \
             `image_copy` (copy docker:// or docker-archive: sources into a \
             configured internal registry; requires skopeo on PATH) / \
             `image_inspect_archive`. \
             SBOM: `sbom_generate_image` / `sbom_list_history` / `sbom_get`. \
             Long-lived sessions return an id you pass to the matching `stop_*` tool."
                .to_string(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

// ---------------------------------------------------------------------------
// Stdio entry
// ---------------------------------------------------------------------------

/// Serve MCP over stdin/stdout. Used by the `k7s-mcp` binary.
pub async fn serve_stdio(server: K7sMcpServer) -> Result<(), Box<dyn std::error::Error>> {
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

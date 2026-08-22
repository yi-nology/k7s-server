//! MCP server for k7s.
//!
//! Exposes the same Kubernetes plumbing the desktop and web shells use, but
//! over the Model Context Protocol -- the wire format AI clients
//! (Claude Desktop, Cursor, Claude Code, ...) speak when they want to call
//! tools on a local process.
//!
//! Transport is stdio: the binary `k7s-mcp` reads JSON-RPC from stdin and
//! writes to stdout. The MCP host launches it as a child process; the host
//! and server never share a network socket.
//!
//! What you get:
//! - Read tools: list / get / describe / logs / events / metrics /
//!   `list_helm_releases`.
//! - Write tools: `apply_yaml` / `dry_run_yaml` / `delete_resource` /
//!   `scale_resource` / `set_cordon` / `restart_pod` / `restart_rollout` /
//!   `drain_node`.
//! - Long-lived tools: `start_port_forward` / `start_service_port_forward` /
//!   `stop_port_forward` / `list_port_forwards`, and `start_shell` /
//!   `shell_input` / `shell_resize` / `stop_shell` / `start_node_shell` /
//!   `stop_node_shell`.
//! - Connection tools: `list_contexts` / `connect` / `disconnect` / `status`.
//!
//! The whole server is one `#[derive(Clone)]` struct wrapped by the rmcp
//! `#[tool_router]` / `#[tool_handler]` macros, so adding a new tool is a
//! matter of writing another method on the impl block -- the macro picks it
//! up and wires the schema in.

#[cfg(any(feature = "mcp", feature = "web"))]
pub mod kube_api;

#[cfg(any(feature = "mcp", feature = "web"))]
mod params;

#[cfg(any(feature = "mcp", feature = "web"))]
mod helpers;

#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod tools;

#[cfg(any(feature = "mcp", feature = "web"))]
pub mod server;

#[cfg(any(feature = "mcp", feature = "web"))]
pub use server::K7sMcpServer;

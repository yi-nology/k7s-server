//! Domain modules holding the bodies of the `#[tool]` methods on
//! [`K7sMcpServer`](crate::mcp::server::K7sMcpServer).
//!
//! The rmcp `#[tool_router]` macro requires every `#[tool]` method to live in
//! the impl block in `server.rs`, so that file keeps thin one-line wrappers
//! and each body lives here, grouped by domain:
//!
//! - [`cluster`] -- connection, generic resource read/write, kinds, nodes
//! - [`pod`] -- logs, exec, pod diagnosis, pod file operations
//! - [`workload`] -- scale / restart / rollout / cronjob / HPA
//! - [`helm`] -- Helm release operations and chart repository management
//! - [`image`] -- image registry queries and skopeo image sync
//! - [`observability`] -- Prometheus / AlertManager / Grafana / top / cost
//! - [`security`] -- RBAC, audit, NetworkPolicy, SBOM
//! - [`shell`] -- interactive shells, node shells, port-forwards

#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod cluster;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod helm;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod image;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod observability;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod pod;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod security;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod shell;
#[cfg(any(feature = "mcp", feature = "web"))]
pub(crate) mod workload;

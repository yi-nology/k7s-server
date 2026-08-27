//! k7s-web — the browser-facing shell.
//!
//! An axum HTTP server that exposes the same `core::` business logic the Tauri
//! shell uses, but reachable from a plain browser tab. Vite (port 1420) is
//! the front-end; this server (port 7180) is the back-end. The Vite dev
//! server proxies `/api/*` to here so the browser sees one origin.
//!
//! The contract with the front-end is intentionally narrow:
//! - `POST /invoke/{cmd}` for one-shot operations (with the body the command
//!   would have taken as parameters).
//! - `GET /events` as an SSE stream of every `EventSink` emit.
//!
//! That mirrors the Tauri contract (`invoke` + `listen`) closely enough that
//! the front-end can pick the right transport at boot — see
//! `src/providers/transport.ts` for the seam.

#[cfg(feature = "web")]
pub mod ai_handlers;
#[cfg(feature = "web")]
pub mod auth;
#[cfg(feature = "web")]
pub mod auth_password;
#[cfg(feature = "web")]
pub mod handlers;
#[cfg(feature = "web")]
pub mod hook_handlers;
#[cfg(feature = "web")]
pub mod server;
#[cfg(feature = "web")]
pub mod sse;
#[cfg(feature = "web")]
pub mod state;
#[cfg(feature = "web")]
pub mod types;

#[cfg(feature = "web")]
pub use server::serve;
#[cfg(feature = "web")]
pub use state::WebState;

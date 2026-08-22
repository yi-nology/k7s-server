//! Web state — the shared bits the axum routes close over.
//!
//! The Tauri shell stores the same data in `k7s_core::core::CoreState` (via
//! `app.manage`). Here we wrap it with the SSE receiver, which only the
//! web shell has — the Tauri shell never serves SSE.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k7s_core::core::events::{WebEvent, WebEventReceiver};
use k7s_core::core::CoreState;
use k7s_core::kube::ClientManager;

/// Everything an axum handler needs. Cheap to clone (`Arc` deref + enum).
#[derive(Clone)]
pub struct WebState {
    /// The shared `core::CoreState` — manager (which carries the sink),
    /// data dir for prefs.
    pub core: Arc<CoreState>,
    /// Sender half of the broadcast the `WebEventSink` writes to. We hold a
    /// clone so the broadcast isn't dropped (it auto-closes with no
    /// receivers); every SSE connection calls [`subscribe_sse`] for its own
    /// receiver.
    pub event_tx: k7s_deps::tokio::sync::broadcast::Sender<WebEvent>,
    /// Per-run event store for polling. Maps run_id → list of events.
    pub ai_runs: Arc<Mutex<HashMap<String, Vec<k7s_deps::serde_json::Value>>>>,
    /// Per-run pending write-tool approvals: call_id → approval sender.
    /// The agent loop's `await_approval` awaits the receiver; the
    /// `/api/invoke/ai_approve_tool_call` handler resolves the sender.
    pub pending_approvals:
        Arc<Mutex<HashMap<String, k7s_deps::tokio::sync::oneshot::Sender<bool>>>>,
    /// Bearer token every `/api/invoke/*` + `/hooks/*` request must carry.
    /// Resolved from `K7S_WEB_TOKEN` or a persisted random secret — see
    /// [`super::auth::resolve_token`].
    pub web_token: Arc<String>,
    /// Whether the bind address is loopback. Loopback binds publish the token
    /// at `GET /api/web-token` (so the same-origin SPA can self-serve it);
    /// non-loopback binds refuse to publish and require `K7S_WEB_TOKEN`.
    pub is_loopback: bool,
    /// Single-user password gate (P1): argon2 hash + in-memory sessions.
    /// `Arc` so the route state and the auth middleware's state clone share
    /// one session map — a plain `Mutex<PasswordAuth>` field would give each
    /// clone its own copy and sessions issued by handlers would be invisible
    /// to `require_token`.
    pub password_auth: Arc<Mutex<super::auth_password::PasswordAuth>>,
    /// Data dir, kept next to `core` for the password-file path. The auth
    /// handlers persist the argon2 hash to `<data_dir>/web-password`.
    pub data_dir: std::path::PathBuf,
    /// The shared command registry — the same table the Tauri shells use.
    /// `POST /api/invoke/{cmd}` dispatches through it for every non-AI
    /// command; AI keeps its bespoke handlers.
    pub registry: std::sync::Arc<k7s_core::core::commands::CommandRegistry>,
}

impl WebState {
    /// Build a fresh web state. The sink the manager gets and the SSE
    /// receivers come from the same broadcast — one emit reaches every
    /// connected client.
    ///
    /// `addr` is the bind address — used to set `is_loopback`, which controls
    /// whether `GET /api/web-token` is mounted (loopback only).
    pub fn new(data_dir: std::path::PathBuf, addr: std::net::SocketAddr) -> Self {
        // The trick: `web_sink` returns both an `EventSink` (which the manager
        // takes) and a *seed* `broadcast::Receiver`. We need a
        // `broadcast::Sender` to keep ourselves, so we go through
        // `web_sink` twice — once to build the sink, once to get a sender to
        // keep. Both wrap the same underlying broadcast.
        let (sink, _seed_rx) = k7s_core::core::events::web_sink(1024);
        let manager = Arc::new(ClientManager::new(sink));
        let core = CoreState::new(manager, data_dir);

        // Grab a sender to keep. `subscribe_sse` will hand out fresh receivers
        // on it for every new SSE connection.
        let event_tx = k7s_core::core::events::web_sink_sender(&core);

        let web_token = Arc::new(super::auth::resolve_token(&core.data_dir));
        let is_loopback = addr.ip().is_loopback();
        let password_auth = Arc::new(Mutex::new(super::auth_password::PasswordAuth::load(
            &core.data_dir,
        )));
        let data_dir = core.data_dir.clone();
        let registry = std::sync::Arc::new(k7s_commands::registry::build_registry());

        Self {
            registry,
            core,
            event_tx,
            ai_runs: Arc::new(Mutex::new(HashMap::new())),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            web_token,
            is_loopback,
            password_auth,
            data_dir,
        }
    }

    /// A fresh subscriber for a new SSE connection.
    pub fn subscribe_sse(&self) -> WebEventReceiver {
        self.event_tx.subscribe()
    }

    /// Emit an event to all connected SSE clients. Used by the AI chat handler
    /// to push `ai_event` frames.
    pub fn emit_event(&self, name: impl Into<String>, data: k7s_deps::serde_json::Value) {
        let _ = self.event_tx.send(WebEvent {
            name: name.into(),
            data,
        });
    }
}

//! Web state — the shared bits the axum routes close over.
//!
//! Every password login gets its own cluster connection (its own
//! `ClientManager` + event sink), so one session's `connect` can't re-point
//! another's writes. Requests without a session cookie (bearer-token API
//! clients, cron) share the "service" connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use k7s_core::core::events::WebEvent;
use k7s_core::core::CoreState;
use k7s_core::kube::ClientManager;

/// The session token a request was authenticated with, inserted by
/// `require_token`. `None` = bearer-token request (shared service connection).
#[derive(Clone)]
pub struct SessionToken(pub Option<String>);

/// One connection: a manager (with its sink) plus the broadcast that feeds its
/// SSE stream.
pub struct SessionCtx {
    pub core: Arc<CoreState>,
    pub event_tx: k7s_deps::tokio::sync::broadcast::Sender<WebEvent>,
}

impl SessionCtx {
    fn new(data_dir: std::path::PathBuf) -> Self {
        // `web_sink` hands back the sink (the manager takes it) plus a seed
        // receiver; a second call yields the sender we keep for SSE.
        let (sink, _seed_rx) = k7s_core::core::events::web_sink(1024);
        let manager = Arc::new(ClientManager::new(sink));
        let core = CoreState::new(manager, data_dir);
        let event_tx = k7s_core::core::events::web_sink_sender(&core);
        Self { core, event_tx }
    }
}

/// Everything an axum handler needs. Cheap to clone (`Arc` deref + enum).
#[derive(Clone)]
pub struct WebState {
    /// Shared connection: bearer-token API clients, cron, and the fallback for
    /// requests without a session cookie.
    pub service: Arc<SessionCtx>,
    /// One connection per password login, keyed by the `k7s_session` cookie.
    sessions: Arc<Mutex<HashMap<String, Arc<SessionCtx>>>>,
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
    /// Whether this process terminates TLS itself (`--tls-cert/--tls-key`).
    /// Together with a reverse proxy's `X-Forwarded-Proto: https` hop header
    /// it decides the session cookie's `Secure` attribute — see
    /// [`super::auth_password::cookie_secure`].
    pub tls_enabled: bool,
    /// Single-user password gate (P1): argon2 hash + in-memory sessions.
    /// `Arc` so the route state and the auth middleware's state clone share
    /// one session map — a plain `Mutex<PasswordAuth>` field would give each
    /// clone its own copy and sessions issued by handlers would be invisible
    /// to `require_token`.
    pub password_auth: Arc<Mutex<super::auth_password::PasswordAuth>>,
    /// Data dir for prefs, the password file and `web-imports.json`.
    pub data_dir: std::path::PathBuf,
    /// The shared command registry — the same table the Tauri shells use.
    /// `POST /api/invoke/{cmd}` dispatches through it for every non-AI
    /// command; AI keeps its bespoke handlers.
    pub registry: std::sync::Arc<k7s_core::core::commands::CommandRegistry>,
}

impl WebState {
    /// Build a fresh web state.
    ///
    /// `addr` is the bind address — used to set `is_loopback`, which controls
    /// whether `GET /api/web-token` is mounted (loopback only).
    pub fn new(data_dir: std::path::PathBuf, addr: std::net::SocketAddr) -> Self {
        let service = Arc::new(SessionCtx::new(data_dir.clone()));
        let web_token = Arc::new(super::auth::resolve_token(&data_dir));
        let is_loopback = addr.ip().is_loopback();
        let password_auth = Arc::new(Mutex::new(super::auth_password::PasswordAuth::load(
            &data_dir,
        )));
        let registry = std::sync::Arc::new(k7s_commands::registry::build_registry());

        Self {
            registry,
            service,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ai_runs: Arc::new(Mutex::new(HashMap::new())),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            web_token,
            is_loopback,
            tls_enabled: false,
            password_auth,
            data_dir,
        }
    }

    /// Mark the server as terminating TLS itself (`--tls-cert/--tls-key`).
    /// Fluent builder for the `k7s-web` binary, which knows the TLS options
    /// only after arg parsing — [`WebState::new`] defaults to `false`.
    pub fn with_tls_enabled(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        self
    }

    /// The connection a request should use: its login's own, else the shared one.
    pub fn session_for(&self, session: &SessionToken) -> Arc<SessionCtx> {
        let Some(token) = session.0.clone() else {
            return self.service.clone();
        };
        // Hold the lock across creation (sync and cheap) so two concurrent
        // first requests can't build two connections for one session.
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ctx) = map.get(&token) {
            return ctx.clone();
        }
        let ctx = Arc::new(SessionCtx::new(self.data_dir.clone()));
        map.insert(token, ctx.clone());
        drop(map);

        // Imported kubeconfigs live on disk; seed this connection from them.
        let manager = ctx.core.manager.clone();
        let dir = self.data_dir.clone();
        k7s_deps::tokio::spawn(async move {
            let n = super::web_imports::restore(&dir, &manager).await;
            if n > 0 {
                k7s_deps::tracing::info!("session restored {n} imported kubeconfig context(s)");
            }
        });
        ctx
    }

    /// Tear down a login's connection (logout).
    pub fn drop_session(&self, token: &str) {
        let ctx = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
        if let Some(ctx) = ctx {
            k7s_deps::tokio::spawn(async move { ctx.core.manager.reset().await });
        }
    }

    /// Drop connections whose login expired. Called on login so an idle-expired
    /// session can't pin its watchers forever.
    pub fn sweep_sessions(&self) {
        let expired = self
            .password_auth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget_expired();
        if expired.is_empty() {
            return;
        }
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        for token in expired {
            if let Some(ctx) = map.remove(&token) {
                k7s_deps::tokio::spawn(async move { ctx.core.manager.reset().await });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> WebState {
        let dir = std::env::temp_dir().join(format!(
            "k7s-web-session-test-{}",
            k7s_deps::uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        WebState::new(dir, "127.0.0.1:0".parse().unwrap())
    }

    #[k7s_deps::tokio::test]
    async fn logins_get_separate_connections() {
        let st = state();
        let a = st.session_for(&SessionToken(Some("a".into())));
        let b = st.session_for(&SessionToken(Some("b".into())));
        assert!(
            !Arc::ptr_eq(&a.core, &b.core),
            "two logins share one connection"
        );
        // Same login → same connection; no cookie → the shared service one.
        assert!(Arc::ptr_eq(
            &a.core,
            &st.session_for(&SessionToken(Some("a".into()))).core
        ));
        assert!(Arc::ptr_eq(
            &st.session_for(&SessionToken(None)).core,
            &st.service.core
        ));
    }

    #[k7s_deps::tokio::test]
    async fn logout_drops_the_connection() {
        let st = state();
        let before = st.session_for(&SessionToken(Some("gone".into())));
        st.drop_session("gone");
        let after = st.session_for(&SessionToken(Some("gone".into())));
        assert!(!Arc::ptr_eq(&before.core, &after.core));
    }
}

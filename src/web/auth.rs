//! Token-based authentication for the web shell.
//!
//! `k7s-web` exposes the full Kubernetes control surface over HTTP — apply,
//! delete, drain, exec into pods, read Secrets. Without a gate, any client
//! that can reach the port (same-host process, browser tab via CSRF) gets
//! full cluster control. This module supplies the gate: a bearer token that
//! every `/api/invoke/*` and `/hooks/*` request must carry.
//!
//! ## Where the token comes from
//!
//! 1. `K7S_WEB_TOKEN` environment variable, if set (operator-managed deployments).
//! 2. Otherwise a randomly generated 32-byte secret written to
//!    `<data_dir>/web-token` (mode 0600), reused across restarts. This lets
//!    the same-origin SPA fetch it once from `/api/web-token` (loopback only)
//!    and present it on every subsequent call — no operator config needed for
//!    the default `127.0.0.1` dev workflow, while a non-loopback bind refuses
//!    to publish the token and forces the operator to set `K7S_WEB_TOKEN`.
//!
//! The comparison is constant-time to avoid a timing side-channel.

use std::path::Path;

use axum::body::Body;
use axum::extract::State;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use k7s_deps::http::{Request, StatusCode};
use k7s_deps::serde_json::json;

use super::state::WebState;

/// File name (under `data_dir`) holding the auto-generated web token.
const TOKEN_FILE: &str = "web-token";

/// Resolve the auth token: env var wins, else a persisted random secret.
///
/// On loopback binds the secret is published via `GET /api/web-token` so the
/// same-origin SPA can pick it up without operator config. Non-loopback binds
/// must set `K7S_WEB_TOKEN` explicitly — a random secret the operator can't
/// read would be useless, and we refuse to publish it.
pub fn resolve_token(data_dir: &Path) -> String {
    if let Ok(t) = std::env::var("K7S_WEB_TOKEN") {
        if !t.trim().is_empty() {
            return t;
        }
    }
    // Otherwise load-or-create the persisted random token.
    let path = data_dir.join(TOKEN_FILE);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // Generate a fresh 32-byte secret. `OsRng` is the OS CSPRNG.
    use k7s_deps::base64::Engine;
    use k7s_deps::rand::Rng;
    let mut bytes = [0u8; 32];
    k7s_deps::rand::rng().fill_bytes(&mut bytes);
    let token = k7s_deps::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    if let Err(e) = std::fs::write(&path, &token) {
        k7s_deps::tracing::warn!("could not persist web token to {}: {e}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
    k7s_deps::tracing::info!(
        "generated web auth token (loopback clients fetch it via GET /api/web-token); \
         set K7S_WEB_TOKEN to use your own"
    );
    token
}

/// Constant-time byte comparison. Returns `true` iff equal.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length itself leaks, but that's unavoidable for a bearer token
        // check and not sensitive (token length is fixed by the generator).
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Axum middleware: require a valid `Authorization: Bearer <token>` on every
/// protected request. Public endpoints (health/status/events, and the
/// loopback-only token-publish route) are exempted by path.
pub async fn require_token(
    State(state): State<WebState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    // Public, side-effect-free endpoints — no auth required. `/api/auth/*`
    // are the password-gate endpoints themselves (status/setup/login/logout);
    // they can't require what they issue. Static assets bypass this layer
    // entirely (the `ServeDir`/embedded fallback is attached after it).
    //
    // `/api/events` and `/api/status` are deliberately NOT public: the SSE
    // stream fans out every event — including `shell-out:{id}` terminal
    // output — to whoever subscribes, and status leaks the active context
    // and API server address. The SPA's fetch-based subscriber sends the
    // bearer token, and cookie sessions cover EventSource clients.
    let is_public = matches!(path, "/api/health" | "/health")
        || (state.is_loopback && path == "/api/web-token")
        || path.starts_with("/api/auth/");
    if is_public {
        return next.run(req).await;
    }

    let expected = state.web_token.as_bytes();
    let provided = req
        .headers()
        .get(k7s_deps::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
                .unwrap_or(h)
                .trim()
        });

    let ok = match provided {
        Some(p) => constant_time_eq(p.as_bytes(), expected),
        None => false,
    };
    if ok {
        next.run(req).await
    } else if cookie_session(&req, &state).is_some() {
        // Session cookie fallback: password login gate (P1). Loopback without
        // a configured password keeps the original token-only behavior.
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "unauthorized: missing or invalid token" })),
        )
            .into_response()
    }
}

/// True when the request carries a live `k7s_session` cookie (sliding-renewal
/// check lives in [`super::auth_password::PasswordAuth::check_session`]).
fn cookie_session(req: &Request<Body>, state: &WebState) -> Option<()> {
    let raw = req
        .headers()
        .get(k7s_deps::http::header::COOKIE)?
        .to_str()
        .ok()?;
    let name = format!("{}=", super::auth_password::PasswordAuth::cookie_name());
    let token = raw
        .split(';')
        .map(str::trim)
        .find(|c| c.starts_with(&name))?
        .strip_prefix(&name)?;
    state
        .password_auth
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .check_session(token)
        .then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn resolve_token_round_trips_file() {
        let dir = std::env::temp_dir().join("k7s-web-token-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // First call generates + persists.
        let t1 = resolve_token(&dir);
        assert!(!t1.is_empty());
        // Second call reads the same value back.
        let t2 = resolve_token(&dir);
        assert_eq!(t1, t2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_token_env_wins() {
        let dir = std::env::temp_dir().join("k7s-web-token-env-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("K7S_WEB_TOKEN", "env-secret-xyz");
        let t = resolve_token(&dir);
        std::env::remove_var("K7S_WEB_TOKEN");
        assert_eq!(t, "env-secret-xyz");
        // File should NOT have been written (env wins, no persist).
        assert!(!dir.join(TOKEN_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

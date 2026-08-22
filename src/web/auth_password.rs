//! 单用户密码登录门(P1)。argon2 哈希落盘 `<data_dir>/web-password`,
//! 会话为内存 token → 过期时刻映射,cookie `k7s_session` 携带。
//! 与既有 Bearer token 并存:loopback 模式沿用 token 免登,
//! 非 loopback 且已设密码时要求会话。

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use k7s_deps::rand::Rng;
use k7s_deps::serde_json::json;

use super::state::WebState;

const PASSWORD_FILE: &str = "web-password";
const SESSION_COOKIE: &str = "k7s_session";
const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

pub struct PasswordAuth {
    hash: Option<String>,
    sessions: Mutex<HashMap<String, Instant>>,
}

impl PasswordAuth {
    /// Load the persisted argon2 PHC hash from `<data_dir>/web-password`, if
    /// one exists. Missing file / read error / empty file → unconfigured.
    pub fn load(data_dir: &Path) -> Self {
        let hash = std::fs::read_to_string(data_dir.join(PASSWORD_FILE))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            hash,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn configured(&self) -> bool {
        self.hash.is_some()
    }

    /// Set the password (memory only). Call [`PasswordAuth::persist`] right
    /// after to write the hash to disk; the setup handler does both under
    /// one lock.
    pub fn setup(&mut self, password: &str) -> Result<(), &'static str> {
        if self.configured() {
            return Err("password already configured");
        }
        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| "hash failed")?
            .to_string();
        self.hash = Some(phc);
        Ok(())
    }

    /// Write the current hash to `<data_dir>/web-password` with mode 0600
    /// (unix). No-op when unconfigured.
    pub fn persist(&self, data_dir: &Path) -> std::io::Result<()> {
        if let Some(h) = &self.hash {
            let path = data_dir.join(PASSWORD_FILE);
            std::fs::write(&path, h)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut p = std::fs::metadata(&path)?.permissions();
                p.set_mode(0o600);
                std::fs::set_permissions(&path, p)?;
            }
        }
        Ok(())
    }

    /// Constant-time verify (argon2 does the comparison internally).
    pub fn verify(&self, password: &str) -> bool {
        let Some(h) = &self.hash else { return false };
        let Ok(parsed) = PasswordHash::new(h) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    fn issue_session(&self) -> String {
        use k7s_deps::base64::Engine;
        let mut b = [0u8; 32];
        k7s_deps::rand::rng().fill_bytes(&mut b);
        let token = k7s_deps::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        if let Ok(mut s) = self.sessions.lock() {
            s.insert(token.clone(), Instant::now() + SESSION_TTL);
        }
        token
    }

    /// 校验 cookie 里的会话 token(滑动续期)。
    pub fn check_session(&self, token: &str) -> bool {
        let Ok(mut s) = self.sessions.lock() else {
            return false;
        };
        match s.get(token) {
            Some(exp) if *exp > Instant::now() => {
                s.insert(token.to_string(), Instant::now() + SESSION_TTL);
                true
            }
            _ => false,
        }
    }

    pub fn drop_session(&self, token: &str) {
        if let Ok(mut s) = self.sessions.lock() {
            s.remove(token);
        }
    }

    pub fn cookie_of(token: &str) -> String {
        format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            SESSION_TTL.as_secs()
        )
    }

    pub fn cookie_name() -> &'static str {
        SESSION_COOKIE
    }
}

fn cookie_token(req: &axum::http::Request<axum::body::Body>) -> Option<String> {
    let raw = req
        .headers()
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    raw.split(';')
        .map(|c| c.trim())
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .map(|t| t.to_string())
}

// ---- handlers ----

/// Session-aware: `authRequired` is only true on non-loopback binds *without* a
/// valid `k7s_session` cookie. The matrix: loopback → always false (the token
/// flow is unchanged); non-loopback fresh install → true + `configured: false`
/// (the SPA shows the setup form); non-loopback configured, no/expired cookie →
/// true (login form); valid cookie → false (straight into the app). Reporting
/// `configured` separately lets the SPA pick setup-vs-login while this stays
/// the single gate bit.
pub async fn auth_status(
    State(state): State<WebState>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let pa = state
        .password_auth
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let authenticated = cookie_token(&req)
        .map(|t| pa.check_session(&t))
        .unwrap_or(false);
    Json(json!({
        "authRequired": !state.is_loopback && !authenticated,
        "configured": pa.configured(),
    }))
    .into_response()
}

pub async fn auth_setup(
    State(state): State<WebState>,
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> Response {
    let Some(pwd) = body["password"].as_str() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "password required"})),
        )
            .into_response();
    };
    if pwd.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "password must be >= 8 chars"})),
        )
            .into_response();
    }
    let mut guard = state
        .password_auth
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Err(e) = guard.setup(pwd) {
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "error": e}))).into_response();
    }
    if let Err(e) = guard.persist(&state.data_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
            .into_response();
    }
    let token = guard.issue_session();
    drop(guard);
    (
        [(SET_COOKIE, PasswordAuth::cookie_of(&token))],
        Json(json!({"ok": true})),
    )
        .into_response()
}

pub async fn auth_login(
    State(state): State<WebState>,
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> Response {
    let Some(pwd) = body["password"].as_str() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "password required"})),
        )
            .into_response();
    };
    let guard = state
        .password_auth
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !guard.verify(pwd) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "wrong password"})),
        )
            .into_response();
    }
    let token = guard.issue_session();
    drop(guard);
    (
        [(SET_COOKIE, PasswordAuth::cookie_of(&token))],
        Json(json!({"ok": true})),
    )
        .into_response()
}

pub async fn auth_logout(
    State(state): State<WebState>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    if let Some(t) = cookie_token(&req) {
        state
            .password_auth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drop_session(&t);
    }
    (
        [(
            SET_COOKIE,
            format!(
                "{}=; Path=/; HttpOnly; Max-Age=0",
                PasswordAuth::cookie_name()
            ),
        )],
        Json(json!({"ok": true})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_verify_roundtrip() {
        let dir = std::env::temp_dir().join("k7s-pwd-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut pa = PasswordAuth {
            hash: None,
            sessions: Mutex::new(HashMap::new()),
        };
        assert!(!pa.configured());
        pa.setup("correct-horse-battery").unwrap();
        assert!(pa.configured());
        assert!(pa.verify("correct-horse-battery"));
        assert!(!pa.verify("wrong"));
        pa.persist(&dir).unwrap();
        let loaded = PasswordAuth::load(&dir);
        assert!(loaded.verify("correct-horse-battery"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_issue_check_drop() {
        let pa = PasswordAuth {
            hash: None,
            sessions: Mutex::new(HashMap::new()),
        };
        let t = pa.issue_session();
        assert!(pa.check_session(&t));
        pa.drop_session(&t);
        assert!(!pa.check_session(&t));
    }

    /// Drive the assembled router: `/api/auth/*` must be reachable without a
    /// bearer token, static files must load pre-login (the login page needs
    /// them), and a session cookie must unlock otherwise-protected routes.
    #[cfg(test)]
    mod router_tests {
        use crate::web::{server, state::WebState};
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use k7s_deps::serde_json::json;
        use tower::ServiceExt;

        fn test_state(tag: &str) -> WebState {
            test_state_at(tag, "127.0.0.1:7180")
        }

        /// Same as [`test_state`], but with an arbitrary bind address — the
        /// non-loopback status tests need `is_loopback: false`.
        fn test_state_at(tag: &str, addr: &str) -> WebState {
            let dir = std::env::temp_dir().join(format!("k7s-auth-router-{tag}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let addr: std::net::SocketAddr = addr.parse().unwrap();
            WebState::new(dir, addr)
        }

        fn static_dir(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!("k7s-auth-static-{tag}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("index.html"), "<html>k7s</html>").unwrap();
            dir
        }

        fn post_json(uri: &str, cookie: Option<&str>, body: String) -> Request<Body> {
            let mut b = Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(c) = cookie {
                b = b.header(header::COOKIE, c);
            }
            b.body(Body::from(body)).unwrap()
        }

        fn set_cookie(resp: &axum::response::Response) -> String {
            resp.headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        }

        /// GET /api/auth/status (optionally with a cookie) → parsed body.
        async fn status(app: &axum::Router, cookie: Option<&str>) -> k7s_deps::serde_json::Value {
            let mut b = Request::builder().uri("/api/auth/status");
            if let Some(c) = cookie {
                b = b.header(header::COOKIE, c);
            }
            let resp = app
                .clone()
                .oneshot(b.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            k7s_deps::serde_json::from_slice(&bytes).unwrap()
        }

        #[tokio::test]
        async fn auth_flow_over_http() {
            let state = test_state("flow");
            let app = server::router(
                state,
                Some(static_dir("flow")),
                false,
                "127.0.0.1:7180".parse().unwrap(),
            );

            // Pre-login: status + static assets are public (login page loads).
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/auth/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            // Loopback never gates, even configured and cookie-less — the
            // published-token flow is unchanged.
            let st = status(&app, None).await;
            assert_eq!(
                st["authRequired"],
                json!(false),
                "loopback must never require auth"
            );
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "static / must be reachable pre-login"
            );

            // Setup: too-short password rejected, then accepted with a cookie.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/setup",
                    None,
                    json!({"password": "short"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/setup",
                    None,
                    json!({"password": "correct-horse-battery"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let cookie = set_cookie(&resp);
            assert!(cookie.starts_with("k7s_session="), "got: {cookie}");
            assert!(cookie.contains("HttpOnly"));
            assert!(cookie.contains("SameSite=Strict"));
            assert!(cookie.contains("Path=/"));
            assert!(
                cookie.contains("Max-Age=604800"),
                "7-day sliding TTL, got: {cookie}"
            );

            // Second setup is refused (409) — single-user, set once.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/setup",
                    None,
                    json!({"password": "another-password"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CONFLICT);

            // Login: wrong password 401s, correct one issues a fresh cookie.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/login",
                    None,
                    json!({"password": "nope"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/login",
                    None,
                    json!({"password": "correct-horse-battery"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let login_cookie = set_cookie(&resp);
            assert!(login_cookie.starts_with("k7s_session="));
            let cookie_pair = login_cookie.split(';').next().unwrap().to_string();

            // The session cookie unlocks a protected route (no bearer token).
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/invoke/load_prefs",
                    Some(&cookie_pair),
                    json!({}).to_string(),
                ))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "valid session must pass the auth gate"
            );

            // Logout clears the session; the same cookie no longer works.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/logout",
                    Some(&cookie_pair),
                    String::new(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let clear = set_cookie(&resp);
            assert!(
                clear.starts_with("k7s_session=;"),
                "logout must clear the cookie, got: {clear}"
            );
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/invoke/load_prefs",
                    Some(&cookie_pair),
                    json!({}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "logged-out session must be rejected"
            );
        }

        #[tokio::test]
        async fn forged_cookie_is_rejected() {
            let state = test_state("forged");
            let app = server::router(
                state,
                Some(static_dir("forged")),
                false,
                "127.0.0.1:7180".parse().unwrap(),
            );
            let resp = app
                .oneshot(post_json(
                    "/api/invoke/load_prefs",
                    Some("k7s_session=forged-token-value"),
                    json!({}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// The full auth-status matrix on a non-loopback bind: unconfigured →
        /// authRequired (setup form), valid session → pass, logout → gated
        /// again. This is the contract the SPA's LoginGate polls; getting it
        /// wrong is what caused the infinite login loop.
        #[tokio::test]
        async fn auth_status_honors_session_cookie_non_loopback() {
            let addr: std::net::SocketAddr = "10.10.0.1:7180".parse().unwrap();
            let state = test_state_at("status-nl", "10.10.0.1:7180");
            assert!(!state.is_loopback, "test premise: non-loopback bind");
            let app = server::router(state, Some(static_dir("status-nl")), false, addr);

            // (a) Fresh install, no cookie: gated, and `configured: false` so
            // the SPA shows the *setup* form (not login).
            let st = status(&app, None).await;
            assert_eq!(st["authRequired"], json!(true));
            assert_eq!(st["configured"], json!(false));

            // (b) Setup issues a session; carrying the Set-Cookie pair clears
            // the gate while `configured` flips to true.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/setup",
                    None,
                    json!({"password": "correct-horse-battery"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let pair = set_cookie(&resp).split(';').next().unwrap().to_string();
            let st = status(&app, Some(&pair)).await;
            assert_eq!(
                st["authRequired"],
                json!(false),
                "valid session must clear the gate"
            );
            assert_eq!(st["configured"], json!(true));

            // (c) Logout drops the session server-side; the same cookie (the
            // one the browser would still hold until the clearing Set-Cookie
            // lands) re-gates — configured stays true → login form.
            let resp = app
                .clone()
                .oneshot(post_json("/api/auth/logout", Some(&pair), String::new()))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let st = status(&app, Some(&pair)).await;
            assert_eq!(
                st["authRequired"],
                json!(true),
                "dropped session must re-gate"
            );
            assert_eq!(st["configured"], json!(true));
        }

        /// `apply_yaml_bundle` must be bridged through the web shell (the P2
        /// wizard's 应用 step). Before the bridge this hit the catch-all and
        /// returned 501 "this command isn't bridged through the web shell yet".
        /// With no cluster connected the handler must answer an ordinary
        /// AppError instead — proving the route exists and delegates.
        #[tokio::test]
        async fn apply_yaml_bundle_is_bridged() {
            let state = test_state("apply-bundle");
            let app = server::router(
                state,
                Some(static_dir("apply-bundle")),
                false,
                "127.0.0.1:7180".parse().unwrap(),
            );
            // Authenticate so require_token lets the invoke through.
            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/auth/setup",
                    None,
                    json!({"password": "correct-horse-battery"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let cookie = set_cookie(&resp);

            let resp = app
                .clone()
                .oneshot(post_json(
                    "/api/invoke/apply_yaml_bundle",
                    Some(&cookie),
                    json!({"yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"})
                        .to_string(),
                ))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::NOT_IMPLEMENTED,
                "apply_yaml_bundle must be bridged, not 501"
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: k7s_deps::serde_json::Value =
                k7s_deps::serde_json::from_slice(&bytes).unwrap();
            assert!(
                body.get("error").is_some(),
                "no cluster connected — expect an AppError body, got: {body}"
            );
            assert_ne!(
                body["error"],
                json!("this command isn't bridged through the web shell yet")
            );
        }
    }
}

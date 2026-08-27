//! axum server for the web shell.
//!
//! One binary, two modes, picked at startup:
//!
//! - **`--static <DIR>`** (the "server" mode): serves the built React app
//!   from `<DIR>` *and* the API on the same port. Bind to `0.0.0.0:8080`,
//!   hand the binary a `./dist` directory, and a single process is your
//!   cluster UI. No node, no vite, no reverse proxy required.
//!
//! - **no `--static`** (the "dev API" mode): serves only the API. Pair it
//!   with `npm run dev` (vite dev server, port 1420) which has its own
//!   `proxy` entry forwarding `/api/*` here. This is the workflow
//!   `dev/web.mjs` automates.
//!
//! Routes use the `/api/*` prefix unconditionally. That way the front-end's
//! `transport.ts` writes the same path in dev and prod — only the routing
//! (Vite proxy vs. nothing) differs.
//!
//! Every interesting operation goes through one of three paths:
//! - `POST /api/invoke/{cmd}` for one-shot commands.
//! - `GET /api/events` for the SSE stream of live data.
//! - `GET /health` for the dev script's readiness probe.
//! - `POST/GET/DELETE /mcp` for the Streamable HTTP MCP transport — the
//!   same tools the stdio `k7s-mcp` binary exposes, but reachable by
//!   network so AI clients on a different host can connect.
//!
//! Everything except `/health` and `/api/health` sits behind the
//! `require_token` middleware (bearer token or password session cookie) —
//! including `/mcp` and `/api/events`, both of which expose cluster data
//! and shell I/O.

use axum::{
    routing::{get, post},
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use super::ai_handlers;
use super::auth_password;
use super::handlers;
use super::hook_handlers;
use super::sse::events_handler;
use super::state::WebState;
use crate::mcp::K7sMcpServer;

/// The built React app embedded at compile time. Only available when the
/// `web` feature is active and `rust-embed` is linked.
#[derive(rust_embed::Embed)]
#[folder = "./dist"]
pub struct FrontendAssets;

/// Axum fallback handler that serves embedded frontend assets.
/// For any request path, tries to find a matching file in the embedded
/// dist/; if not found, serves index.html for SPA client-side routing.
async fn embedded_fallback(req: axum::extract::Request) -> impl axum::response::IntoResponse {
    use axum::response::Response;
    use k7s_deps::http::{header, StatusCode};

    let path = req.uri().path().trim_start_matches('/').to_string();
    let path = if path.is_empty() {
        "index.html".to_string()
    } else {
        path
    };

    match FrontendAssets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .body(axum::body::Body::from(content.data.to_vec()))
                .expect("Response::builder with hardcoded status and body is infallible")
        }
        None => {
            // SPA fallback: serve index.html for any unmatched path
            match FrontendAssets::get("index.html") {
                Some(content) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(axum::body::Body::from(content.data.to_vec()))
                    .expect("Response::builder with hardcoded status and body is infallible"),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(axum::body::Body::empty())
                    .expect("Response::builder with hardcoded status and body is infallible"),
            }
        }
    }
}

/// Build the API router (no static files). Exposed so tests can drive it
/// with `tower::ServiceExt::oneshot` without needing a built `dist/`.
pub fn api_router(state: WebState) -> Router {
    // The MCP service factory: a *fresh* `K7sMcpServer` per session, so
    // each Streamable HTTP client gets its own `ClientManager` (and its
    // own connection state, port-forwards, shells). The factory closure
    // must be cheap — see the safety note on `StreamableHttpService` in
    // the rmcp docs.
    let mcp_service: StreamableHttpService<K7sMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            || {
                // Same wiring the stdio `k7s-mcp` binary uses, just inside
                // an HTTP request. The server carries its own
                // `Arc<CoreState>` (and thus its own `Arc<ClientManager>`)
                // — port-forwards and shells started by one Streamable
                // HTTP client are visible only to that client.
                //
                // The data dir is a per-session scratch keyed by a fresh
                // uuid — the factory runs once per Streamable HTTP session
                // (stateful mode below), and this path used to be keyed by
                // pid, which made every session in the process silently
                // share one directory. Nothing writes to it today (the MCP
                // server has no prefs UI), but a future per-session cache
                // would land here and must not collide across sessions.
                let data_dir = std::env::temp_dir().join(format!(
                    "k7s-mcp-session-{}",
                    k7s_deps::uuid::Uuid::new_v4()
                ));
                Ok(K7sMcpServer::new(data_dir))
            },
            Arc::new(LocalSessionManager::default()),
            // Stateful mode: the first `initialize` response carries an
            // `Mcp-Session-Id` header; subsequent requests echo it back
            // and the factory-built server (with its `Arc<CoreState>`)
            // stays alive for the whole session. Without stateful mode
            // every request is a fresh server — fine for read-only tools
            // but it makes `connect → list_resources` impossible to chain
            // in a single client turn.
            //
            // SSE keep-alive keeps idle connections from being torn down
            // by intermediate proxies while a long-running tool (e.g.
            // a streaming log tail) is mid-flight.
            {
                let mut config = StreamableHttpServerConfig::default();
                config.sse_keep_alive = Some(std::time::Duration::from_secs(15));
                config.legacy_session_mode = true;
                config
            },
        );

    Router::new()
        .route("/api/invoke/load_prefs", post(handlers::load_prefs))
        .route("/api/invoke/save_prefs", post(handlers::save_prefs))
        // Browser equivalent of the Tauri file-picker dialog: the user
        // picks a kubeconfig file in the browser, the front-end reads its
        // bytes and POSTs the contents here. See HttpProvider.importKubeconfig.
        .route(
            "/api/invoke/import_kubeconfig_content",
            post(handlers::import_kubeconfig_content),
        )
        // Everything else (mutations, log streaming, interactive shells,
        // EndpointSlices, …) goes through the registry catch-all below —
        // same business logic as the Tauri shell, same wire names.
        // SBOM endpoints (REST-style).
        .route("/api/sbom/image", post(handlers::sbom_generate_image))
        .route("/api/sbom/history", get(handlers::sbom_list_history))
        .route("/api/sbom/{id}", get(handlers::sbom_get))
        // SBOM invoke bridges — the frontend calls POST /api/invoke/sbom_*.
        // AI webhook hooks — external systems (monitoring, CI/CD) can trigger
        // the AI agent via these endpoints. Authenticated via Bearer token.
        .route("/hooks/wake", post(hook_handlers::hook_wake))
        .route("/hooks/agent", post(hook_handlers::hook_agent))
        .route("/hooks/event", post(hook_handlers::hook_event))
        // AI assistant endpoints.
        .route(
            "/api/invoke/ai_get_config",
            post(ai_handlers::ai_get_config_handler),
        )
        .route(
            "/api/invoke/ai_get_context",
            post(ai_handlers::ai_get_context_handler),
        )
        .route(
            "/api/invoke/ai_save_config",
            post(ai_handlers::ai_save_config_handler),
        )
        .route("/api/invoke/ai_chat", post(ai_handlers::ai_chat_handler))
        .route(
            "/api/invoke/ai_cancel",
            post(ai_handlers::ai_cancel_handler),
        )
        .route(
            "/api/invoke/ai_poll_events",
            post(ai_handlers::ai_poll_events_handler),
        )
        .route(
            "/api/invoke/ai_approve_tool_call",
            post(ai_handlers::ai_approve_tool_call_handler),
        )
        .route(
            "/api/invoke/ai_test_connection",
            post(ai_handlers::ai_test_connection_handler),
        )
        .route(
            "/api/invoke/ai_save_api_key",
            post(ai_handlers::ai_save_api_key_handler),
        )
        .route(
            "/api/invoke/ai_list_skills",
            post(ai_handlers::ai_list_skills_handler),
        )
        .route(
            "/api/invoke/ai_memory_list",
            post(ai_handlers::ai_memory_list_handler),
        )
        .route(
            "/api/invoke/ai_memory_search",
            post(ai_handlers::ai_memory_search_handler),
        )
        .route(
            "/api/invoke/ai_memory_add",
            post(ai_handlers::ai_memory_add_handler),
        )
        .route(
            "/api/invoke/ai_cron_list",
            post(ai_handlers::ai_cron_list_handler),
        )
        .route(
            "/api/invoke/ai_cron_presets",
            post(ai_handlers::ai_cron_presets_handler),
        )
        .route(
            "/api/invoke/ai_evolution_strategies",
            post(ai_handlers::ai_evolution_strategies_handler),
        )
        .route(
            "/api/invoke/ai_memory_preferences",
            post(ai_handlers::ai_memory_preferences_handler),
        )
        .route(
            "/api/invoke/ai_memory_delete",
            post(ai_handlers::ai_memory_delete_handler),
        )
        .route(
            "/api/invoke/ai_memory_clear",
            post(ai_handlers::ai_memory_clear_handler),
        )
        .route(
            "/api/invoke/ai_memory_search_vault",
            post(ai_handlers::ai_memory_search_vault_handler),
        )
        .route(
            "/api/invoke/ai_cron_add",
            post(ai_handlers::ai_cron_add_handler),
        )
        .route(
            "/api/invoke/ai_cron_toggle",
            post(ai_handlers::ai_cron_toggle_handler),
        )
        .route(
            "/api/invoke/ai_cron_delete",
            post(ai_handlers::ai_cron_delete_handler),
        )
        // Stubs for everything else.
        .route("/api/invoke/{cmd}", post(handlers::invoke_registry))
        // Connection banner polling. `GET` (no body) so a misbehaving client
        // can't accidentally trigger a state change by retrying.
        .route("/api/status", get(handlers::status))
        .route("/api/events", get(events_handler))
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/version", get(handlers::version))
        .route("/health", get(|| async { "ok" }))
        // Loopback-only: publish the auth token so the same-origin SPA can
        // self-serve it. The handler double-checks `is_loopback` and 404s
        // if the router is somehow reached on a non-loopback bind.
        .route("/api/web-token", get(handlers::web_token))
        // Single-user password gate (P1): status/setup/login/logout. These
        // are exempted from the bearer-token middleware inside
        // `require_token` (`/api/auth/*` prefix) — they ARE the auth.
        // Sessions are HttpOnly cookies; see `auth_password`.
        .route("/api/auth/status", get(auth_password::auth_status))
        .route("/api/auth/setup", post(auth_password::auth_setup))
        .route("/api/auth/login", post(auth_password::auth_login))
        .route("/api/auth/logout", post(auth_password::auth_logout))
        // The Streamable HTTP MCP transport. Same tools the stdio
        // `k7s-mcp` binary exposes, reachable by URL — point any modern
        // MCP client at `http://<host>:<port>/mcp`. Mounted as a service
        // (not a route) because the transport handles GET / POST / DELETE
        // internally per the MCP Streamable HTTP spec.
        //
        // Merged BEFORE `.with_state`/`.layer` below on purpose: axum's
        // `Router::layer` only covers routes registered before the call, so
        // a post-layer merge would leave `/mcp` completely unauthenticated —
        // and it exposes exec, node shells and full cluster write access.
        // MCP clients must send `Authorization: Bearer <K7S_WEB_TOKEN>`
        // (a live password session cookie also works).
        // See `README.md` § "MCP server → Wire it into …" for client configs.
        .merge(Router::new().nest_service("/mcp", mcp_service.clone()))
        .with_state(state.clone())
        // Auth gate: every `/api/invoke/*`, `/mcp`, `/api/status`,
        // `/api/events` and `/hooks/*` request must carry
        // `Authorization: Bearer <token>` (or a live session cookie). Public
        // endpoints (health, and loopback `/api/web-token`) are exempted
        // inside the middleware by path. Applied after routes are registered
        // so it sees the resolved state.
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::auth::require_token,
        ))
}

/// Build the full router. In server mode, layer the static-file service on
/// top: any path the API doesn't match falls through to `static_dir`, with
/// `index.html` as the catch-all so the front-end's client-side router can
/// take over.
pub fn router(
    state: WebState,
    static_dir: Option<PathBuf>,
    use_embedded: bool,
    addr: SocketAddr,
    https: bool,
) -> Router {
    let cors = cors_layer(addr, https);

    let api = api_router(state);
    let mut app = api.layer(TraceLayer::new_for_http()).layer(cors);

    if let Some(dir) = static_dir {
        // `ServeDir` looks up files inside `dir` and falls through to the
        // `not_found` service for misses — we set that to `index.html` so
        // the front-end's router can claim the URL. This makes the server
        // mode feel exactly like a real SPA host.
        let serve_dir =
            ServeDir::new(&dir).not_found_service(ServeFile::new(dir.join("index.html")));
        // Merge: the API routes are tried first (their paths are
        // more specific), and any unmatched path falls back to `serve_dir`.
        app = app.fallback_service(serve_dir);
    } else if use_embedded {
        app = app.fallback(embedded_fallback);
    }

    app
}

/// Build the CORS layer. Although `/api/invoke/*` now requires a bearer
/// token, an open `allow_origin(Any)` still lets any web page attempt
/// cluster-control requests against a victim's k7s-web (and a leaked/token-
/// readable page would succeed). Instead we allow only:
/// - the server's own origin (prod: same-origin SPA),
/// - the Vite dev origin (`http://localhost:1420`), and
/// - any comma-separated origins in `K7S_ALLOWED_ORIGINS`.
///
/// Methods/headers are narrowed to what the API actually uses. If you need a
/// browser client on another origin, set `K7S_ALLOWED_ORIGINS=https://app.example.com`.
///
/// `https` picks the scheme of the same-origin entry so it matches what the
/// browser actually sees when `--tls-cert/--tls-key` terminate TLS here.
fn cors_layer(addr: SocketAddr, https: bool) -> CorsLayer {
    use k7s_deps::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::AllowOrigin;

    let scheme = if https { "https" } else { "http" };
    let mut origins: Vec<HeaderValue> = vec![
        // Same-origin prod (the SPA is served from this same addr).
        HeaderValue::from_str(&format!("{scheme}://{addr}")).expect("valid origin"),
        // Vite dev server (proxies /api/* here).
        HeaderValue::from_static("http://localhost:1420"),
    ];
    // Extra origins via env (comma-separated), e.g. for a separate dashboard host.
    if let Ok(extra) = std::env::var("K7S_ALLOWED_ORIGINS") {
        for raw in extra.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            match HeaderValue::from_str(trimmed) {
                Ok(v) => origins.push(v),
                Err(e) => {
                    k7s_deps::tracing::warn!(
                        "ignoring invalid K7S_ALLOWED_ORIGINS entry '{trimmed}': {e}"
                    )
                }
            }
        }
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
        ])
}

/// Build a TLS acceptor from a PEM certificate chain + private key, for
/// first-party HTTPS (`k7s-web --tls-cert/--tls-key`).
///
/// Parse failures come back as `io::Error` of kind `InvalidData` so the
/// binary can fail fast with the offending path in the message.
pub fn tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> std::io::Result<k7s_deps::tokio_rustls::TlsAcceptor> {
    use k7s_deps::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{BufReader, ErrorKind};

    fn bad(ctx: String) -> std::io::Error {
        std::io::Error::new(ErrorKind::InvalidData, ctx)
    }

    let certs: Vec<CertificateDer<'static>> =
        k7s_deps::rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_path)?))
            .collect::<Result<_, _>>()
            .map_err(|e| bad(format!("{}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(bad(format!(
            "{}: no PEM certificates found",
            cert_path.display()
        )));
    }
    let key: PrivateKeyDer<'static> =
        k7s_deps::rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key_path)?))
            .map_err(|e| bad(format!("{}: {e}", key_path.display())))?
            .ok_or_else(|| bad(format!("{}: no private key found", key_path.display())))?;

    // No client-cert auth (the bearer/password gates handle identity) and a
    // single cert+key pair — the standard small-operator setup.
    let config = k7s_deps::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| bad(format!("cert/key unusable together: {e}")))?;
    Ok(k7s_deps::tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// A bound TCP listener that upgrades every accepted connection to TLS, so
/// `axum::serve` can drive HTTPS over it. Implementing axum's `Listener`
/// trait (rather than hand-rolling accept loops with hyper) keeps graceful
/// shutdown, connection limits and error handling identical to the plain
/// HTTP path.
struct TlsListener {
    tcp: k7s_deps::tokio::net::TcpListener,
    acceptor: k7s_deps::tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = k7s_deps::tokio_rustls::server::TlsStream<k7s_deps::tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // Mirror axum's TcpListener impl: transient errors are logged and
        // retried instead of killing the server — one client speaking
        // garbage (or a port scanner) must not take the listener down.
        loop {
            match self.tcp.accept().await {
                Ok((stream, addr)) => match self.acceptor.accept(stream).await {
                    Ok(tls) => return (tls, addr),
                    Err(e) => {
                        k7s_deps::tracing::warn!("TLS handshake with {addr} failed: {e}");
                    }
                },
                Err(e) => {
                    k7s_deps::tracing::error!("accept failed: {e}");
                    k7s_deps::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Serve on an already-bound listener until the process is asked to stop.
///
/// The listener is handed in (not bound here) so the binary's port-picking
/// can probe with `std::net::TcpListener` and then hand the *live* socket
/// over — binding twice would re-open the race where another process grabs
/// the port between probe and serve. `tls` wraps the listener in a
/// `TlsAcceptor` for HTTPS; `None` serves plain HTTP.
pub async fn serve(
    listener: k7s_deps::tokio::net::TcpListener,
    state: WebState,
    static_dir: Option<PathBuf>,
    use_embedded: bool,
    tls: Option<k7s_deps::tokio_rustls::TlsAcceptor>,
) -> std::io::Result<()> {
    let addr = listener.local_addr()?;
    let mode = if static_dir.is_some() {
        "server"
    } else if use_embedded {
        "embedded"
    } else {
        "dev-api"
    };
    let scheme = if tls.is_some() { "https" } else { "http" };
    k7s_deps::tracing::info!("k7s-web ({mode}) listening on {scheme}://{addr} (MCP: /mcp)");

    // k7s-web exposes the full Kubernetes control surface (apply/delete/drain/
    // exec, plaintext Secret reads). Every `/api/invoke/*` and `/hooks/*`
    // request now requires a bearer token. On loopback the token is auto-
    // generated and published at `GET /api/web-token` for the same-origin SPA;
    // on non-loopback the operator MUST set `K7S_WEB_TOKEN`, and we warn loudly
    // because a network-reachable cluster control surface is high-risk.
    if !addr.ip().is_loopback() {
        if std::env::var("K7S_WEB_TOKEN")
            .map(|t| t.trim().is_empty())
            .unwrap_or(true)
        {
            k7s_deps::tracing::warn!(
                "⚠️  k7s-web is bound to {addr} (non-loopback) and K7S_WEB_TOKEN is not set. \
                 A random token was generated and written to the data dir, but on a \
                 non-loopback bind you cannot read it via /api/web-token (that route is \
                 loopback-only). Set K7S_WEB_TOKEN explicitly so your clients know it."
            );
        }
        if tls.is_none() {
            k7s_deps::tracing::warn!(
                "⚠️  k7s-web on {addr} is network-reachable over plain HTTP. Password \
                 logins will travel in the clear — pass --tls-cert/--tls-key or put the \
                 server behind a TLS-terminating reverse proxy."
            );
        } else {
            k7s_deps::tracing::warn!(
                "⚠️  k7s-web on {addr} is network-reachable. Any client that can reach this \
                 port AND has the token has full cluster control. Prefer binding to 127.0.0.1 \
                 or sitting behind an authenticating reverse proxy."
            );
        }
    }

    let app = router(state, static_dir, use_embedded, addr, tls.is_some());
    match tls {
        Some(acceptor) => {
            axum::serve(
                TlsListener {
                    tcp: listener,
                    acceptor,
                },
                app,
            )
            .await
        }
        None => axum::serve(listener, app).await,
    }
}

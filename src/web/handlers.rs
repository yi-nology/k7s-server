//! Core HTTP handlers — connection management, preferences, and helpers.
//!
//! Contains the cluster lifecycle commands (`list_contexts`, `connect`,
//! `status`, `import_kubeconfig_content`), preference I/O, the SBOM REST
//! endpoints, the loopback `web_token` publisher, the registry-backed
//! `invoke_registry` catch-all, and the shared `core_client` helper that
//! every handler module uses.
//!
//! Resource mutation and shell handlers live in their own modules
//! (`resource_handlers`, `shell_handlers`); AI assistant handlers in
//! `ai_handlers`; webhook hooks in `hook_handlers`.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use k7s_deps::kube::config::Kubeconfig;
use std::sync::Arc;

use k7s_core::core::prefs::{self, Prefs};
use k7s_core::core::shell_common;
use k7s_core::core::CoreState;
use k7s_core::error::{AppError, AppResult};
use k7s_core::kube::{
    client::{self, ContextInfo},
    manager::ImportedContext,
};

use super::state::WebState;
use super::types::*;

// ---------------------------------------------------------------------------
// list_contexts
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// default_kubeconfig_path
// ---------------------------------------------------------------------------

/// `POST /invoke/default_kubeconfig_path` — no body.
pub async fn default_kubeconfig_path() -> axum::response::Response {
    respond(Ok(client::default_kubeconfig_path()))
}

// ---------------------------------------------------------------------------
// status — what the connection banner reads on every poll.
// ---------------------------------------------------------------------------

pub async fn status(State(state): State<WebState>) -> axum::response::Response {
    let info = state.core.manager.connection_info().await;
    // `connected` is the *intersection* of "client is live" and "info is
    // populated". Both halves are set/cleared atomically with the same lock
    // in `set_connected` / `reset`, so in practice they're in lockstep —
    // but the intersection makes the invariant explicit: a half-state
    // (e.g. client leaked through `reset` due to a future refactor) would
    // surface as `connected: false` here rather than a phantom banner.
    let client_alive = state.core.manager.client().await.is_some();
    let dto = StatusDto {
        connected: client_alive && info.is_some(),
        context: info.as_ref().map(|i| i.context.clone()),
        server: info.as_ref().map(|i| i.server.clone()),
        version: info.as_ref().map(|i| i.version.clone()),
        watcher_count: if client_alive {
            // Reuse the read lock the client check just held. Cheap and
            // avoids a second write-side acquire.
            state.core.manager.watcher_count().await
        } else {
            0
        },
    };
    respond(Ok(dto))
}

// ---------------------------------------------------------------------------
// load_prefs / save_prefs
// ---------------------------------------------------------------------------

/// `POST /invoke/load_prefs` — read the prefs file under `state.core.data_dir`.
pub async fn load_prefs(State(state): State<WebState>) -> axum::response::Response {
    let path = state.core.data_dir.join("prefs.json");
    let text = std::fs::read_to_string(&path).ok();
    let prefs: Option<Prefs> = text.and_then(|t| k7s_deps::serde_json::from_str(&t).ok());
    respond(Ok(prefs))
}

/// `POST /invoke/save_prefs` — write the prefs file under `state.core.data_dir`.
pub async fn save_prefs(
    State(state): State<WebState>,
    Json(args): Json<SavePrefsArgs>,
) -> axum::response::Response {
    respond(prefs::save_prefs(&state.core.data_dir, &args.prefs))
}

// ---------------------------------------------------------------------------
// import_kubeconfig_content — browser equivalent of the Tauri file dialog.
// ---------------------------------------------------------------------------

/// `POST /api/invoke/import_kubeconfig_content` — parse a kubeconfig the
/// user picked in the browser, register every context in the manager, and
/// return the merged switcher list.
pub async fn import_kubeconfig_content(
    State(state): State<WebState>,
    Json(args): Json<ImportKubeconfigContentArgs>,
) -> axum::response::Response {
    let core = state.core.clone();
    let result: AppResult<ImportResultWire> = (|| async {
        // Parse the YAML exactly like `client::contexts_from_file` does for
        // the Tauri path, so the two shells agree on the wire shape and
        // what "unparseable" looks like to the user.
        let kc = Kubeconfig::from_yaml(&args.contents)
            .map_err(|e| AppError::Kubeconfig(format!("couldn't parse {}: {e}", args.filename)))?;

        let imported: Vec<ContextInfo> = kc
            .contexts
            .iter()
            .map(|ctx| {
                let cluster = ctx
                    .context
                    .as_ref()
                    .map(|c| c.cluster.clone())
                    .unwrap_or_default();
                ContextInfo {
                    name: ctx.name.clone(),
                    cluster,
                    current: false,
                }
            })
            .collect();

        // Register each context so a later `connect` builds from this file.
        // We stash the parsed `Kubeconfig` (rather than the file path)
        // because the web shell has no real file on disk — the bytes came
        // from the user's `<input type="file">` and are gone the moment
        // they pick again.
        for ctx in &imported {
            core.manager
                .add_import(
                    ctx.name.clone(),
                    ImportedContext {
                        path: args.filename.clone(),
                        cluster: ctx.cluster.clone(),
                        kubeconfig: Some(kc.clone()),
                    },
                )
                .await;
        }

        let merged = shell_common::merged_contexts(&core.manager).await;
        Ok(ImportResultWire {
            contexts: merged,
            path: args.filename,
        })
    })()
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Catch-all stub for unimplemented commands.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Helpers (re-implementations of the small bits commands.rs's connect/get_yaml
// need that aren't already in `k7s_deps::kube::`).
// ---------------------------------------------------------------------------

pub(super) async fn core_client(core: &Arc<CoreState>) -> AppResult<k7s_deps::kube::Client> {
    // `Disconnected` (not `NotFound`) is intentional: the front-end wants to
    // detect this case and route to a "pick a cluster" flow, not treat it as
    // "the object you asked for doesn't exist". String-matching would be
    // fragile; switching on the error variant in serde-deserialised output
    // is harder, so the error message itself stays human-readable and the
    // Tauri shell (which uses a different error path) keeps its own
    // classification.
    core.manager.client().await.ok_or(AppError::Disconnected)
}

// ---------------------------------------------------------------------------
// SBOM handlers
// ---------------------------------------------------------------------------

/// `POST /api/sbom/image` — Generate SBOM for a container image.
pub async fn sbom_generate_image(
    State(state): State<WebState>,
    Json(req): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let image_ref = req["image_ref"].as_str().unwrap_or("").to_string();
    let format_str = req["format"].as_str().unwrap_or("cyclonedx");
    let format = k7s_core::kube::sbom::SbomFormat::parse(format_str)
        .unwrap_or(k7s_core::kube::sbom::SbomFormat::CycloneDx);

    let engine = {
        let p = prefs::read_prefs(&state.core.data_dir);
        k7s_core::kube::sbom::SbomEngine::with_prefs(
            p.scanner_trivy_path.as_deref(),
            p.scanner_grype_path.as_deref(),
            p.scanner_timeout.as_deref(),
        )
    };
    let result: AppResult<_> = async {
        let sbom = engine.generate_with_vulns(&image_ref, &format).await?;
        let storage = k7s_core::kube::sbom_storage::SbomStorage::new(&state.core.data_dir);
        storage.save(&sbom)?;
        Ok(sbom)
    }
    .await;
    respond(result)
}

/// `GET /api/sbom/history` — List SBOM scan history.
pub async fn sbom_list_history(State(state): State<WebState>) -> axum::response::Response {
    let storage = k7s_core::kube::sbom_storage::SbomStorage::new(&state.core.data_dir);
    respond(storage.list())
}

/// `GET /api/sbom/:id` — Get SBOM by ID.
pub async fn sbom_get(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let storage = k7s_core::kube::sbom_storage::SbomStorage::new(&state.core.data_dir);
    respond(storage.load(&id))
}

/// GET /api/web-token — return the auth token so the same-origin SPA can
/// attach it to subsequent `/api/invoke/*` calls.
///
/// **Loopback only.** The router does not mount this route on non-loopback
/// binds; this handler is a backstop that refuses if reached anyway.
pub async fn web_token(State(state): State<WebState>) -> axum::response::Response {
    if !state.is_loopback {
        return axum::response::Response::builder()
            .status(k7s_deps::http::StatusCode::NOT_FOUND)
            .body(axum::body::Body::empty())
            .expect("Response::builder with hardcoded status and body is infallible");
    }
    Json(k7s_deps::serde_json::json!({ "token": *state.web_token })).into_response()
}

// ---------------------------------------------------------------------------
// Dynamic /invoke dispatch — everything except the bespoke handlers above.
// ---------------------------------------------------------------------------

/// `POST /api/invoke/{cmd}` — dispatch through the shared command registry.
///
/// Explicit routes registered earlier in the router (prefs, kubeconfig import,
/// the AI surface) win over this catch-all; everything else resolves here
/// against the same table the Tauri shells compile in, so a command only
/// needs one implementation to be reachable from both transports.
pub async fn invoke_registry(
    axum::extract::Path(cmd): axum::extract::Path<String>,
    axum::extract::State(state): axum::extract::State<WebState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let Some(handler) = state.registry.get(&cmd) else {
        return respond::<k7s_deps::serde_json::Value>(Err(AppError::NotFound(format!(
            "unknown command `{cmd}`"
        ))));
    };
    let args: k7s_deps::serde_json::Value = if body.is_empty() {
        k7s_deps::serde_json::Value::Object(Default::default())
    } else {
        match k7s_deps::serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return respond::<k7s_deps::serde_json::Value>(Err(AppError::Other(format!(
                    "invalid JSON body: {e}"
                ))))
            }
        }
    };
    match handler(state.core.clone(), args).await {
        Ok(v) => respond::<k7s_deps::serde_json::Value>(Ok(v)),
        Err(e) => respond::<k7s_deps::serde_json::Value>(Err(e)),
    }
}

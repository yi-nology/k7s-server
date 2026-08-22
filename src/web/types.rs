//! Shared types for the web shell handlers.
//!
//! Response envelopes (`InvokeResponse`, `InvokeError`), the `respond`
//! convenience helper, and all request-body structs (`*Args`) used by the
//! `POST /invoke/{cmd}` routes live here so every handler module can import
//! them without circular dependencies.

use axum::{response::IntoResponse, Json};
use k7s_deps::http::StatusCode;
use serde::{Deserialize, Serialize};

use k7s_core::core::prefs::Prefs;
use k7s_core::error::AppResult;
use k7s_core::kube::client::ContextInfo;

// ---------------------------------------------------------------------------
// Response envelopes — every command has the same shape on the wire.
// ---------------------------------------------------------------------------

/// The shape every successful `POST /invoke/{cmd}` returns. `data` is a
/// per-command JSON value; the front-end types assert on it.
#[derive(Serialize)]
pub struct InvokeResponse<T: Serialize> {
    pub ok: bool,
    pub data: T,
}

/// The shape every failed `POST /invoke/{cmd}` returns. `error` is the
/// message string the back-end gave us; the front-end displays it inline.
#[derive(Serialize)]
pub struct InvokeError {
    pub ok: bool,
    pub error: String,
}

impl<T: Serialize> IntoResponse for InvokeResponse<T> {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

impl IntoResponse for InvokeError {
    fn into_response(self) -> axum::response::Response {
        // 200 with `{ ok: false, error }` so the front-end can deserialise
        // uniformly; some shells prefer 4xx for errors but k7s's existing
        // Tauri contract is to throw, which Tauri maps to a rejected promise
        // — the front-end handles both via `try/catch`. The HTTP analogue
        // here is "the request succeeded, the command didn't".
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Convenience: convert an `AppResult<T>` into the right response type.
pub(super) fn respond<T: Serialize>(r: AppResult<T>) -> axum::response::Response {
    match r {
        Ok(data) => InvokeResponse { ok: true, data }.into_response(),
        Err(e) => InvokeError {
            ok: false,
            error: e.to_string(),
        }
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Request-body structs (the JSON the front-end POSTs for each command).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SavePrefsArgs {
    pub prefs: Prefs,
}

/// `POST /invoke/import_kubeconfig_content` — body: a kubeconfig file's
/// filename and its raw YAML. The web shell sends the file's bytes after
/// reading it with the browser's `<input type="file">`; the desktop Tauri
/// shell reads the file path with its native dialog and goes through
/// `commands::import_kubeconfig` instead. Both register the imported
/// contexts in the manager so `connect` later can find which file a context
/// came from (B17).
#[derive(Deserialize)]
pub struct ImportKubeconfigContentArgs {
    /// Just the filename — the file's bytes are in `contents`, the path
    /// doesn't exist on the server. Used as the label in the switcher and
    /// for `restore_imports` on next boot.
    pub filename: String,
    pub contents: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosePodArgs {
    pub namespace: String,
    pub pod: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRevisionsArgs {
    pub kind: String,
    pub namespace: String,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellInputArgs {
    pub stream_id: String,
    pub data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellResizeArgs {
    pub stream_id: String,
    pub cols: u16,
    pub rows: u16,
}

/// Args for `dry_run_yaml_bundle` — just the multi-doc YAML string. Each
/// document's apiVersion/kind/namespace/name are read from the doc itself.
#[derive(Debug, Deserialize)]
pub struct DryRunYamlBundleArgs {
    pub yaml: String,
}

/// Args for `apply_yaml_bundle` — the create-apply counterpart of
/// `DryRunYamlBundleArgs`. Same shape: the whole multi-doc YAML string.

// ---------------------------------------------------------------------------
// Wire DTOs — serialisable shapes returned by specific handlers.
// ---------------------------------------------------------------------------

/// `GET /api/status` — no body. The render side of the connection banner.
#[derive(Serialize)]
pub struct StatusDto {
    pub connected: bool,
    pub context: Option<String>,
    pub server: Option<String>,
    pub version: Option<String>,
    /// Number of resource watchers running on the current connection.
    pub watcher_count: usize,
}

/// Wire shape for `import_kubeconfig_content`. Mirrors the Tauri `ImportResult`
/// 1:1 so the front-end can use the same TypeScript type for both shells.
#[derive(Serialize)]
pub struct ImportResultWire {
    pub contexts: Vec<ContextInfo>,
    pub path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelmManifestRevisionArgs {
    pub namespace: String,
    pub name: String,
    pub revision: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelmValuesRevisionArgs {
    pub namespace: String,
    pub name: String,
    pub revision: i64,
}

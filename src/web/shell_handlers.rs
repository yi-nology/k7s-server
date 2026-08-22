//! Shell and log-streaming HTTP handlers.
//!
//! Covers: pod/node shell sessions (start, input, resize, stop) and log
//! streaming (start, stop, export). The wire names match the Tauri commands
//! so the front-end can swap providers unchanged.

use axum::{extract::State, Json};

use k7s_core::error::AppResult;

use super::state::WebState;
use super::types::*;

// ---------------------------------------------------------------------------
// Log streaming — the headline feature of the web shell, previously stubbed.
// The Tauri path spawned a tokio task and pushed events to the same
// `EventSink`; the web path does the same, just behind a different transport.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shell sessions (B4, B53) — the same exec task the Tauri shell spawns, with
// input/resize going over POST and the byte stream coming back through the
// shared `EventSink` -> SSE. The wire names match the Tauri commands so the
// front-end can swap providers unchanged.
// ---------------------------------------------------------------------------

pub async fn shell_input(
    State(state): State<WebState>,
    Json(args): Json<ShellInputArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = async {
        state
            .core
            .manager
            .shell_input(&args.stream_id, args.data.into_bytes())
            .await;
        Ok(())
    }
    .await;
    respond(result)
}

pub async fn shell_resize(
    State(state): State<WebState>,
    Json(args): Json<ShellResizeArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = async {
        state
            .core
            .manager
            .shell_resize(&args.stream_id, args.cols, args.rows)
            .await;
        Ok(())
    }
    .await;
    respond(result)
}

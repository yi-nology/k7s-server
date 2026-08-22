//! Resource-oriented HTTP handlers — read and mutate Kubernetes objects.
//!
//! Covers: YAML viewing, events, properties, secret data, apply/dry-run,
//! delete, scale, cordon, restart, rollout revisions/undo, drain, and
//! endpoint listing. All delegate to the same `core::k7s_deps::kube::*` business
//! logic the Tauri shell uses.

use axum::{extract::State, Json};

use k7s_core::error::{AppError, AppResult};

use super::handlers::core_client;
use super::state::WebState;
use super::types::*;

// ---------------------------------------------------------------------------
// get_yaml — fetch an object's YAML. For Helm releases, decode from the
// release Secret (mirrors commands::get_yaml).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// get_events — read events filtered by the involved object.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// get_properties — delegate to the core helper.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// get_secret_data — decoded Secret values (base64 -> UTF-8). Deliberately
// separate from get_yaml which redacts values.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Mutation commands — share the same `dynamic_api` path the Tauri shell uses.
// ---------------------------------------------------------------------------

/// List the revision history of a Deployment/StatefulSet/DaemonSet — backs the
/// Revisions detail tab in web mode. Mirrors the `list_revisions` Tauri command.
pub async fn list_revisions(
    State(state): State<WebState>,
    Json(args): Json<ListRevisionsArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::rollout::Revision>> = async {
        if !k7s_core::kube::rollout::is_rollout_kind(&args.kind) {
            return Err(AppError::Other(format!(
                "{} has no revision history",
                args.kind
            )));
        }
        let client = core_client(&state.core).await?;
        k7s_core::kube::rollout::list_revisions(client, &args.kind, &args.namespace, &args.name)
            .await
    }
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// list_endpoints — EndpointSlices for the topology graph.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// diagnose_pod — analyze why a Pod terminated or is unhealthy.
// ---------------------------------------------------------------------------

pub async fn diagnose_pod(
    State(state): State<WebState>,
    Json(args): Json<DiagnosePodArgs>,
) -> axum::response::Response {
    let result: AppResult<k7s_deps::serde_json::Value> = async {
        let client = core_client(&state.core).await?;
        let diagnosis =
            k7s_core::kube::pod_diagnosis::diagnose_pod(client, &args.namespace, &args.pod).await?;
        k7s_deps::serde_json::to_value(diagnosis)
            .map_err(|e| AppError::Other(format!("serialize error: {e}")))
    }
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// Helm revision diff — manifest / values for a specific revision
// ---------------------------------------------------------------------------

pub async fn helm_manifest_revision(
    State(state): State<WebState>,
    Json(args): Json<HelmManifestRevisionArgs>,
) -> axum::response::Response {
    let result: AppResult<String> = async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::helm::helm_manifest_revision(
            client,
            &args.namespace,
            &args.name,
            args.revision,
        )
        .await
    }
    .await;
    respond(result)
}

pub async fn helm_values_revision(
    State(state): State<WebState>,
    Json(args): Json<HelmValuesRevisionArgs>,
) -> axum::response::Response {
    let result: AppResult<k7s_deps::serde_json::Value> = async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::helm::helm_values_revision(
            client,
            &args.namespace,
            &args.name,
            args.revision,
        )
        .await
    }
    .await;
    respond(result)
}

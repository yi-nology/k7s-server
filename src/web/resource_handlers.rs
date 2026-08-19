//! Resource-oriented HTTP handlers — read and mutate Kubernetes objects.
//!
//! Covers: YAML viewing, events, properties, secret data, apply/dry-run,
//! delete, scale, cordon, restart, rollout revisions/undo, drain, and
//! endpoint listing. All delegate to the same `core::k7s_deps::kube::*` business
//! logic the Tauri shell uses.

use axum::{extract::State, Json};
use k7s_deps::kube::ResourceExt;

use k7s_core::core::shell_common;
use k7s_core::error::{AppError, AppResult};
use k7s_core::kube::properties;
use k7s_deps::k8s_openapi::api::core::v1::{Event, Secret};
use k7s_deps::kube::api::{Api, ListParams};

use super::handlers::core_client;
use super::state::WebState;
use super::types::*;

// ---------------------------------------------------------------------------
// get_yaml — fetch an object's YAML. For Helm releases, decode from the
// release Secret (mirrors commands::get_yaml).
// ---------------------------------------------------------------------------

pub async fn get_yaml(
    State(state): State<WebState>,
    Json(args): Json<GetYamlArgs>,
) -> axum::response::Response {
    let result: AppResult<String> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::fetch_object_yaml(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// get_events — read events filtered by the involved object.
// ---------------------------------------------------------------------------

pub async fn get_events(
    State(state): State<WebState>,
    Json(args): Json<GetEventsArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<WireEvent>> = (|| async {
        let client = core_client(&state.core).await?;
        // Server-side field-selector, mirroring the MCP path (kube_api::get_events)
        // and `kubectl get event --field-selector`. The previous client-side
        // filter on a cluster-wide `Api::all().list()` was unreliable: it pulled
        // every event in the cluster and then dropped most of them, and on some
        // clusters returned an empty list entirely (the Dashboard/EventsTab
        // "always empty on the web path" symptom). A field-selected list is both
        // cheaper and correct.
        //
        // Map the plural kind the frontend sends to the singular Kubernetes Kind
        // the involvedObject carries. Same table the MCP path uses.
        let involved_kind = match args.kind.rsplit('/').next().unwrap_or(&args.kind) {
            "pods" => "Pod",
            "deployments" => "Deployment",
            "replicasets" => "ReplicaSet",
            "statefulsets" => "StatefulSet",
            "daemonsets" => "DaemonSet",
            "jobs" => "Job",
            "cronjobs" => "CronJob",
            "services" => "Service",
            "ingresses" => "Ingress",
            "configmaps" => "ConfigMap",
            "secrets" => "Secret",
            "persistentvolumeclaims" => "PersistentVolumeClaim",
            "nodes" => "Node",
            "namespaces" => "Namespace",
            other => other,
        };
        // Cluster-scoped kinds (nodes, namespaces, ...) have no namespace; list
        // cluster-wide for them. `Api::namespaced(client, "")` would hit
        // `/api/v1/namespaces//events` and the 307 redirect breaks the kube
        // client's deserializer.
        let api: Api<Event> = if args.namespace.is_empty() {
            Api::all(client)
        } else {
            Api::namespaced(client, &args.namespace)
        };
        let lp = ListParams::default().fields(&format!(
            "involvedObject.name={},involvedObject.kind={}",
            args.name, involved_kind
        ));
        let list = api.list(&lp).await?;
        let mut out: Vec<WireEvent> = list
            .items
            .into_iter()
            .map(|e| {
                // last-seen for the EventsTab filter: prefer lastTimestamp, then
                // eventTime, then creationTimestamp. Same precedence as map_event.
                let last_ts = e
                    .last_timestamp
                    .as_ref()
                    .map(|t| t.0)
                    .or_else(|| e.event_time.as_ref().map(|t| t.0))
                    .or_else(|| e.creation_timestamp().map(|t| t.0))
                    .map(|dt| dt.to_string());
                WireEvent {
                    ty: e.type_.unwrap_or_else(|| "Normal".into()),
                    reason: e.reason.unwrap_or_default(),
                    message: e.message.unwrap_or_default(),
                    count: e.count.unwrap_or(1),
                    age: "\u{2014}".into(),
                    last_timestamp: last_ts,
                }
            })
            .collect();
        // Newest first: the API server returns events in creation order (oldest
        // first), and the front-end renders them in arrival order.
        out.sort_by_key(|e| {
            // parse the RFC3339 we just built; fall back to 0 (sorts oldest) so a
            // missing timestamp can't crash the comparator.
            e.last_timestamp
                .as_deref()
                .and_then(|s| k7s_deps::chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(0)
        });
        out.reverse();
        Ok(out)
    })()
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// get_properties — delegate to the core helper.
// ---------------------------------------------------------------------------

pub async fn get_properties(
    State(state): State<WebState>,
    Json(args): Json<GetPropertiesArgs>,
) -> axum::response::Response {
    let result: AppResult<k7s_core::kube::properties::Properties> = (|| async {
        let client = core_client(&state.core).await?;
        properties::gather(client, &args.kind, &args.namespace, &args.name).await
    })()
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// get_secret_data — decoded Secret values (base64 -> UTF-8). Deliberately
// separate from get_yaml which redacts values.
// ---------------------------------------------------------------------------

pub async fn get_secret_data(
    State(state): State<WebState>,
    Json(args): Json<GetSecretDataArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<WireSecretEntry>> = (|| async {
        let client = core_client(&state.core).await?;
        let api: Api<Secret> = Api::namespaced(client, &args.namespace);
        let sec = api
            .get(&args.name)
            .await
            .map_err(|e| AppError::Kube(e.to_string()))?;
        let mut entries = Vec::new();
        if let Some(data) = &sec.data {
            for (k, v) in data {
                let decoded = String::from_utf8_lossy(&v.0).to_string();
                entries.push(WireSecretEntry {
                    key: k.clone(),
                    value: decoded,
                });
            }
        }
        Ok(entries)
    })()
    .await;
    respond(result)
}

// ---------------------------------------------------------------------------
// Mutation commands — share the same `dynamic_api` path the Tauri shell uses.
// ---------------------------------------------------------------------------

pub async fn apply_yaml(
    State(state): State<WebState>,
    Json(args): Json<ApplyYamlArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::apply_yaml_core(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            &args.yaml,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

pub async fn dry_run_yaml(
    State(state): State<WebState>,
    Json(args): Json<DryRunYamlArgs>,
) -> axum::response::Response {
    let result: AppResult<shell_common::YamlDiff> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::dry_run_yaml_core(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            &args.yaml,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

/// `POST /invoke/dry_run_yaml_bundle` — multi-doc dry run for the create
/// overlay's YAML-import Preview. Delegates to `templates::multi_dry_run`.
pub async fn dry_run_yaml_bundle(
    State(state): State<WebState>,
    Json(args): Json<DryRunYamlBundleArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::templates::DocDryRun>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::templates::multi_dry_run(&args.yaml, client).await
    })()
    .await;
    respond(result)
}

/// `POST /invoke/apply_yaml_bundle` — the create-apply counterpart of
/// `dry_run_yaml_bundle` (the P2 wizard's 应用 step). Delegates to
/// `templates::multi_apply`, same path the desktop Tauri command uses.
pub async fn apply_yaml_bundle(
    State(state): State<WebState>,
    Json(args): Json<ApplyYamlBundleArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::templates::ApplyResult>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::templates::multi_apply(&args.yaml, client, &state.core.manager).await
    })()
    .await;
    respond(result)
}

pub async fn delete_resource(
    State(state): State<WebState>,
    Json(args): Json<DeleteResourceArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::delete_resource_core(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

pub async fn scale_resource(
    State(state): State<WebState>,
    Json(args): Json<ScaleResourceArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::scale_resource_core(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            args.replicas,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

pub async fn set_cordon(
    State(state): State<WebState>,
    Json(args): Json<SetCordonArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::set_cordon_core(client, &args.name, args.unschedulable, &state.core.manager)
            .await
    })()
    .await;
    respond(result)
}

pub async fn restart_pod(
    State(state): State<WebState>,
    Json(args): Json<RestartPodArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::restart_pod_core(client, &args.namespace, &args.name).await
    })()
    .await;
    respond(result)
}

pub async fn restart_rollout(
    State(state): State<WebState>,
    Json(args): Json<RestartRolloutArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        shell_common::restart_rollout_core(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            &state.core.manager,
        )
        .await
    })()
    .await;
    respond(result)
}

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
        k7s_core::kube::rollout::list_revisions(client, &args.kind, &args.namespace, &args.name).await
    }
    .await;
    respond(result)
}

/// Roll a workload back to `to_revision`, or to the previous revision when
/// `to_revision` is None. Mirrors the `undo_rollout` Tauri command.
pub async fn undo_rollout(
    State(state): State<WebState>,
    Json(args): Json<UndoRolloutArgs>,
) -> axum::response::Response {
    let result: AppResult<()> = async {
        if !k7s_core::kube::rollout::is_rollout_kind(&args.kind) {
            return Err(AppError::Other(format!(
                "{} cannot be rolled back",
                args.kind
            )));
        }
        let client = core_client(&state.core).await?;
        k7s_core::kube::rollout::undo_to(
            client,
            &args.kind,
            &args.namespace,
            &args.name,
            args.to_revision,
        )
        .await
    }
    .await;
    respond(result)
}

pub async fn drain_node(
    State(state): State<WebState>,
    Json(args): Json<DrainNodeArgs>,
) -> axum::response::Response {
    use k7s_core::kube::drain;
    let result: AppResult<()> = (|| async {
        let client = core_client(&state.core).await?;
        let manager = state.core.manager.clone();

        // Cordon first (matches Tauri shell behaviour): without it the scheduler
        // could refill the node as we drain it.
        drain::cordon(client.clone(), &args.name).await?;

        let sink = manager.sink();
        let task = k7s_deps::tokio::spawn(async move {
            drain::run_drain(client, sink, args.name).await;
        });
        manager.push_task(task).await;
        Ok(())
    })()
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
    let result: AppResult<k7s_deps::serde_json::Value> = (|| async {
        let client = core_client(&state.core).await?;
        let diagnosis =
            k7s_core::kube::pod_diagnosis::diagnose_pod(client, &args.namespace, &args.pod).await?;
        k7s_deps::serde_json::to_value(diagnosis)
            .map_err(|e| AppError::Other(format!("serialize error: {e}")))
    })()
    .await;
    respond(result)
}

pub async fn list_endpoints(State(state): State<WebState>) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::endpoints::EndpointRow>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::endpoints::list_all(&client).await
    })()
    .await;
    respond(result)
}

/// `POST /invoke/custom_kind_counts` — per-CRD instance counts for the
/// custom-kinds nav badges (P4). No args: the sweep covers every CRD
/// discovery finds, and each kind that can't be listed (RBAC-denied)
/// reports 0 rather than failing the call.
pub async fn custom_kind_counts(State(state): State<WebState>) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::CustomKindCount>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::custom_kind_counts(&client).await
    })()
    .await;
    respond(result)
}

pub async fn list_endpoints_for_service(
    State(state): State<WebState>,
    Json(args): Json<ListEndpointsForServiceArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::endpoints::EndpointRow>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::endpoints::list_for_service(&client, &args.namespace, &args.name).await
    })()
    .await;
    respond(result)
}

pub async fn list_endpoint_addresses(
    State(state): State<WebState>,
    Json(args): Json<ListEndpointAddressesArgs>,
) -> axum::response::Response {
    let result: AppResult<Vec<k7s_core::kube::endpoints::EndpointAddress>> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::endpoints::addresses_for(&client, &args.namespace, &args.name).await
    })()
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
    let result: AppResult<String> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::helm::helm_manifest_revision(
            client,
            &args.namespace,
            &args.name,
            args.revision,
        )
        .await
    })()
    .await;
    respond(result)
}

pub async fn helm_values_revision(
    State(state): State<WebState>,
    Json(args): Json<HelmValuesRevisionArgs>,
) -> axum::response::Response {
    let result: AppResult<k7s_deps::serde_json::Value> = (|| async {
        let client = core_client(&state.core).await?;
        k7s_core::kube::helm::helm_values_revision(client, &args.namespace, &args.name, args.revision)
            .await
    })()
    .await;
    respond(result)
}

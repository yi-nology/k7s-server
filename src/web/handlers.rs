//! Core HTTP handlers — connection management, preferences, and helpers.
//!
//! Contains the cluster lifecycle commands (`list_contexts`, `connect`,
//! `status`, `import_kubeconfig_content`), preference I/O, the catch-all
//! `not_implemented` stub, and the shared `core_client` helper that every
//! handler module uses.
//!
//! Resource mutation and shell handlers live in their own modules
//! (`resource_handlers`, `shell_handlers`).

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







// ---------------------------------------------------------------------------
// Helpers (re-implementations of the small bits commands.rs's connect/get_yaml
// need that aren't already in `k7s_deps::kube::`).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AI webhook hooks
// ---------------------------------------------------------------------------

/// Verify webhook authorization. Returns `Some(error_response)` if unauthorized.
fn verify_hook_auth(headers: &k7s_deps::http::HeaderMap) -> Option<axum::response::Response> {
    let token = std::env::var("K7S_HOOK_TOKEN").unwrap_or_default();
    let hook_config = k7s_core::ai::hooks::HookConfig {
        enabled: !token.is_empty(),
        token,
        ..Default::default()
    };
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    if k7s_core::ai::hooks::verify_hook(&hook_config, auth) {
        return None;
    }
    Some(
        axum::response::Json(
            k7s_deps::serde_json::json!({"success": false, "message": "unauthorized"}),
        )
        .into_response(),
    )
}

/// POST /hooks/wake — fire-and-forget: wake the agent with a message.
/// The response returns immediately; the agent runs in the background.
pub async fn hook_wake(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("health check");
    k7s_deps::tracing::info!(message = message, "hook/wake triggered");
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("received: {}", message),
    }))
    .into_response()
}

/// POST /hooks/agent — synchronous: send a message, get the response back.
/// Currently returns a placeholder; full integration would construct a
/// ChatRequest and run the agent loop.
pub async fn hook_agent(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let message = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let skill_id = body.get("skillId").and_then(|v| v.as_str());
    k7s_deps::tracing::info!(message = message, skill = skill_id, "hook/agent triggered");
    // Full integration: construct ChatRequest, run AgentLoop, return response.
    // For now, acknowledge receipt.
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("agent received: '{}' (full agent integration pending)", message),
    }))
    .into_response()
}

/// POST /hooks/event — push a cluster event for the agent to analyze.
pub async fn hook_event(
    State(_state): State<WebState>,
    headers: k7s_deps::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    if let Some(resp) = verify_hook_auth(&headers) {
        return resp;
    }
    let event_type = body
        .get("eventType")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = body
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("info");
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    k7s_deps::tracing::info!(
        event_type = event_type,
        severity = severity,
        description = description,
        "hook/event received"
    );
    // Full integration: store the event, trigger agent analysis if severity >= warning.
    axum::response::Json(k7s_deps::serde_json::json!({
        "success": true,
        "message": format!("event received: {} ({})", event_type, severity),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// AI assistant web handlers
// ---------------------------------------------------------------------------

/// POST /invoke/ai_get_config
pub async fn ai_get_config_handler(State(state): State<WebState>) -> axum::response::Response {
    let dir = state.core.data_dir.clone();
    let result = match k7s_deps::tokio::time::timeout(
        std::time::Duration::from_secs(3),
        k7s_deps::tokio::task::spawn_blocking(move || k7s_core::ai::config::load(Some(&dir))),
    )
    .await
    {
        Ok(Ok(Ok(view))) => Ok(view),
        Ok(Ok(Err(e))) => Err(k7s_core::error::AppError::Other(e.to_string())),
        Ok(Err(e)) => Err(k7s_core::error::AppError::Other(e.to_string())),
        Err(_) => Err(k7s_core::error::AppError::Other(
            "config load timed out (keychain may be locked)".into(),
        )),
    };
    respond(result)
}

/// POST /invoke/ai_get_context
pub async fn ai_get_context_handler(State(state): State<WebState>) -> axum::response::Response {
    let ctx = state
        .core
        .manager
        .connection_info()
        .await
        .map(|i| i.context)
        .unwrap_or_default();
    respond(Ok(ctx))
}

/// POST /invoke/ai_list_skills
pub async fn ai_list_skills_handler(State(state): State<WebState>) -> axum::response::Response {
    let reg = k7s_core::ai::skills::SkillRegistry::load(Some(&state.core.data_dir));
    let skills: Vec<k7s_core::ai::skills::Skill> = reg.list().into_iter().cloned().collect();
    respond(Ok(skills))
}

/// POST /invoke/ai_memory_list
pub async fn ai_memory_list_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    let entries: Vec<k7s_core::ai::memory::MemoryEntry> =
        store.list(None).into_iter().cloned().collect();
    respond(Ok(entries))
}

/// POST /invoke/ai_memory_search
pub async fn ai_memory_search_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    let results = store.search(query);
    respond(Ok(results))
}

/// POST /invoke/ai_memory_add
pub async fn ai_memory_add_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let tags: Vec<String> = args
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let tier_str = args
        .get("tier")
        .and_then(|v| v.as_str())
        .unwrap_or("longTerm");
    let tier = match tier_str {
        "shortTerm" => k7s_core::ai::memory::Tier::ShortTerm,
        "knowledgeVault" => k7s_core::ai::memory::Tier::KnowledgeVault,
        _ => k7s_core::ai::memory::Tier::LongTerm,
    };
    let mut store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    store.add(tier, content, tags, k7s_core::ai::memory::MemorySource::User);
    respond(Ok(k7s_deps::serde_json::json!({"ok": true})))
}

/// POST /invoke/ai_cron_list
pub async fn ai_cron_list_handler(State(state): State<WebState>) -> axum::response::Response {
    let scheduler = k7s_core::ai::cron::CronScheduler::new(state.core.data_dir.clone());
    let tasks = scheduler.list().await;
    respond(Ok(tasks))
}

/// POST /invoke/ai_evolution_strategies
pub async fn ai_evolution_strategies_handler(
    State(state): State<WebState>,
) -> axum::response::Response {
    let store = k7s_core::ai::evolution::EvolutionStore::open(&state.core.data_dir);
    let strategies: Vec<k7s_core::ai::evolution::Strategy> = store.list_strategies().to_vec();
    respond(Ok(strategies))
}

/// POST /invoke/ai_memory_preferences
pub async fn ai_memory_preferences_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    let prefs: Vec<k7s_core::ai::memory::UserPreference> = store.preferences().to_vec();
    respond(Ok(prefs))
}

/// POST /invoke/ai_memory_delete
pub async fn ai_memory_delete_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    let deleted = store.delete(id);
    respond(Ok(k7s_deps::serde_json::json!({ "deleted": deleted })))
}

/// POST /invoke/ai_memory_clear
pub async fn ai_memory_clear_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let tier_str = args.get("tier").and_then(|v| v.as_str());
    let tier = tier_str.and_then(|s| match s {
        "shortTerm" => Some(k7s_core::ai::memory::Tier::ShortTerm),
        "longTerm" => Some(k7s_core::ai::memory::Tier::LongTerm),
        "knowledgeVault" => Some(k7s_core::ai::memory::Tier::KnowledgeVault),
        _ => None,
    });
    let mut store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    store.clear(tier);
    respond(Ok(k7s_deps::serde_json::json!({ "ok": true })))
}

/// POST /invoke/ai_memory_search_vault
pub async fn ai_memory_search_vault_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let kube_context = args
        .get("kubeContext")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = k7s_core::ai::memory::MemoryStore::open(&state.core.data_dir, kube_context);
    let results = store.search_vault(query);
    respond(Ok(results))
}

/// POST /invoke/ai_cron_add
pub async fn ai_cron_add_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let task: k7s_core::ai::cron::CronTask = match k7s_deps::serde_json::from_value(args) {
        Ok(t) => t,
        Err(e) => return respond::<()>(Err(k7s_core::error::AppError::Other(e.to_string()))),
    };
    let scheduler = k7s_core::ai::cron::CronScheduler::new(state.core.data_dir.clone());
    scheduler.add(task).await;
    respond(Ok(k7s_deps::serde_json::json!({ "ok": true })))
}

/// POST /invoke/ai_cron_toggle
pub async fn ai_cron_toggle_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let scheduler = k7s_core::ai::cron::CronScheduler::new(state.core.data_dir.clone());
    let toggled = scheduler.toggle(id).await;
    respond(Ok(k7s_deps::serde_json::json!({ "toggled": toggled })))
}

/// POST /invoke/ai_cron_delete
pub async fn ai_cron_delete_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let scheduler = k7s_core::ai::cron::CronScheduler::new(state.core.data_dir.clone());
    let deleted = scheduler.delete(id).await;
    respond(Ok(k7s_deps::serde_json::json!({ "deleted": deleted })))
}

/// POST /invoke/ai_cron_presets
pub async fn ai_cron_presets_handler() -> axum::response::Response {
    respond(Ok(k7s_core::ai::cron::builtin_presets()))
}

/// POST /invoke/ai_save_config
pub async fn ai_save_config_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let config_input = args
        .get("configInput")
        .cloned()
        .unwrap_or(k7s_deps::serde_json::Value::Null);
    let config: k7s_core::ai::config::AiConfig = match k7s_deps::serde_json::from_value(config_input) {
        Ok(c) => c,
        Err(e) => {
            return respond::<()>(Err(k7s_core::error::AppError::Other(format!(
                "invalid config: {e}"
            ))))
        }
    };
    let dir = state.core.data_dir.clone();
    let result = match k7s_deps::tokio::task::spawn_blocking(move || {
        k7s_core::ai::config::save(Some(&dir), &config)
    })
    .await
    {
        Ok(Ok(())) => Ok::<(), k7s_core::error::AppError>(()),
        Ok(Err(e)) => Err(k7s_core::error::AppError::Other(e.to_string())),
        Err(e) => Err(k7s_core::error::AppError::Other(e.to_string())),
    };
    respond(result)
}

/// POST /invoke/ai_save_api_key
pub async fn ai_save_api_key_handler(
    State(state): State<WebState>,
    Json(args): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let api_key = args
        .get("apiKey")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let dir = state.core.data_dir.clone();
    let result = match k7s_deps::tokio::task::spawn_blocking(move || {
        k7s_core::ai::config::save_api_key(Some(&dir), &api_key)
    })
    .await
    {
        Ok(Ok(())) => Ok::<(), k7s_core::error::AppError>(()),
        Ok(Err(e)) => Err(k7s_core::error::AppError::Other(e.to_string())),
        Err(e) => Err(k7s_core::error::AppError::Other(e.to_string())),
    };
    respond(result)
}

/// POST /invoke/ai_test_connection
pub async fn ai_test_connection_handler(State(state): State<WebState>) -> axum::response::Response {
    use k7s_core::ai::llm::LlmClient;
    let dir = state.core.data_dir.clone();
    let view =
        match k7s_deps::tokio::task::spawn_blocking(move || k7s_core::ai::config::load(Some(&dir)))
            .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string())))
            }
            Err(e) => return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string()))),
        };
    let cfg = view.config;
    let (base, model, key) = match k7s_core::ai::config::resolve(&cfg, Some(&state.core.data_dir)) {
        Ok(t) => t,
        Err(e) => return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string()))),
    };
    let client = k7s_core::ai::llm::OpenAiClient::new(base, model, key, cfg.provider.temperature);
    use k7s_deps::futures::StreamExt;
    let mut stream = client.chat_stream(
        &[k7s_core::ai::llm::Message::System {
            content: "Reply with the single word: ok".into(),
        }],
        &[],
    );
    let mut got = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(k7s_core::ai::llm::StreamEvent::TextDelta(t))
            | Ok(k7s_core::ai::llm::StreamEvent::ReasoningDelta(t)) => got.push_str(&t),
            Ok(k7s_core::ai::llm::StreamEvent::Done { .. }) => break,
            Err(e) => return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string()))),
        }
    }
    respond(Ok(format!("connected (model replied: {:?})", got.trim())))
}

// ---------------------------------------------------------------------------
// AI chat (streaming via SSE)
// ---------------------------------------------------------------------------

/// A web-mode EventSink that pushes AgentEvents to the SSE broadcast channel
/// AND stores them for polling.
struct WebAiSink {
    event_tx: k7s_deps::tokio::sync::broadcast::Sender<k7s_core::core::events::WebEvent>,
    run_id: String,
    events_store: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<k7s_deps::serde_json::Value>>>,
    >,
    /// Per-call approval senders. `await_approval` inserts one; the
    /// `/api/invoke/ai_approve_tool_call` handler resolves it. If the handler
    /// never runs (or the run is cancelled), the sender is dropped and the
    /// receiver errors — which the agent loop treats as **deny** (the safe
    /// default).
    pending_approvals: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, k7s_deps::tokio::sync::oneshot::Sender<bool>>,
        >,
    >,
}

impl k7s_core::ai::agent::EventSink for WebAiSink {
    fn emit(&self, ev: k7s_core::ai::agent::AgentEvent) {
        let data = k7s_deps::serde_json::json!({ "runId": self.run_id, "event": ev });
        // Store for polling.
        if let Ok(mut store) = self.events_store.lock() {
            if let Some(events) = store.get_mut(&self.run_id) {
                events.push(data.clone());
            }
        }
        // Also broadcast via SSE.
        let _ = self.event_tx.send(k7s_core::core::events::WebEvent {
            name: "ai_event".into(),
            data,
        });
    }
    fn await_approval(&self, call_id: &str) -> k7s_deps::tokio::sync::oneshot::Receiver<bool> {
        // Register a pending approval and wait for the matching
        // `ai_approve_tool_call` to resolve it. If nobody resolves it (the
        // common case until the web approval UI ships), the sender is dropped
        // when the run ends and the receiver errors → the agent loop treats
        // that as a deny. This is the safe default: writes don't proceed
        // without an explicit approval.
        let (tx, rx) = k7s_deps::tokio::sync::oneshot::channel();
        if let Ok(mut map) = self.pending_approvals.lock() {
            // A duplicate call_id (shouldn't happen) replaces the old sender,
            // dropping it → old receiver sees deny. Acceptable.
            map.insert(call_id.to_string(), tx);
        }
        rx
    }
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// POST /invoke/ai_chat — start a streaming AI chat. Returns run_id immediately;
/// events arrive via SSE on the `ai_event` channel.
pub async fn ai_chat_handler(
    State(state): State<WebState>,
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    // Parse request.
    let request: k7s_core::ai::agent::ChatRequest = match k7s_deps::serde_json::from_value(
        body.get("request")
            .cloned()
            .unwrap_or(k7s_deps::serde_json::Value::Null),
    ) {
        Ok(r) => r,
        Err(e) => {
            return respond::<String>(Err(k7s_core::error::AppError::Other(format!(
                "invalid request: {e}"
            ))))
        }
    };

    // Load config.
    let dir = state.core.data_dir.clone();
    let view =
        match k7s_deps::tokio::task::spawn_blocking(move || k7s_core::ai::config::load(Some(&dir)))
            .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string())))
            }
            Err(e) => return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string()))),
        };
    let cfg = view.config;
    let data_dir = state.core.data_dir.clone();

    // Resolve LLM provider (with Ollama fallback).
    let (base, model, key) = match k7s_core::ai::config::resolve(&cfg, Some(&data_dir)) {
        Ok(t) => t,
        Err(_) => match k7s_core::ai::embedded_models::discover_ollama(None).await {
            Some(models) if !models.is_empty() => {
                let m = &models[0];
                (
                    "http://localhost:11434/v1".to_string(),
                    m.name.clone(),
                    "ollama".to_string(),
                )
            }
            _ => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(
                    "No LLM configured. Set an API key in Settings → AI Assistant.".into(),
                )))
            }
        },
    };

    let run_id = k7s_deps::uuid::Uuid::new_v4().to_string();
    let temperature = cfg.provider.temperature;

    let llm_factory: std::sync::Arc<dyn Fn() -> Box<dyn k7s_core::ai::llm::LlmClient> + Send + Sync> =
        std::sync::Arc::new(move || {
            Box::new(k7s_core::ai::llm::OpenAiClient::new(
                base.clone(),
                model.clone(),
                key.clone(),
                temperature,
            ))
        });

    let agent =
        k7s_core::ai::agent::AgentLoop::new(k7s_core::ai::tools::ToolRegistry::new(), llm_factory);
    // Store events for polling by the frontend.
    let events_store = state.ai_runs.clone();

    let sink: std::sync::Arc<dyn k7s_core::ai::agent::EventSink> = std::sync::Arc::new(WebAiSink {
        event_tx: state.event_tx.clone(),
        run_id: run_id.clone(),
        events_store: events_store.clone(),
        pending_approvals: state.pending_approvals.clone(),
    });
    let manager = state.core.manager.clone();
    // SECURITY: web mode forces ReadOnly. Write tools are refused by the
    // permission gate regardless of the saved config (FullAuto /
    // ReadConfirmWrite). The approval channel exists (`await_approval` +
    // `ai_approve_tool_call`), but until a web approval UI is in place we do
    // not expose a way to flip the run back to an approving mode — so even a
    // leaked token cannot make the LLM mutate the cluster.
    let mode = if cfg.permission == k7s_core::ai::config::PermissionMode::ReadOnly {
        cfg.permission
    } else {
        k7s_deps::tracing::warn!(
            "web ai_chat: downgrading permission mode {:?} to ReadOnly (web mode safety default)",
            cfg.permission
        );
        k7s_core::ai::config::PermissionMode::ReadOnly
    };
    let max_turns = cfg.max_turns;
    let session_id = body
        .get("sessionId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let run_data_dir = data_dir.clone();

    // Initialize the run's event store.
    if let Ok(mut store) = events_store.lock() {
        store.insert(run_id.clone(), Vec::new());
    }

    k7s_deps::tokio::spawn(async move {
        agent
            .run(
                request,
                mode,
                max_turns,
                manager,
                sink,
                run_data_dir,
                session_id,
            )
            .await;
    });

    respond(Ok(run_id))
}

/// POST /invoke/ai_cancel — cancel a running AI chat.
pub async fn ai_cancel_handler(
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    // In web mode, cancellation is best-effort. The agent loop checks
    // is_cancelled() between steps. A production implementation would
    // store a CancellationToken per run_id.
    let _run_id = body.get("runId").and_then(|v| v.as_str()).unwrap_or("");
    respond(Ok::<_, k7s_core::error::AppError>(()))
}

/// POST /invoke/ai_poll_events — poll for events from a running/completed AI chat.
/// Returns events since `afterIndex` (0-based). The frontend calls this in a
/// loop after sending a message, avoiding SSE connection-limit issues.
pub async fn ai_poll_events_handler(
    State(state): State<WebState>,
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let run_id = body.get("runId").and_then(|v| v.as_str()).unwrap_or("");
    let after_index = body.get("afterIndex").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if run_id.is_empty() {
        return respond(Ok::<_, k7s_core::error::AppError>(
            k7s_deps::serde_json::json!({"events": [], "done": true}),
        ));
    }
    let store = match state.ai_runs.lock() {
        Ok(s) => s,
        Err(_) => {
            return respond(Ok::<_, k7s_core::error::AppError>(
                k7s_deps::serde_json::json!({"events": [], "done": true}),
            ))
        }
    };
    match store.get(run_id) {
        Some(events) => {
            // Clamp to bounds — `after_index` comes from the client and a
            // value past the end would panic on the slice. Treat it as "no
            // new events" instead.
            let after_index = after_index.min(events.len());
            let new_events: Vec<_> = events[after_index..].to_vec();
            let done = new_events.iter().any(|e| {
                e.get("event")
                    .and_then(|ev| ev.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("done")
                    || e.get("event")
                        .and_then(|ev| ev.get("type"))
                        .and_then(|t| t.as_str())
                        == Some("error")
            });
            respond(Ok::<_, k7s_core::error::AppError>(
                k7s_deps::serde_json::json!({
                    "events": new_events,
                    "done": done,
                    "total": events.len()
                }),
            ))
        }
        None => respond(Ok::<_, k7s_core::error::AppError>(
            k7s_deps::serde_json::json!({"events": [], "done": true}),
        )),
    }
}

/// POST /invoke/ai_approve_tool_call — approve/deny a pending write tool.
pub async fn ai_approve_tool_call_handler(
    State(state): State<WebState>,
    Json(body): Json<k7s_deps::serde_json::Value>,
) -> axum::response::Response {
    let call_id = body
        .get("callId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let approved = body
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Resolve the pending approval sender (if any) and deliver the verdict.
    // The agent loop's `await_approval` is awaiting the matching receiver.
    if let Ok(mut map) = state.pending_approvals.lock() {
        if let Some(tx) = map.remove(&call_id) {
            let _ = tx.send(approved);
            return respond(Ok::<_, k7s_core::error::AppError>(
                k7s_deps::serde_json::json!({
                    "ok": true,
                    "resolved": true
                }),
            ));
        }
    }
    // No pending approval for that call_id — either unknown or already settled.
    respond(Ok::<_, k7s_core::error::AppError>(
        k7s_deps::serde_json::json!({
            "ok": true,
            "resolved": false
        }),
    ))
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

//! AI assistant web handlers.
//!
//! The bespoke `/api/invoke/ai_*` surface: config load/save, memory store,
//! cron scheduler, skills, the streaming chat (`ai_chat`) with its
//! `WebAiSink` EventSink implementation, polling, and write-tool approval.

use axum::{extract::State, Json};

use super::state::WebState;
use super::types::respond;

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
    store.add(
        tier,
        content,
        tags,
        k7s_core::ai::memory::MemorySource::User,
    );
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
    let config: k7s_core::ai::config::AiConfig =
        match k7s_deps::serde_json::from_value(config_input) {
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
            Err(e) => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string())))
            }
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
            Err(e) => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string())))
            }
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
            Err(e) => {
                return respond::<String>(Err(k7s_core::error::AppError::Other(e.to_string())))
            }
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

    let llm_factory: std::sync::Arc<
        dyn Fn() -> Box<dyn k7s_core::ai::llm::LlmClient> + Send + Sync,
    > = std::sync::Arc::new(move || {
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

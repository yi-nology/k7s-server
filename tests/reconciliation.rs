//! Web-surface reconciliation: every command the desktop can invoke must be
//! reachable from the web shell too — either through the registry
//! (`POST /api/invoke/{cmd}` catch-all) or through a dedicated route.
//!
//! Companion of `k7s-commands/tests/reconciliation.rs`. The dedicated-route
//! list below is cross-checked against server.rs source so it can't drift.

use std::collections::BTreeSet;

/// Dedicated `/api/invoke/{name}` routes in server.rs (the interactive AI
/// surface + prefs + kubeconfig import). Parsed from source at test time.
fn dedicated_routes() -> BTreeSet<String> {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/server.rs"))
        .expect("src/web/server.rs readable");
    let marker = "\"/api/invoke/";
    let mut out = BTreeSet::new();
    let mut i = 0;
    while let Some(at) = src[i..].find(marker) {
        let start = i + at + marker.len();
        let end = src[start..].find('"').map(|e| start + e).unwrap_or(start);
        let name = &src[start..end];
        if !name.is_empty() {
            out.insert(name.to_string());
        }
        i = end.max(start) + 1;
    }
    // The catch-all `{cmd}` route is not a dedicated name.
    out.remove("{cmd}");
    out
}

#[tokio::test]
async fn every_command_is_reachable_on_the_web() {
    let registry = k7s_commands::registry::build_registry();
    let registered: BTreeSet<&str> = registry.names().collect();
    let dedicated = dedicated_routes();

    let mut unreachable: Vec<&str> = Vec::new();
    for name in k7s_commands::COMMAND_NAMES {
        let dedicated_hit = dedicated.contains(*name);
        if !registered.contains(name) && !dedicated_hit {
            unreachable.push(name);
        }
    }
    assert!(
        unreachable.is_empty(),
        "commands invocable on desktop but unreachable over HTTP (no registry \
         entry, no dedicated route): {unreachable:?} — register them, route \
         them, or move them to the WEB_BESPOKE list with a reason in \
         k7s-commands/tests/reconciliation.rs"
    );

    // Web-only extras are fine (ai_poll_events, import_kubeconfig_content),
    // but a command must not be BOTH registered and dedicated — the
    // dedicated route would shadow the registry entry invisibly.
    let shadowed: Vec<_> = registered
        .iter()
        .filter(|n| dedicated.contains(**n))
        .collect();
    assert!(
        shadowed.is_empty(),
        "commands both registered and on a dedicated route (route wins — \
         pick one): {shadowed:?}"
    );
}

/// The dedicated-route list is real: each name must actually appear as a
/// route in server.rs (guards against renames orphaning a command).
#[tokio::test]
async fn dedicated_routes_parse_from_server_source() {
    let routes = dedicated_routes();
    assert!(
        routes.contains("ai_chat"),
        "expected ai_chat among dedicated routes, got: {routes:?}"
    );
    assert!(routes.len() >= 23, "dedicated route set shrank: {routes:?}");
}

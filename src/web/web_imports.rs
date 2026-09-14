//! Persistence for web-shell kubeconfig imports.
//!
//! Browser imports (`import_kubeconfig_content`) have no file on disk — the
//! bytes came from the user's `<input type="file">` or the paste box and live
//! only in the manager's `imports` map. Without this store every container /
//! process restart wipes them. So each successful import also appends the
//! raw YAML to `<data_dir>/web-imports.json`, and `restore` re-registers
//! everything at boot. `prune` drops entries whose contexts the user has
//! since removed.
//!
//! The file holds client PRIVATE KEYS — written 0600, next to the password
//! hash under the data dir.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use k7s_core::kube::client::contexts_from_kubeconfig;
use k7s_core::kube::manager::{ClientManager, ImportedContext};
use k7s_deps::kube::config::Kubeconfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebImportEntry {
    filename: String,
    contents: String,
}

/// `<data_dir>/web-imports.json` (0600).
fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("web-imports.json")
}

/// Load every stored import. A missing file means "nothing imported yet";
/// a corrupt file is skipped the same way (imports are recoverable state —
/// losing them degrades to "paste it again", it must not block boot).
fn load_all(data_dir: &Path) -> Vec<WebImportEntry> {
    let Ok(text) = std::fs::read_to_string(store_path(data_dir)) else {
        return Vec::new();
    };
    k7s_deps::serde_json::from_str(&text).unwrap_or_default()
}

fn save_all(data_dir: &Path, entries: &[WebImportEntry]) {
    let path = store_path(data_dir);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = k7s_deps::serde_json::to_string_pretty(entries).unwrap_or_default();
    if std::fs::write(&path, body).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Insert or overwrite the entry for `filename` (re-importing the same file
/// replaces its stored contents).
pub fn upsert(data_dir: &Path, filename: &str, contents: &str) {
    let mut entries = load_all(data_dir);
    match entries.iter_mut().find(|e| e.filename == filename) {
        Some(e) => e.contents = contents.to_string(),
        None => entries.push(WebImportEntry {
            filename: filename.to_string(),
            contents: contents.to_string(),
        }),
    }
    save_all(data_dir, &entries);
}

/// Keep only entries whose filename still backs a registered import; drop
/// (and forget) the rest. Called after a context removal — a stored file
/// must not outlive every context that came from it.
pub fn prune_to_filenames(data_dir: &Path, keep: &HashSet<String>) {
    let entries = load_all(data_dir);
    let kept: Vec<WebImportEntry> = entries
        .into_iter()
        .filter(|e| keep.contains(&e.filename))
        .collect();
    save_all(data_dir, &kept);
}

/// Re-register every stored import at boot: parse each stored YAML, and for
/// every context in it record an `ImportedContext` (web imports carry their
/// parsed config so later `connect`s don't need a file). Returns how many
/// contexts were restored; entries that no longer parse are skipped.
pub async fn restore(data_dir: &Path, manager: &ClientManager) -> usize {
    let mut restored = 0;
    for entry in load_all(data_dir) {
        let Ok(kc) = Kubeconfig::from_yaml(&entry.contents) else {
            continue;
        };
        for ctx in contexts_from_kubeconfig(&kc) {
            manager
                .add_import(
                    ctx.name.clone(),
                    ImportedContext {
                        path: entry.filename.clone(),
                        cluster: ctx.cluster,
                        kubeconfig: Some(kc.clone()),
                    },
                )
                .await;
            restored += 1;
        }
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_core::core::shell_common;

    const VALID_CFG: &str = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.44.56.106:6443
  name: rd1
contexts:
- context:
    cluster: rd1
    user: rd1-admin
  name: rd1@rd1
current-context: rd1@rd1
users:
- name: rd1-admin
  user:
    token: test-token
"#;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("k7s-web-imports-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn upsert_then_load_roundtrips_and_overwrites_same_filename() {
        let dir = tmp_dir("roundtrip");
        upsert(&dir, "a.yaml", "first");
        upsert(&dir, "b.yaml", "second");
        upsert(&dir, "a.yaml", "first-v2");
        let entries = load_all(&dir);
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.filename == "a.yaml").unwrap();
        assert_eq!(a.contents, "first-v2");
    }

    #[test]
    fn prune_keeps_only_referenced_filenames() {
        let dir = tmp_dir("prune");
        upsert(&dir, "keep.yaml", "k");
        upsert(&dir, "drop.yaml", "d");
        let mut keep = HashSet::new();
        keep.insert("keep.yaml".to_string());
        prune_to_filenames(&dir, &keep);
        let names: Vec<String> = load_all(&dir).into_iter().map(|e| e.filename).collect();
        assert_eq!(names, vec!["keep.yaml".to_string()]);
    }

    #[test]
    fn store_file_is_private_0600() {
        let dir = tmp_dir("mode");
        upsert(&dir, "secret.yaml", "s");
        let meta = std::fs::metadata(store_path(&dir)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// The actual contract: import (persist) → fresh manager + `restore` →
    /// the context is back in the switcher with `imported: true`, and a
    /// later `connect` can use the stashed kubeconfig (no file on disk).
    #[tokio::test]
    async fn restore_reregisters_imported_contexts_after_restart() {
        let dir = tmp_dir("restore");
        upsert(&dir, "rd1.yaml", VALID_CFG);

        // Fresh manager = post-restart state. The default kubeconfig (if any
        // on this machine) also feeds merged_contexts — assert on the
        // imported context, not on the total count.
        let (sink, _seed) = k7s_core::core::events::web_sink(16);
        let manager = ClientManager::new(sink);
        assert!(
            !shell_common::merged_contexts(&manager)
                .await
                .iter()
                .any(|c| c.name == "rd1@rd1"),
            "premise: rd1@rd1 must be absent before restore"
        );

        let restored = restore(&dir, &manager).await;
        assert_eq!(restored, 1);

        let merged = shell_common::merged_contexts(&manager).await;
        let rd1 = merged.iter().find(|c| c.name == "rd1@rd1").unwrap();
        assert_eq!(rd1.cluster, "rd1");
        assert!(rd1.imported, "restored context must be marked imported");
        // And the parsed kubeconfig is stashed for file-less connect.
        assert!(manager.import_kubeconfig("rd1@rd1").await.is_some());
    }
}

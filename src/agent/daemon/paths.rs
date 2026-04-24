use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::control_plane::audit::LogMode;
use crate::crypto::at_rest::{read_persisted_bytes, write_persisted_bytes};
use crate::os_adapter::home::{preferred_desktop_dir, preferred_user_home_dir};
use crate::os_adapter::secure_wipe::secure_wipe_dir;

const USED_INVITES_PERSIST_SCOPE: &[u8] = b"used-invites-v1";
const SAFE_RUNTIME_TMPDIR_NAME: &str = "runtime_tmp";
const SAFE_EPHEMERAL_RUNTIME_DIRS: &[&str] =
    &["qypha-transfer", "qypha-sessions", "qypha-chunk-recv"];

pub(crate) fn derive_did_from_verifying_key(vk_bytes: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk_bytes);
    let hash = hasher.finalize();
    format!("did:nxf:{}", hex::encode(hash))
}

pub(crate) fn scoped_replay_nonce(sender_did: &str, nonce: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"NXF_REPLAY_SCOPE_V1");
    hasher.update(sender_did.as_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub(crate) fn onion_prefix(onion: &str, chars: usize) -> String {
    onion.chars().take(chars).collect::<String>()
}

pub(crate) fn invite_code_fingerprint(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"NXF_INVITE_CODE_V1");
    hasher.update(code.trim().as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn runtime_temp_root() -> PathBuf {
    std::env::var("QYPHA_RUNTIME_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}

pub(crate) fn runtime_temp_path(name: &str) -> PathBuf {
    runtime_temp_root().join(name)
}

pub(crate) fn safe_runtime_temp_root(agent_data_dir: &Path) -> PathBuf {
    agent_data_dir.join(SAFE_RUNTIME_TMPDIR_NAME)
}

pub(crate) fn configure_safe_runtime_temp_root(agent_data_dir: &Path) -> std::io::Result<PathBuf> {
    let root = safe_runtime_temp_root(agent_data_dir);
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }
    Ok(root)
}

pub(crate) fn ghost_secure_handoff_enabled(log_mode: &LogMode) -> bool {
    matches!(log_mode, LogMode::Ghost)
        && std::env::var("QYPHA_GHOST_SECURE_HANDOFF")
            .map(|value| {
                let normalized = value.trim().to_ascii_lowercase();
                normalized == "1" || normalized == "true" || normalized == "yes"
            })
            .unwrap_or(false)
}

pub(crate) fn ghost_handoff_root() -> PathBuf {
    runtime_temp_path("qypha-ghost-handoff")
}

pub(crate) fn create_ghost_handoff_dir() -> std::io::Result<(String, PathBuf)> {
    let handoff_id = format!("handoff_{}", uuid::Uuid::new_v4());
    let dir = ghost_handoff_root().join(&handoff_id);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        if let Some(parent) = dir.parent() {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok((handoff_id, dir))
}

fn desktop_root() -> PathBuf {
    preferred_desktop_dir().unwrap_or_else(|| PathBuf::from(".").join("Desktop"))
}

pub(crate) fn default_receive_root() -> PathBuf {
    desktop_root().join("received")
}

pub(crate) fn expand_receive_path(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return preferred_user_home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    PathBuf::from(trimmed)
}

pub(crate) fn emit_transfer_event(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    reason: Option<&str>,
) {
    emit_transfer_event_extended(
        event, direction, peer_did, peer_name, session_id, filename, reason, None, None, None,
        None, None, None, None, None, None,
    );
}

pub(crate) fn emit_transfer_event_with_group(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    reason: Option<&str>,
    group_id: Option<&str>,
    group_name: Option<&str>,
) {
    emit_transfer_event_extended(
        event, direction, peer_did, peer_name, session_id, filename, reason, None, None, None,
        None, None, None, None, group_id, group_name,
    );
}

pub(crate) fn emit_transfer_event_with_handoff(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    reason: Option<&str>,
    handoff_id: Option<&str>,
    handoff_path: Option<&Path>,
) {
    emit_transfer_event_extended(
        event,
        direction,
        peer_did,
        peer_name,
        session_id,
        filename,
        reason,
        handoff_id,
        handoff_path,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
}

pub(crate) fn emit_transfer_event_with_handoff_and_group(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    reason: Option<&str>,
    handoff_id: Option<&str>,
    handoff_path: Option<&Path>,
    group_id: Option<&str>,
    group_name: Option<&str>,
) {
    emit_transfer_event_extended(
        event,
        direction,
        peer_did,
        peer_name,
        session_id,
        filename,
        reason,
        handoff_id,
        handoff_path,
        None,
        None,
        None,
        None,
        None,
        group_id,
        group_name,
    );
}

pub(crate) fn emit_transfer_progress_event(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    transferred_chunks: usize,
    total_chunks: usize,
    transferred_bytes: u64,
    total_bytes: u64,
) {
    let percent = if total_chunks == 0 {
        0u32
    } else {
        ((transferred_chunks as f64 / total_chunks as f64) * 100.0) as u32
    };
    emit_transfer_event_extended(
        event,
        direction,
        peer_did,
        peer_name,
        session_id,
        filename,
        None,
        None,
        None,
        Some(transferred_chunks),
        Some(total_chunks),
        Some(transferred_bytes),
        Some(total_bytes),
        Some(percent),
        None,
        None,
    );
}

pub(crate) fn emit_transfer_progress_event_with_group(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    transferred_chunks: usize,
    total_chunks: usize,
    transferred_bytes: u64,
    total_bytes: u64,
    group_id: Option<&str>,
    group_name: Option<&str>,
) {
    let percent = if total_chunks == 0 {
        0u32
    } else {
        ((transferred_chunks as f64 / total_chunks as f64) * 100.0) as u32
    };
    emit_transfer_event_extended(
        event,
        direction,
        peer_did,
        peer_name,
        session_id,
        filename,
        None,
        None,
        None,
        Some(transferred_chunks),
        Some(total_chunks),
        Some(transferred_bytes),
        Some(total_bytes),
        Some(percent),
        group_id,
        group_name,
    );
}

fn emit_transfer_event_extended(
    event: &str,
    direction: &str,
    peer_did: Option<&str>,
    peer_name: Option<&str>,
    session_id: Option<&str>,
    filename: Option<&str>,
    reason: Option<&str>,
    handoff_id: Option<&str>,
    handoff_path: Option<&Path>,
    transferred_chunks: Option<usize>,
    total_chunks: Option<usize>,
    transferred_bytes: Option<u64>,
    total_bytes: Option<u64>,
    percent: Option<u32>,
    group_id: Option<&str>,
    group_name: Option<&str>,
) {
    let payload = serde_json::json!({
        "event": event,
        "direction": direction,
        "peer_did": peer_did,
        "peer_name": peer_name,
        "session_id": session_id,
        "filename": filename,
        "reason": reason,
        "handoff_id": handoff_id,
        "handoff_path": handoff_path.map(|path| path.display().to_string()),
        "transferred_chunks": transferred_chunks,
        "total_chunks": total_chunks,
        "transferred_bytes": transferred_bytes,
        "total_bytes": total_bytes,
        "percent": percent,
        "group_id": group_id,
        "group_name": group_name,
        "ts_ms": chrono::Utc::now().timestamp_millis(),
    });
    emit_transfer_event_sidechannel(&payload);
}

fn emit_transfer_event_sidechannel(payload: &serde_json::Value) {
    let Ok(path) = std::env::var("QYPHA_TRANSFER_EVENT_FILE") else {
        return;
    };
    let path = PathBuf::from(path);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let _ = writeln!(file, "{}", payload);
}

pub(crate) fn wipe_stale_zero_trace_temp_artifacts() -> usize {
    let mut wiped = 0usize;
    let primary_root = runtime_temp_root();
    let mut roots = vec![primary_root.clone()];
    if primary_root != std::env::temp_dir() {
        roots.push(std::env::temp_dir());
    }

    wipe_zero_trace_temp_artifacts_in_roots(&roots, &mut wiped);
    wiped
}

pub(crate) fn wipe_stale_safe_temp_artifacts(root: &Path) -> usize {
    let mut wiped = 0usize;
    wipe_named_temp_artifacts_in_root(root, SAFE_EPHEMERAL_RUNTIME_DIRS, &mut wiped);
    wiped
}

fn wipe_zero_trace_temp_artifacts_in_roots(roots: &[PathBuf], wiped: &mut usize) {
    for root in roots {
        wipe_named_temp_artifacts_in_root(
            root,
            &[
                "qypha-ghost-recv",
                "qypha-ghost-handoff",
                "qypha-transfer",
                "qypha-sessions",
                "qypha-chunk-recv",
            ],
            wiped,
        );
    }
}

fn wipe_named_temp_artifacts_in_root(root: &Path, dir_names: &[&str], wiped: &mut usize) {
    for dir_name in dir_names {
        let path = root.join(dir_name);
        if path.exists() {
            secure_wipe_dir(&path);
            *wiped = wiped.saturating_add(1);
        }
    }
}

pub(crate) fn load_used_invites(path: &Path, persist_key: Option<&[u8; 32]>) -> HashSet<String> {
    match read_persisted_bytes(path, persist_key, USED_INVITES_PERSIST_SCOPE) {
        Ok(Some(bytes)) => match serde_json::from_slice::<Vec<String>>(&bytes) {
            Ok(list) => list.into_iter().collect(),
            Err(e) => {
                tracing::warn!(path = %path.display(), %e, "used invite store parse failed; starting empty");
                HashSet::new()
            }
        },
        Ok(None) => HashSet::new(),
        Err(e) => {
            tracing::warn!(path = %path.display(), %e, "used invite store read failed; starting empty");
            HashSet::new()
        }
    }
}

pub(crate) fn persist_used_invites(
    path: &Path,
    used: &HashSet<String>,
    persist_key: Option<&[u8; 32]>,
) {
    let mut list: Vec<String> = used.iter().cloned().collect();
    list.sort_unstable();
    let json = match serde_json::to_vec_pretty(&list) {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!(path = %path.display(), %e, "failed to serialize used invites");
            return;
        }
    };
    if let Err(e) = write_persisted_bytes(path, persist_key, USED_INVITES_PERSIST_SCOPE, &json) {
        tracing::warn!(path = %path.display(), %e, "failed to persist used invites");
    }
}

pub(crate) fn used_invites_store_path(
    agent_data_dir: &Path,
    log_mode: &LogMode,
) -> Option<PathBuf> {
    match log_mode {
        LogMode::Ghost => None,
        _ => Some(agent_data_dir.join("used_invites.json")),
    }
}

pub(crate) fn group_mailboxes_store_path(
    agent_data_dir: &Path,
    log_mode: &LogMode,
) -> Option<PathBuf> {
    match log_mode {
        LogMode::Ghost => None,
        _ => Some(agent_data_dir.join("group_mailboxes.bin")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_used_invites_roundtrip_encrypted_for_persistent_modes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("used_invites.json");
        let mut invites = HashSet::new();
        invites.insert("fp-b".to_string());
        invites.insert("fp-a".to_string());

        persist_used_invites(&path, &invites, Some(&[33u8; 32]));
        let on_disk = std::fs::read(&path).unwrap();
        assert!(
            !std::str::from_utf8(&on_disk)
                .unwrap_or_default()
                .contains("fp-a"),
            "used invites should not leak plaintext fingerprints to disk"
        );

        let loaded = load_used_invites(&path, Some(&[33u8; 32]));
        assert_eq!(loaded, invites);
    }

    #[test]
    fn test_wipe_stale_zero_trace_temp_artifacts_cleans_known_dirs() {
        let root = tempfile::tempdir().unwrap();
        let expected_dirs = [
            "qypha-ghost-recv",
            "qypha-ghost-handoff",
            "qypha-transfer",
            "qypha-sessions",
            "qypha-chunk-recv",
        ];
        for dir in &expected_dirs {
            let path = root.path().join(dir);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("artifact.bin"), b"residue").unwrap();
        }

        let mut wiped = 0usize;
        wipe_zero_trace_temp_artifacts_in_roots(&[root.path().to_path_buf()], &mut wiped);
        assert_eq!(wiped, expected_dirs.len());
        for dir in &expected_dirs {
            assert!(
                !root.path().join(dir).exists(),
                "expected {} to be wiped",
                dir
            );
        }
    }

    #[test]
    fn test_wipe_stale_safe_temp_artifacts_cleans_safe_dirs_only() {
        let root = tempfile::tempdir().unwrap();
        for dir in SAFE_EPHEMERAL_RUNTIME_DIRS {
            let path = root.path().join(dir);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("artifact.bin"), b"residue").unwrap();
        }
        let ghost_dir = root.path().join("qypha-ghost-recv");
        std::fs::create_dir_all(&ghost_dir).unwrap();

        let wiped = wipe_stale_safe_temp_artifacts(root.path());
        assert_eq!(wiped, SAFE_EPHEMERAL_RUNTIME_DIRS.len());
        for dir in SAFE_EPHEMERAL_RUNTIME_DIRS {
            assert!(
                !root.path().join(dir).exists(),
                "expected {} to be wiped",
                dir
            );
        }
        assert!(
            ghost_dir.exists(),
            "safe janitor must not touch ghost-only dirs"
        );
    }
}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::paths::default_receive_root;

#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct ReceiveDirConfig {
    pub(crate) global_dir: Option<PathBuf>,
    pub(crate) per_peer_dirs: HashMap<String, PathBuf>,
}

pub(crate) fn effective_receive_base_dir(config: &ReceiveDirConfig, sender_did: &str) -> PathBuf {
    config
        .per_peer_dirs
        .get(sender_did)
        .cloned()
        .or_else(|| config.global_dir.clone())
        .unwrap_or_else(default_receive_root)
}

pub(crate) fn effective_receive_dir(
    config: &ReceiveDirConfig,
    sender_did: &str,
    _sender_name: &str,
) -> PathBuf {
    effective_receive_base_dir(config, sender_did)
}

pub(crate) fn receive_dir_store_path(agent_data_dir: &Path) -> PathBuf {
    agent_data_dir.join("receive_dirs.json")
}

pub(crate) fn load_receive_dir_config(path: &Path) -> ReceiveDirConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str::<ReceiveDirConfig>(&json).ok())
        .unwrap_or_default()
}

pub(crate) fn persist_receive_dir_config(path: &Path, config: &ReceiveDirConfig) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(config) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!(path = %path.display(), %e, "receive_dirs.json write failed");
            }
        }
        Err(e) => tracing::warn!(%e, "receive_dirs.json encode failed"),
    }
}

pub(crate) fn harden_configured_receive_dirs(config: &ReceiveDirConfig) -> Result<()> {
    let mut seen = HashSet::<PathBuf>::new();
    for path in config
        .global_dir
        .iter()
        .cloned()
        .chain(config.per_peer_dirs.values().cloned())
    {
        if seen.insert(path.clone()) {
            ensure_private_receive_dir(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn ensure_private_receive_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Harden only the user-selected receive directory itself. Mutating parent
        // directories can leak side effects into unrelated system or user paths.
        let private = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(path, private);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_receive_dir_defaults_to_desktop_received() {
        let cfg = ReceiveDirConfig::default();
        let expected = default_receive_root();
        assert_eq!(
            effective_receive_dir(&cfg, "did:nxf:test", "Test"),
            expected
        );
    }

    #[test]
    fn test_effective_receive_dir_prefers_global_override() {
        let mut cfg = ReceiveDirConfig::default();
        let custom = PathBuf::from("/tmp/custom-recv");
        cfg.global_dir = Some(custom.clone());

        assert_eq!(effective_receive_dir(&cfg, "did:nxf:test", "Test"), custom);
    }

    #[test]
    fn test_effective_receive_dir_prefers_per_peer_override() {
        let mut cfg = ReceiveDirConfig::default();
        cfg.global_dir = Some(PathBuf::from("/tmp/global-recv"));
        let per_peer = PathBuf::from("/tmp/peer-recv");
        cfg.per_peer_dirs
            .insert("did:nxf:peer".to_string(), per_peer.clone());

        assert_eq!(
            effective_receive_dir(&cfg, "did:nxf:peer", "Peer"),
            per_peer
        );
    }

    #[test]
    fn test_harden_configured_receive_dirs_creates_and_secures_known_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut cfg = ReceiveDirConfig::default();
        let global = root.path().join("global-recv");
        let per_peer = root.path().join("peer-recv");
        cfg.global_dir = Some(global.clone());
        cfg.per_peer_dirs
            .insert("did:nxf:peer".to_string(), per_peer.clone());

        harden_configured_receive_dirs(&cfg).unwrap();

        assert!(global.exists());
        assert!(per_peer.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&global).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&per_peer).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_private_receive_dir_does_not_mutate_parent_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("shared-parent");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let child = parent.join("private-recv");
        ensure_private_receive_dir(&child).unwrap();

        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(&child).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

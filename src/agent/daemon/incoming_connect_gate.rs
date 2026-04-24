use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::control_plane::audit::LogMode;
use crate::crypto::at_rest::{read_persisted_bytes, write_persisted_bytes};
use crate::crypto::identity::is_valid_did;
use crate::network::contact_did::decode_contact_did;
use crate::os_adapter::secure_wipe::secure_wipe_file;

const INCOMING_CONNECT_GATE_PERSIST_SCOPE: &[u8] = b"incoming-connect-gate-v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct IncomingConnectPolicySnapshot {
    #[serde(default)]
    pub(crate) block_all: bool,
    #[serde(default)]
    pub(crate) blocked_dids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedIncomingConnectGate {
    #[serde(default)]
    block_all: bool,
    #[serde(default)]
    blocked_dids: Vec<String>,
    #[serde(default)]
    blocked_peer_id_bindings: Vec<BlockedPeerIdBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BlockedPeerIdBinding {
    peer_id: String,
    did: String,
}

#[derive(Debug, Default)]
pub(crate) struct IncomingConnectGate {
    block_all: bool,
    blocked_dids: HashSet<String>,
    blocked_peer_ids: HashMap<String, String>,
    store_path: Option<PathBuf>,
    persist_key: Option<[u8; 32]>,
}

impl IncomingConnectGate {
    pub(crate) fn new(store_path: Option<&Path>) -> Self {
        Self {
            store_path: store_path.map(Path::to_path_buf),
            ..Self::default()
        }
    }

    pub(crate) fn load_with_persist_key(
        store_path: Option<&Path>,
        persist_key: Option<[u8; 32]>,
    ) -> Self {
        let Some(path) = store_path else {
            return Self::new(None);
        };
        if let Some(legacy_path) = legacy_normal_store_path(path).filter(|legacy| legacy.exists()) {
            secure_wipe_file(&legacy_path);
        }
        match read_persisted_bytes(
            path,
            persist_key.as_ref(),
            INCOMING_CONNECT_GATE_PERSIST_SCOPE,
        ) {
            Ok(Some(bytes)) => match serde_json::from_slice::<PersistedIncomingConnectGate>(&bytes)
            {
                Ok(stored) => {
                    let mut gate = Self::new(Some(path));
                    gate.persist_key = persist_key;
                    gate.block_all = stored.block_all;
                    gate.blocked_dids = stored
                        .blocked_dids
                        .into_iter()
                        .filter_map(|did| canonicalize_did_selector(&did).ok())
                        .collect();
                    gate.blocked_peer_ids = stored
                        .blocked_peer_id_bindings
                        .into_iter()
                        .filter_map(|binding| {
                            let peer_id = binding.peer_id.trim();
                            if peer_id.is_empty() {
                                return None;
                            }
                            canonicalize_did_selector(&binding.did)
                                .ok()
                                .map(|did| (peer_id.to_string(), did))
                        })
                        .collect();
                    gate
                }
                Err(error) => {
                    tracing::warn!(%error, "Failed to parse incoming connect gate");
                    let mut gate = Self::new(Some(path));
                    gate.persist_key = persist_key;
                    gate
                }
            },
            Ok(None) => {
                let mut gate = Self::new(Some(path));
                gate.persist_key = persist_key;
                gate
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to read incoming connect gate");
                let mut gate = Self::new(Some(path));
                gate.persist_key = persist_key;
                gate
            }
        }
    }

    pub(crate) fn snapshot(&self) -> IncomingConnectPolicySnapshot {
        let mut blocked_dids = self.blocked_dids.iter().cloned().collect::<Vec<_>>();
        blocked_dids.sort();
        IncomingConnectPolicySnapshot {
            block_all: self.block_all,
            blocked_dids,
        }
    }

    pub(crate) fn block_selector(&mut self, selector: &str) -> Result<(bool, String)> {
        self.block_peer_identity(selector, None)
    }

    pub(crate) fn block_peer_identity(
        &mut self,
        selector: &str,
        peer_id: Option<&str>,
    ) -> Result<(bool, String)> {
        let canonical_did = canonicalize_did_selector(selector)?;
        let did_changed = self.blocked_dids.insert(canonical_did.clone());
        let peer_changed = peer_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                self.blocked_peer_ids
                    .insert(value.to_string(), canonical_did.clone())
                    .as_deref()
                    != Some(canonical_did.as_str())
            })
            .unwrap_or(false);
        if did_changed || peer_changed {
            self.save()?;
        }
        Ok((did_changed || peer_changed, canonical_did))
    }

    pub(crate) fn unblock_selector(&mut self, selector: &str) -> Result<(bool, String)> {
        let canonical_did = canonicalize_did_selector(selector)?;
        let did_changed = self.blocked_dids.remove(&canonical_did);
        let blocked_peer_ids_before = self.blocked_peer_ids.len();
        self.blocked_peer_ids.retain(|_, did| did != &canonical_did);
        let peer_changed = self.blocked_peer_ids.len() != blocked_peer_ids_before;
        if did_changed || peer_changed {
            self.save()?;
        }
        Ok((did_changed || peer_changed, canonical_did))
    }

    pub(crate) fn set_block_all(&mut self, value: bool) -> Result<bool> {
        if self.block_all == value {
            return Ok(false);
        }
        self.block_all = value;
        self.save()?;
        Ok(true)
    }

    pub(crate) fn is_block_all(&self) -> bool {
        self.block_all
    }

    pub(crate) fn is_did_blocked(&self, canonical_did: &str) -> bool {
        self.blocked_dids.contains(canonical_did.trim())
    }

    pub(crate) fn is_peer_id_blocked(&self, peer_id: &str) -> bool {
        self.blocked_peer_ids.contains_key(peer_id.trim())
    }

    fn save(&self) -> Result<()> {
        let Some(path) = self.store_path.as_ref() else {
            return Ok(());
        };
        let mut blocked_peer_id_bindings = self
            .blocked_peer_ids
            .iter()
            .map(|(peer_id, did)| BlockedPeerIdBinding {
                peer_id: peer_id.clone(),
                did: did.clone(),
            })
            .collect::<Vec<_>>();
        blocked_peer_id_bindings.sort_by(|left, right| {
            left.did
                .cmp(&right.did)
                .then_with(|| left.peer_id.cmp(&right.peer_id))
        });
        let stored = PersistedIncomingConnectGate {
            block_all: self.block_all,
            blocked_dids: self.snapshot().blocked_dids,
            blocked_peer_id_bindings,
        };
        let encoded = serde_json::to_vec_pretty(&stored)?;
        write_persisted_bytes(
            path,
            self.persist_key.as_ref(),
            INCOMING_CONNECT_GATE_PERSIST_SCOPE,
            &encoded,
        )?;
        Ok(())
    }
}

pub(crate) fn emit_headless_policy_snapshot(snapshot: &IncomingConnectPolicySnapshot) {
    let headless = std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false);
    if headless {
        if let Ok(encoded) = serde_json::to_string(snapshot) {
            println!("INCOMING_CONNECT_POLICY {}", encoded);
        }
    }
}

pub(crate) fn canonicalize_did_selector(selector: &str) -> Result<String> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        anyhow::bail!("missing DID selector");
    }
    if let Ok(resolved) = decode_contact_did(trimmed) {
        return Ok(resolved.canonical_did);
    }
    if is_valid_did(trimmed) {
        return Ok(trimmed.to_string());
    }
    anyhow::bail!("expected did:qypha:... or canonical did:nxf:...");
}

pub(crate) fn store_path_for_mode(agent_data_dir: &Path, log_mode: &LogMode) -> Option<PathBuf> {
    match log_mode {
        LogMode::Safe => Some(agent_data_dir.join("incoming_connect_gate_safe.json")),
        LogMode::Ghost => None,
    }
}

fn legacy_normal_store_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if file_name == "incoming_connect_gate_safe.json" {
        Some(path.with_file_name("incoming_connect_gate.json"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::contact_did_from_verifying_key_bytes;
    use tempfile::tempdir;

    #[test]
    fn canonicalize_short_contact_did_to_canonical_did() {
        let keypair = AgentKeyPair::generate("GateDidOwner", "agent");
        let selector = contact_did_from_verifying_key_bytes(keypair.verifying_key.to_bytes());
        let canonical = canonicalize_did_selector(&selector).unwrap();
        assert_eq!(canonical, keypair.did);
    }

    #[test]
    fn block_and_unblock_selector_roundtrip() {
        let keypair = AgentKeyPair::generate("GateBlockOwner", "agent");
        let selector = contact_did_from_verifying_key_bytes(keypair.verifying_key.to_bytes());
        let mut gate = IncomingConnectGate::default();
        let (_, canonical) = gate.block_selector(&selector).unwrap();
        assert_eq!(canonical, keypair.did);
        assert!(gate.is_did_blocked(&keypair.did));
        gate.unblock_selector(&selector).unwrap();
        assert!(!gate.is_did_blocked(&keypair.did));
    }

    #[test]
    fn block_peer_identity_tracks_peer_id_until_unblock() {
        let keypair = AgentKeyPair::generate("GatePeerOwner", "agent");
        let mut gate = IncomingConnectGate::default();
        let peer_id = libp2p::PeerId::random().to_string();

        let (_, canonical) = gate
            .block_peer_identity(&keypair.did, Some(&peer_id))
            .unwrap();
        assert_eq!(canonical, keypair.did);
        assert!(gate.is_did_blocked(&keypair.did));
        assert!(gate.is_peer_id_blocked(&peer_id));

        gate.unblock_selector(&keypair.did).unwrap();
        assert!(!gate.is_did_blocked(&keypair.did));
        assert!(!gate.is_peer_id_blocked(&peer_id));
    }

    #[test]
    fn block_all_roundtrip() {
        let mut gate = IncomingConnectGate::default();
        assert!(!gate.is_block_all());
        assert!(gate.set_block_all(true).unwrap());
        assert!(gate.is_block_all());
        assert!(gate.set_block_all(false).unwrap());
        assert!(!gate.is_block_all());
    }

    #[test]
    fn safe_mode_persistence_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("incoming_connect_gate_safe.json");
        let keypair = AgentKeyPair::generate("GatePersistOwner", "agent");

        let mut gate = IncomingConnectGate::load_with_persist_key(Some(&path), Some([7u8; 32]));
        gate.set_block_all(true).unwrap();
        let peer_id = libp2p::PeerId::random().to_string();
        gate.block_peer_identity(&keypair.did, Some(&peer_id))
            .unwrap();

        let restored = IncomingConnectGate::load_with_persist_key(Some(&path), Some([7u8; 32]));
        assert!(restored.is_block_all());
        assert!(restored.is_did_blocked(&keypair.did));
        assert!(restored.is_peer_id_blocked(&peer_id));
    }
}

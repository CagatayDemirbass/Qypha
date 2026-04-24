use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::crypto::at_rest::{read_persisted_bytes, write_persisted_bytes};
use crate::os_adapter::secure_wipe::secure_wipe_file;

const HANDSHAKE_REQUEST_GATE_PERSIST_SCOPE: &[u8] = b"handshake-request-gate-v1";
const HANDSHAKE_REQUEST_MIN_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct HandshakeRequestPolicySnapshot {
    #[serde(default)]
    pub(crate) block_all: bool,
    #[serde(default)]
    pub(crate) blocked_member_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeOfferDecision {
    Allow,
    BlockedGlobal,
    BlockedMember,
    RateLimited { retry_after_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutgoingHandshakeOfferDecision {
    Allow,
    RateLimited { retry_after_ms: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedHandshakeRequestGate {
    #[serde(default)]
    block_all: bool,
    #[serde(default)]
    blocked_member_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct HandshakeRequestGate {
    block_all: bool,
    blocked_member_ids: HashSet<String>,
    last_surface_by_sender: HashMap<String, u64>,
    last_outgoing_offer_by_member: HashMap<String, u64>,
    store_path: Option<PathBuf>,
    persist_key: Option<[u8; 32]>,
}

impl HandshakeRequestGate {
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
            HANDSHAKE_REQUEST_GATE_PERSIST_SCOPE,
        ) {
            Ok(Some(bytes)) => {
                match serde_json::from_slice::<PersistedHandshakeRequestGate>(&bytes) {
                    Ok(stored) => {
                        let mut gate = Self::new(Some(path));
                        gate.persist_key = persist_key;
                        gate.block_all = stored.block_all;
                        gate.blocked_member_ids = stored
                            .blocked_member_ids
                            .into_iter()
                            .filter(|member_id| !member_id.trim().is_empty())
                            .collect();
                        gate
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Failed to parse handshake request gate");
                        let mut gate = Self::new(Some(path));
                        gate.persist_key = persist_key;
                        gate
                    }
                }
            }
            Ok(None) => {
                let mut gate = Self::new(Some(path));
                gate.persist_key = persist_key;
                gate
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to read handshake request gate");
                let mut gate = Self::new(Some(path));
                gate.persist_key = persist_key;
                gate
            }
        }
    }

    pub(crate) fn snapshot(&self) -> HandshakeRequestPolicySnapshot {
        let mut blocked_member_ids = self.blocked_member_ids.iter().cloned().collect::<Vec<_>>();
        blocked_member_ids.sort();
        HandshakeRequestPolicySnapshot {
            block_all: self.block_all,
            blocked_member_ids,
        }
    }

    pub(crate) fn block_member(&mut self, member_id: &str) -> Result<bool> {
        let changed = self.blocked_member_ids.insert(member_id.trim().to_string());
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    pub(crate) fn unblock_member(&mut self, member_id: &str) -> Result<bool> {
        let changed = self.blocked_member_ids.remove(member_id.trim());
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    pub(crate) fn set_block_all(&mut self, value: bool) -> Result<bool> {
        if self.block_all == value {
            return Ok(false);
        }
        self.block_all = value;
        self.save()?;
        Ok(true)
    }

    pub(crate) fn is_member_blocked(&self, member_id: &str) -> bool {
        self.blocked_member_ids.contains(member_id.trim())
    }

    pub(crate) fn evaluate_incoming_offer(
        &mut self,
        sender_member_id: &str,
        now_ms: u64,
    ) -> HandshakeOfferDecision {
        if self.block_all {
            return HandshakeOfferDecision::BlockedGlobal;
        }
        if self.is_member_blocked(sender_member_id) {
            return HandshakeOfferDecision::BlockedMember;
        }
        let sender_key = sender_member_id.trim().to_string();
        if let Some(last_seen_ms) = self.last_surface_by_sender.get(&sender_key).copied() {
            let elapsed = now_ms.saturating_sub(last_seen_ms);
            if elapsed < HANDSHAKE_REQUEST_MIN_INTERVAL_MS {
                return HandshakeOfferDecision::RateLimited {
                    retry_after_ms: HANDSHAKE_REQUEST_MIN_INTERVAL_MS.saturating_sub(elapsed),
                };
            }
        }
        self.last_surface_by_sender.insert(sender_key, now_ms);
        HandshakeOfferDecision::Allow
    }

    pub(crate) fn evaluate_outgoing_offer(
        &mut self,
        member_id: &str,
        now_ms: u64,
    ) -> OutgoingHandshakeOfferDecision {
        let member_key = member_id.trim().to_string();
        if let Some(last_sent_ms) = self.last_outgoing_offer_by_member.get(&member_key).copied() {
            let elapsed = now_ms.saturating_sub(last_sent_ms);
            if elapsed < HANDSHAKE_REQUEST_MIN_INTERVAL_MS {
                return OutgoingHandshakeOfferDecision::RateLimited {
                    retry_after_ms: HANDSHAKE_REQUEST_MIN_INTERVAL_MS.saturating_sub(elapsed),
                };
            }
        }
        self.last_outgoing_offer_by_member
            .insert(member_key, now_ms);
        OutgoingHandshakeOfferDecision::Allow
    }

    fn save(&self) -> Result<()> {
        let Some(path) = self.store_path.as_ref() else {
            return Ok(());
        };
        let stored = PersistedHandshakeRequestGate {
            block_all: self.block_all,
            blocked_member_ids: self.snapshot().blocked_member_ids,
        };
        let encoded = serde_json::to_vec_pretty(&stored)?;
        write_persisted_bytes(
            path,
            self.persist_key.as_ref(),
            HANDSHAKE_REQUEST_GATE_PERSIST_SCOPE,
            &encoded,
        )?;
        Ok(())
    }
}

pub(crate) fn store_path_for_mode(
    agent_data_dir: &Path,
    log_mode: &crate::control_plane::audit::LogMode,
) -> Option<PathBuf> {
    match log_mode {
        crate::control_plane::audit::LogMode::Safe => {
            Some(agent_data_dir.join("handshake_request_gate_safe.json"))
        }
        crate::control_plane::audit::LogMode::Ghost => None,
    }
}

fn legacy_normal_store_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if file_name == "handshake_request_gate_safe.json" {
        Some(path.with_file_name("handshake_request_gate.json"))
    } else {
        None
    }
}

pub(crate) fn emit_headless_policy_snapshot(snapshot: &HandshakeRequestPolicySnapshot) {
    let headless = std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false);
    if headless {
        if let Ok(encoded) = serde_json::to_string(snapshot) {
            println!("HANDSHAKE_REQUEST_POLICY {}", encoded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn request_gate_blocks_and_unblocks_members() {
        let mut gate = HandshakeRequestGate::default();
        assert!(!gate.is_member_blocked("did:nxf:bob"));
        gate.block_member("did:nxf:bob").unwrap();
        assert!(gate.is_member_blocked("did:nxf:bob"));
        gate.unblock_member("did:nxf:bob").unwrap();
        assert!(!gate.is_member_blocked("did:nxf:bob"));
    }

    #[test]
    fn request_gate_rate_limits_repeated_offers() {
        let mut gate = HandshakeRequestGate::default();
        assert_eq!(
            gate.evaluate_incoming_offer("did:nxf:bob", 1_000),
            HandshakeOfferDecision::Allow
        );
        match gate.evaluate_incoming_offer("did:nxf:bob", 20_000) {
            HandshakeOfferDecision::RateLimited { retry_after_ms } => {
                assert!(retry_after_ms > 0);
            }
            other => panic!("expected rate limited, got {other:?}"),
        }
        assert_eq!(
            gate.evaluate_incoming_offer("did:nxf:bob", 70_500),
            HandshakeOfferDecision::Allow
        );
    }

    #[test]
    fn request_gate_rate_limits_repeated_outgoing_offers() {
        let mut gate = HandshakeRequestGate::default();
        assert_eq!(
            gate.evaluate_outgoing_offer("did:nxf:bob", 1_000),
            OutgoingHandshakeOfferDecision::Allow
        );
        match gate.evaluate_outgoing_offer("did:nxf:bob", 20_000) {
            OutgoingHandshakeOfferDecision::RateLimited { retry_after_ms } => {
                assert!(retry_after_ms > 0);
            }
            other => panic!("expected outgoing rate limited, got {other:?}"),
        }
        assert_eq!(
            gate.evaluate_outgoing_offer("did:nxf:bob", 70_500),
            OutgoingHandshakeOfferDecision::Allow
        );
    }

    #[test]
    fn request_gate_persists_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("handshake_request_gate.json");
        let persist_key = [13u8; 32];
        let mut gate = HandshakeRequestGate::load_with_persist_key(Some(&path), Some(persist_key));
        gate.block_member("did:nxf:alice").unwrap();
        gate.set_block_all(true).unwrap();

        let restored = HandshakeRequestGate::load_with_persist_key(Some(&path), Some(persist_key));
        assert!(restored.block_all);
        assert!(restored.is_member_blocked("did:nxf:alice"));
    }

    #[test]
    fn legacy_normal_path_is_discarded_for_safe_gate() {
        let dir = tempdir().unwrap();
        let legacy_path = dir.path().join("handshake_request_gate.json");
        let safe_path = dir.path().join("handshake_request_gate_safe.json");

        let mut gate = HandshakeRequestGate::new(Some(&legacy_path));
        gate.block_member("did:nxf:alice").unwrap();

        let restored = HandshakeRequestGate::load_with_persist_key(Some(&safe_path), None);
        assert!(!restored.is_member_blocked("did:nxf:alice"));
        assert!(!safe_path.exists());
        assert!(!legacy_path.exists());
    }
}

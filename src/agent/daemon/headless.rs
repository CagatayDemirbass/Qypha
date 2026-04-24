use super::*;
use chrono::Utc;
use serde::Serialize;
use std::path::Path;

pub(crate) const HEADLESS_DIRECT_PEERS_BEGIN: &str = "DIRECT_PEERS_BEGIN";
pub(crate) const HEADLESS_DIRECT_PEERS_END: &str = "DIRECT_PEERS_END";
pub(crate) const HEADLESS_DIRECT_PEERS_EMPTY: &str = "DIRECT_PEERS_EMPTY";
pub(crate) const HEADLESS_DIRECT_PEER: &str = "DIRECT_PEER";
pub(crate) const HEADLESS_WHOAMI: &str = "WHOAMI";
pub(crate) const HEADLESS_INVITE_RESULT: &str = "INVITE_RESULT";
pub(crate) const HEADLESS_DIRECT_MESSAGE_EVENT: &str = "DIRECT_MESSAGE_EVENT";
pub(crate) const HEADLESS_DIRECT_PEER_EVENT: &str = "DIRECT_PEER_EVENT";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeadlessDirectPeerSnapshot {
    pub(crate) name: String,
    pub(crate) did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) canonical_did: Option<String>,
    pub(crate) peer_id: Option<String>,
    pub(crate) status: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeadlessWhoAmISnapshot {
    pub(crate) name: String,
    pub(crate) did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) contact_did: Option<String>,
    pub(crate) peer_id: String,
    pub(crate) transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iroh_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) onion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) relay_routes: Option<u64>,
    pub(crate) direct_peers: usize,
    pub(crate) groups: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeadlessInviteResult {
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<GroupMailboxSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeadlessDirectMessageEvent {
    pub(crate) direction: String,
    pub(crate) peer_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) peer_contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) peer_canonical_did: Option<String>,
    pub(crate) peer_name: String,
    pub(crate) message: String,
    pub(crate) ts_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeadlessDirectPeerEvent {
    pub(crate) event: String,
    pub(crate) did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) contact_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) canonical_did: Option<String>,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) peer_id: Option<String>,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    pub(crate) ts_ms: i64,
}

pub(crate) fn headless_enabled() -> bool {
    std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false)
}

pub(crate) fn emit_headless_direct_peers(agent_data_dir: &Path, peer_list: &[PeerInfo]) {
    if !headless_enabled() {
        return;
    }
    if peer_list.is_empty() {
        println!("{}", HEADLESS_DIRECT_PEERS_EMPTY);
        return;
    }

    println!("{}", HEADLESS_DIRECT_PEERS_BEGIN);
    for peer in peer_list {
        let visible_did = crate::agent::contact_identity::displayed_did(&peer.did);
        let payload = HeadlessDirectPeerSnapshot {
            name: peer.name.clone(),
            did: visible_did.clone(),
            contact_did: Some(
                crate::agent::contact_identity::cached_peer_contact_did(agent_data_dir, &peer.did)
                    .unwrap_or(visible_did),
            ),
            canonical_did: Some(peer.did.clone()),
            peer_id: Some(peer.peer_id.to_string()),
            status: if peer.x25519_public_key.is_some() && peer.verifying_key.is_some() {
                "ready".to_string()
            } else {
                "connecting".to_string()
            },
        };
        if let Ok(encoded) = serde_json::to_string(&payload) {
            println!("{} {}", HEADLESS_DIRECT_PEER, encoded);
        }
    }
    println!("{}", HEADLESS_DIRECT_PEERS_END);
}

pub(crate) fn emit_headless_direct_peer_roster(
    agent_data_dir: &Path,
    roster: &[DirectPeerRosterEntry],
) {
    if !headless_enabled() {
        return;
    }
    if roster.is_empty() {
        println!("{}", HEADLESS_DIRECT_PEERS_EMPTY);
        return;
    }

    println!("{}", HEADLESS_DIRECT_PEERS_BEGIN);
    for entry in roster {
        let visible_did = crate::agent::contact_identity::displayed_did(&entry.did);
        let payload = HeadlessDirectPeerSnapshot {
            name: entry.name.clone(),
            did: visible_did.clone(),
            contact_did: Some(
                crate::agent::contact_identity::cached_peer_contact_did(agent_data_dir, &entry.did)
                    .unwrap_or(visible_did),
            ),
            canonical_did: Some(entry.did.clone()),
            peer_id: entry.peer_id.clone(),
            status: if entry.online {
                if entry.ready {
                    "ready".to_string()
                } else {
                    "connecting".to_string()
                }
            } else {
                "offline".to_string()
            },
        };
        if let Ok(encoded) = serde_json::to_string(&payload) {
            println!("{} {}", HEADLESS_DIRECT_PEER, encoded);
        }
    }
    println!("{}", HEADLESS_DIRECT_PEERS_END);
}

pub(crate) fn emit_headless_whoami(snapshot: HeadlessWhoAmISnapshot) {
    if !headless_enabled() {
        return;
    }
    if let Ok(encoded) = serde_json::to_string(&snapshot) {
        println!("{} {}", HEADLESS_WHOAMI, encoded);
    }
}

pub(crate) fn emit_headless_invite_success(
    kind: &str,
    code: &str,
    group: Option<&GroupMailboxSummary>,
) {
    emit_headless_invite_result(HeadlessInviteResult {
        kind: kind.to_string(),
        code: Some(code.to_string()),
        error: None,
        group: group.cloned(),
    });
}

pub(crate) fn emit_headless_invite_error(
    kind: &str,
    error: impl Into<String>,
    group: Option<&GroupMailboxSummary>,
) {
    emit_headless_invite_result(HeadlessInviteResult {
        kind: kind.to_string(),
        code: None,
        error: Some(error.into()),
        group: group.cloned(),
    });
}

fn emit_headless_invite_result(payload: HeadlessInviteResult) {
    if !headless_enabled() {
        return;
    }
    if let Ok(encoded) = serde_json::to_string(&payload) {
        println!("{} {}", HEADLESS_INVITE_RESULT, encoded);
    }
}

pub(crate) fn emit_headless_direct_message_event(
    direction: &str,
    peer_did: &str,
    peer_name: &str,
    message: &str,
) {
    if !headless_enabled() {
        return;
    }
    if peer_did.trim().is_empty() || message.trim().is_empty() {
        return;
    }
    let visible_did = crate::agent::contact_identity::displayed_did(peer_did.trim());
    let payload = HeadlessDirectMessageEvent {
        direction: direction.trim().to_string(),
        peer_did: visible_did.clone(),
        peer_contact_did: Some(visible_did),
        peer_canonical_did: Some(peer_did.trim().to_string()),
        peer_name: peer_name.trim().to_string(),
        message: message.to_string(),
        ts_ms: Utc::now().timestamp_millis().max(0),
    };
    if let Ok(encoded) = serde_json::to_string(&payload) {
        println!("{} {}", HEADLESS_DIRECT_MESSAGE_EVENT, encoded);
    }
}

pub(crate) fn emit_headless_direct_peer_event(
    event: &str,
    did: &str,
    name: &str,
    peer_id: Option<&str>,
    status: &str,
    reason: Option<&str>,
) {
    if !headless_enabled() {
        return;
    }
    if did.trim().is_empty() {
        return;
    }
    let visible_did = crate::agent::contact_identity::displayed_did(did.trim());
    let payload = HeadlessDirectPeerEvent {
        event: event.trim().to_string(),
        did: visible_did.clone(),
        contact_did: Some(visible_did),
        canonical_did: Some(did.trim().to_string()),
        name: name.trim().to_string(),
        peer_id: peer_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        status: status.trim().to_string(),
        reason: reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        ts_ms: Utc::now().timestamp_millis().max(0),
    };
    if let Ok(encoded) = serde_json::to_string(&payload) {
        println!("{} {}", HEADLESS_DIRECT_PEER_EVENT, encoded);
    }
}

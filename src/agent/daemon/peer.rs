use dashmap::DashMap;
use std::collections::HashMap;

use crate::control_plane::audit::LogMode;
use crate::network::peer_store::{sanitize_known_peer, KnownPeer, PeerStore};

#[derive(Debug, Clone)]
pub(crate) struct PeerInfo {
    pub(crate) peer_id: libp2p::PeerId,
    pub(crate) did: String,
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) onion_address: Option<String>,
    pub(crate) tcp_address: Option<String>,
    pub(crate) iroh_endpoint_addr: Option<String>,
    pub(crate) onion_port: u16,
    pub(crate) x25519_public_key: Option<[u8; 32]>,
    pub(crate) kyber_public_key: Option<Vec<u8>>,
    pub(crate) verifying_key: Option<[u8; 32]>,
    pub(crate) aegis_supported: bool,
    pub(crate) ratchet_dh_public: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub(crate) struct IrohPeerLiveness {
    pub(crate) connected_at: tokio::time::Instant,
    pub(crate) last_activity: tokio::time::Instant,
    pub(crate) failed_keepalives: u8,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct IrohHandshakeSyncState {
    pub(crate) sent_message_ids: Vec<String>,
    pub(crate) peer_acknowledged_live_session: bool,
    pub(crate) last_received_message_id: Option<String>,
}

pub(crate) type IrohAuthenticatedSessionMap = DashMap<String, usize>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveIncomingIrohTransfer {
    pub(crate) session_id: String,
    pub(crate) sender_did: String,
    pub(crate) sender_name: String,
    pub(crate) total_chunks: usize,
    pub(crate) received_chunks: usize,
    pub(crate) last_progress_at: tokio::time::Instant,
    pub(crate) pause_notified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IrohHandshakeState {
    SuppressedUntilValidated,
    SentAwaitingConnectionObservation,
    SentForSession(tokio::time::Instant),
}

pub(crate) type IrohHandshakeTracker = HashMap<libp2p::PeerId, IrohHandshakeState>;

pub(crate) struct PendingIrohReconnect {
    pub(crate) did: String,
    pub(crate) name: String,
    pub(crate) iroh_endpoint_addr_json: String,
    pub(crate) encryption_public_key_hex: Option<String>,
    pub(crate) verifying_key_hex: Option<String>,
    pub(crate) kyber_public_key_hex: Option<String>,
    pub(crate) next_attempt_at: tokio::time::Instant,
    pub(crate) attempts: u32,
    pub(crate) force_replace: bool,
}

#[derive(Clone)]
pub(crate) struct PendingTorReconnect {
    pub(crate) did: String,
    pub(crate) name: String,
    pub(crate) peer_id: String,
    pub(crate) onion_address: String,
    pub(crate) onion_port: u16,
    pub(crate) next_attempt_at: tokio::time::Instant,
    pub(crate) attempts: u32,
    pub(crate) inflight: bool,
}

pub(crate) fn should_persist_known_peer(
    log_mode: &LogMode,
    existing: Option<&KnownPeer>,
    trusted_new_peer: bool,
) -> bool {
    match log_mode {
        LogMode::Ghost => false,
        LogMode::Safe => existing.is_some() || trusted_new_peer,
    }
}

pub(crate) fn desired_auto_reconnect(log_mode: &LogMode, existing: Option<&KnownPeer>) -> bool {
    match log_mode {
        LogMode::Ghost => false,
        LogMode::Safe => existing.map(|peer| peer.auto_reconnect).unwrap_or(true),
    }
}

pub(crate) fn build_known_peer(
    peer: &PeerInfo,
    existing: Option<&KnownPeer>,
    auto_reconnect: bool,
) -> KnownPeer {
    sanitize_known_peer(KnownPeer {
        did: peer.did.clone(),
        name: peer.name.clone(),
        role: peer.role.clone(),
        peer_id: peer.peer_id.to_string(),
        onion_address: peer
            .onion_address
            .clone()
            .or_else(|| existing.and_then(|kp| kp.onion_address.clone())),
        tcp_address: peer
            .tcp_address
            .clone()
            .or_else(|| existing.and_then(|kp| kp.tcp_address.clone())),
        iroh_endpoint_addr: peer
            .iroh_endpoint_addr
            .clone()
            .or_else(|| existing.and_then(|kp| kp.iroh_endpoint_addr.clone())),
        onion_port: if peer.onion_port == 0 {
            existing.map_or(9090, |kp| kp.onion_port)
        } else {
            peer.onion_port
        },
        encryption_public_key_hex: peer
            .x25519_public_key
            .map(hex::encode)
            .or_else(|| existing.and_then(|kp| kp.encryption_public_key_hex.clone())),
        verifying_key_hex: peer
            .verifying_key
            .map(hex::encode)
            .or_else(|| existing.and_then(|kp| kp.verifying_key_hex.clone())),
        kyber_public_key_hex: peer
            .kyber_public_key
            .as_ref()
            .map(hex::encode)
            .or_else(|| existing.and_then(|kp| kp.kyber_public_key_hex.clone())),
        last_seen: chrono::Utc::now().timestamp() as u64,
        auto_reconnect,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DirectPeerRosterEntry {
    pub(crate) did: String,
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) peer_id: Option<String>,
    pub(crate) online: bool,
    pub(crate) ready: bool,
    pub(crate) paired: bool,
    pub(crate) auto_reconnect: bool,
}

pub(crate) fn collect_direct_peer_roster_entries(
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
    known_peers: &[KnownPeer],
) -> Vec<DirectPeerRosterEntry> {
    let mut by_did: HashMap<String, DirectPeerRosterEntry> = HashMap::new();

    for known in known_peers {
        by_did.insert(
            known.did.clone(),
            DirectPeerRosterEntry {
                did: known.did.clone(),
                name: known.name.clone(),
                role: known.role.clone(),
                peer_id: (!known.peer_id.trim().is_empty()).then(|| known.peer_id.clone()),
                online: false,
                ready: false,
                paired: true,
                auto_reconnect: known.auto_reconnect,
            },
        );
    }

    for entry in peers.iter() {
        let peer = entry.value();
        if !super::selectors::is_direct_peer(peer, direct_peer_dids) {
            continue;
        }
        let roster_entry =
            by_did
                .entry(peer.did.clone())
                .or_insert_with(|| DirectPeerRosterEntry {
                    did: peer.did.clone(),
                    name: peer.name.clone(),
                    role: peer.role.clone(),
                    peer_id: Some(peer.peer_id.to_string()),
                    online: true,
                    ready: peer.x25519_public_key.is_some() && peer.verifying_key.is_some(),
                    paired: false,
                    auto_reconnect: false,
                });
        roster_entry.name = peer.name.clone();
        roster_entry.role = peer.role.clone();
        roster_entry.peer_id = Some(peer.peer_id.to_string());
        roster_entry.online = true;
        roster_entry.ready = peer.x25519_public_key.is_some() && peer.verifying_key.is_some();
    }

    let mut roster = by_did.into_values().collect::<Vec<_>>();
    roster.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.did.cmp(&b.did))
    });
    roster
}

pub(crate) fn live_peer_ids_for_did(
    peers: &DashMap<String, PeerInfo>,
    did: &str,
) -> Vec<libp2p::PeerId> {
    peers
        .iter()
        .filter(|entry| entry.value().did == did)
        .map(|entry| entry.value().peer_id)
        .collect()
}

pub(crate) fn known_peer_from_live_iroh_peer(peer: &PeerInfo) -> Option<KnownPeer> {
    let iroh_endpoint_addr = peer.iroh_endpoint_addr.clone()?;
    Some(sanitize_known_peer(KnownPeer {
        did: peer.did.clone(),
        name: peer.name.clone(),
        role: peer.role.clone(),
        peer_id: peer.peer_id.to_string(),
        onion_address: peer.onion_address.clone(),
        tcp_address: peer.tcp_address.clone(),
        iroh_endpoint_addr: Some(iroh_endpoint_addr),
        onion_port: if peer.onion_port == 0 {
            9090
        } else {
            peer.onion_port
        },
        encryption_public_key_hex: peer.x25519_public_key.map(hex::encode),
        verifying_key_hex: peer.verifying_key.map(hex::encode),
        kyber_public_key_hex: peer.kyber_public_key.as_ref().map(hex::encode),
        last_seen: chrono::Utc::now().timestamp() as u64,
        auto_reconnect: true,
    }))
}

pub(crate) fn known_peer_from_authenticated_live_iroh_peer(peer: &PeerInfo) -> Option<KnownPeer> {
    peer.verifying_key?;
    known_peer_from_live_iroh_peer(peer)
}

fn known_peer_matches_live_iroh_endpoint_identity(known: &KnownPeer, peer_id: &str) -> bool {
    known
        .iroh_endpoint_addr
        .as_deref()
        .is_some_and(|endpoint_addr_json| {
            serde_json::from_str::<iroh::EndpointAddr>(endpoint_addr_json)
                .ok()
                .map(|endpoint_addr| {
                    crate::network::iroh_transport::peer_id_from_endpoint_id(&endpoint_addr.id)
                        .to_string()
                })
                .as_deref()
                == Some(peer_id)
        })
}

fn known_peer_matches_live_peer_id_hint(known: &KnownPeer, peer_id: &str) -> bool {
    known.peer_id == peer_id
}

pub(crate) fn known_peer_for_live_peer_id(
    peer_store: &PeerStore,
    peer_id: &libp2p::PeerId,
) -> Option<KnownPeer> {
    let peer_id = peer_id.to_string();
    let all_peers = peer_store.all_peers();

    all_peers
        .iter()
        .find(|known| known_peer_matches_live_iroh_endpoint_identity(known, &peer_id))
        .map(|known| (*known).clone())
        .or_else(|| {
            all_peers
                .iter()
                .find(|known| known_peer_matches_live_peer_id_hint(known, &peer_id))
                .map(|known| (*known).clone())
        })
}

pub(crate) fn bound_live_peer_slot_matches_did(
    peers: &DashMap<String, PeerInfo>,
    peer_id: &libp2p::PeerId,
    sender_did: &str,
) -> bool {
    peers
        .get(&peer_id.to_string())
        .is_some_and(|peer| peer.did == sender_did && !peer.did.is_empty())
}

pub(crate) fn should_locally_initiate_tor_reconnect(local_did: &str, peer_did: &str) -> bool {
    // Tor/libp2p reconnect is single-initiator on purpose.
    // When both sides proactively dial at the same time, loopback bridge dials
    // can race each other and end up in self/duplicate-connection churn.
    // A stable DID ordering gives us one deterministic dialer without adding
    // any extra persisted coordination state.
    if local_did.is_empty() || peer_did.is_empty() {
        return true;
    }

    local_did < peer_did
}

pub(crate) fn reconnecting_iroh_placeholder(
    peer_id: libp2p::PeerId,
    known: &KnownPeer,
) -> PeerInfo {
    let x25519_public_key = known
        .encryption_public_key_hex
        .as_ref()
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Some(key)
            } else {
                None
            }
        });
    PeerInfo {
        peer_id,
        did: known.did.clone(),
        name: known.name.clone(),
        role: "unknown".to_string(),
        onion_address: known.onion_address.clone(),
        tcp_address: known.tcp_address.clone(),
        iroh_endpoint_addr: known.iroh_endpoint_addr.clone(),
        onion_port: known.onion_port,
        x25519_public_key,
        kyber_public_key: known
            .kyber_public_key_hex
            .as_ref()
            .and_then(|hex_str| hex::decode(hex_str).ok()),
        // Reconnect placeholders may reuse persisted routing/encryption hints,
        // but they must not look like an authenticated live peer before the
        // new transport session proves itself again.
        verifying_key: None,
        aegis_supported: false,
        ratchet_dh_public: None,
    }
}

pub(crate) fn demote_iroh_peer_for_live_reauthentication(peer: &mut PeerInfo) {
    // These fields are bound to the currently authenticated live iroh session.
    // A newly established transport connection must re-prove them before we
    // accept any non-handshake traffic on that exact peer slot.
    peer.verifying_key = None;
    peer.aegis_supported = false;
    peer.ratchet_dh_public = None;
}

pub(crate) fn print_auto_reconnect_state(did: &str, enabled: bool) {
    let headless = std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false);
    if headless {
        println!("AUTO_RECONNECT_SET:{}:{}", did, enabled);
    }
}

pub(crate) fn observe_iroh_peer_connection(
    liveness: &DashMap<String, IrohPeerLiveness>,
    handshake_tracker: &mut IrohHandshakeTracker,
    peer_id: &libp2p::PeerId,
) {
    let now = tokio::time::Instant::now();
    let key = peer_id.to_string();
    let connected_at = if let Some(mut state) = liveness.get_mut(&key) {
        state.last_activity = now;
        state.failed_keepalives = 0;
        state.connected_at
    } else {
        liveness.insert(
            key,
            IrohPeerLiveness {
                connected_at: now,
                last_activity: now,
                failed_keepalives: 0,
            },
        );
        now
    };
    if matches!(
        handshake_tracker.get(peer_id),
        Some(IrohHandshakeState::SentAwaitingConnectionObservation)
    ) {
        handshake_tracker.insert(
            peer_id.to_owned(),
            IrohHandshakeState::SentForSession(connected_at),
        );
    }
}

pub(crate) fn mark_iroh_peer_active(
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
) {
    let now = tokio::time::Instant::now();
    let key = peer_id.to_string();
    if let Some(mut state) = liveness.get_mut(&key) {
        state.last_activity = now;
        state.failed_keepalives = 0;
    } else {
        liveness.insert(
            key,
            IrohPeerLiveness {
                connected_at: now,
                last_activity: now,
                failed_keepalives: 0,
            },
        );
    }
}

pub(crate) fn iroh_peer_recently_active(
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
    window: tokio::time::Duration,
) -> bool {
    liveness
        .get(&peer_id.to_string())
        .is_some_and(|state| state.last_activity.elapsed() < window)
}

pub(crate) fn note_iroh_keepalive_failure(
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
) -> u8 {
    let key = peer_id.to_string();
    if let Some(mut state) = liveness.get_mut(&key) {
        state.failed_keepalives = state.failed_keepalives.saturating_add(1);
        state.failed_keepalives
    } else {
        liveness.insert(
            key,
            IrohPeerLiveness {
                connected_at: tokio::time::Instant::now(),
                last_activity: tokio::time::Instant::now(),
                failed_keepalives: 1,
            },
        );
        1
    }
}

pub(crate) fn queue_iroh_reconnect(
    pending: &mut HashMap<String, PendingIrohReconnect>,
    known: &KnownPeer,
    force_replace: bool,
) -> bool {
    let did = known.did.clone();
    let now = tokio::time::Instant::now();
    let mut inserted = false;
    let entry = pending.entry(did.clone()).or_insert_with(|| {
        inserted = true;
        PendingIrohReconnect {
            did: did.clone(),
            name: known.name.clone(),
            iroh_endpoint_addr_json: known.iroh_endpoint_addr.clone().unwrap_or_default(),
            encryption_public_key_hex: known.encryption_public_key_hex.clone(),
            verifying_key_hex: known.verifying_key_hex.clone(),
            kyber_public_key_hex: known.kyber_public_key_hex.clone(),
            next_attempt_at: now,
            attempts: 0,
            force_replace,
        }
    });
    let escalated = !entry.force_replace && force_replace;
    entry.name = known.name.clone();
    if let Some(ref endpoint) = known.iroh_endpoint_addr {
        entry.iroh_endpoint_addr_json = endpoint.clone();
    }
    entry.encryption_public_key_hex = known.encryption_public_key_hex.clone();
    entry.verifying_key_hex = known.verifying_key_hex.clone();
    entry.kyber_public_key_hex = known.kyber_public_key_hex.clone();
    entry.next_attempt_at = now;
    entry.force_replace |= force_replace;
    inserted || escalated
}

pub(crate) fn queue_tor_reconnect(
    pending: &mut HashMap<String, PendingTorReconnect>,
    known: &KnownPeer,
    force_immediate: bool,
) -> bool {
    let Some(onion_address) = known.onion_address.clone() else {
        return false;
    };

    let did = known.did.clone();
    let now = tokio::time::Instant::now();
    let mut inserted = false;
    let entry = pending.entry(did.clone()).or_insert_with(|| {
        inserted = true;
        PendingTorReconnect {
            did: did.clone(),
            name: known.name.clone(),
            peer_id: known.peer_id.clone(),
            onion_address: onion_address.clone(),
            onion_port: known.onion_port,
            next_attempt_at: now,
            attempts: 0,
            inflight: false,
        }
    });
    entry.name = known.name.clone();
    entry.peer_id = known.peer_id.clone();
    entry.onion_address = onion_address;
    entry.onion_port = known.onion_port;
    let escalated =
        force_immediate && (entry.inflight || entry.next_attempt_at > now || entry.attempts != 0);
    if force_immediate {
        entry.next_attempt_at = now;
        entry.attempts = 0;
        entry.inflight = false;
    }
    inserted || escalated
}

pub(crate) fn queue_tor_reconnect_for_local_role(
    pending: &mut HashMap<String, PendingTorReconnect>,
    known: &KnownPeer,
    local_did: &str,
    preferred_delay: tokio::time::Duration,
    fallback_delay: tokio::time::Duration,
    force_reset: bool,
) -> bool {
    let queued = queue_tor_reconnect(pending, known, force_reset);
    if queued || force_reset {
        if let Some(entry) = pending.get_mut(&known.did) {
            let delay = if should_locally_initiate_tor_reconnect(local_did, &known.did) {
                preferred_delay
            } else {
                fallback_delay
            };
            entry.next_attempt_at = tokio::time::Instant::now() + delay;
        }
    }
    queued
}

pub(crate) fn clear_tor_reconnect_inflight(
    pending: &mut HashMap<String, PendingTorReconnect>,
    did: &str,
) {
    if let Some(entry) = pending.get_mut(did) {
        entry.inflight = false;
    }
}

pub(crate) fn next_due_tor_reconnect_did(
    pending: &HashMap<String, PendingTorReconnect>,
    now: tokio::time::Instant,
) -> Option<String> {
    next_due_tor_reconnect_dids(pending, now, 1)
        .into_iter()
        .next()
}

pub(crate) fn next_due_tor_reconnect_dids(
    pending: &HashMap<String, PendingTorReconnect>,
    now: tokio::time::Instant,
    limit: usize,
) -> Vec<String> {
    let mut ready: Vec<(&String, &PendingTorReconnect)> = pending
        .iter()
        .filter(|(_, reconnect)| !reconnect.inflight && reconnect.next_attempt_at <= now)
        .collect();
    ready.sort_by_key(|(did, reconnect)| (reconnect.next_attempt_at, (*did).clone()));
    ready
        .into_iter()
        .take(limit)
        .map(|(did, _)| did.clone())
        .collect()
}

pub(crate) fn tor_reconnect_backoff(attempts: u32) -> tokio::time::Duration {
    let secs = match attempts {
        0 | 1 => 5,
        2 => 10,
        3 => 20,
        4 => 30,
        _ => 60,
    };
    tokio::time::Duration::from_secs(secs)
}

pub(crate) fn schedule_tor_reconnect_attempt(
    pending: &mut HashMap<String, PendingTorReconnect>,
    did: &str,
) -> Option<PendingTorReconnect> {
    let now = tokio::time::Instant::now();
    let entry = pending.get_mut(did)?;
    entry.inflight = true;
    entry.attempts = entry.attempts.saturating_add(1);
    entry.next_attempt_at = now + tor_reconnect_backoff(entry.attempts);
    Some(PendingTorReconnect {
        did: entry.did.clone(),
        name: entry.name.clone(),
        peer_id: entry.peer_id.clone(),
        onion_address: entry.onion_address.clone(),
        onion_port: entry.onion_port,
        next_attempt_at: entry.next_attempt_at,
        attempts: entry.attempts,
        inflight: entry.inflight,
    })
}

pub(crate) fn mark_active_incoming_iroh_transfers_paused(
    transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    sender_did: &str,
) -> Vec<ActiveIncomingIrohTransfer> {
    let mut paused = Vec::new();

    for mut entry in transfers.iter_mut() {
        if entry.sender_did == sender_did && !entry.pause_notified {
            entry.pause_notified = true;
            paused.push((*entry).clone());
        }
    }

    paused.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    paused
}

pub(crate) fn has_active_incoming_iroh_transfer_for_sender(
    transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    sender_did: &str,
) -> bool {
    transfers
        .iter()
        .any(|entry| entry.sender_did == sender_did && !entry.sender_did.is_empty())
}

pub(crate) fn has_pending_chunk_transfer_for_peer_did(
    pending_chunk_transfers: &HashMap<String, super::PendingChunkTransfer>,
    peer_did: &str,
) -> bool {
    pending_chunk_transfers
        .values()
        .any(|transfer| transfer.peer_did == peer_did && !transfer.peer_did.is_empty())
}

pub(crate) fn stalled_incoming_iroh_transfer_sender_dids(
    transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    stall_after: tokio::time::Duration,
) -> Vec<String> {
    let mut sender_dids = std::collections::BTreeSet::new();

    for entry in transfers.iter() {
        let transfer = entry.value();
        if !transfer.pause_notified && transfer.last_progress_at.elapsed() >= stall_after {
            sender_dids.insert(transfer.sender_did.clone());
        }
    }

    sender_dids.into_iter().collect()
}

pub(crate) fn is_trusted_peer_identity(
    sender_did: &str,
    peers: &DashMap<String, PeerInfo>,
    peer_store: &PeerStore,
) -> bool {
    if peer_store.get(sender_did).is_some() {
        return true;
    }

    peers
        .iter()
        .any(|entry| entry.value().did == sender_did && !entry.value().did.is_empty())
}

pub(crate) fn should_auto_send_live_handshake(
    peer_id: &libp2p::PeerId,
    peers: &DashMap<String, PeerInfo>,
    invite_proofs: &DashMap<String, String>,
) -> bool {
    let key = peer_id.to_string();
    invite_proofs.contains_key(&key) || peers.get(&key).is_some_and(|peer| !peer.did.is_empty())
}

pub(crate) fn should_auto_send_iroh_handshake(
    peer_id: &libp2p::PeerId,
    peers: &DashMap<String, PeerInfo>,
    invite_proofs: &DashMap<String, String>,
) -> bool {
    should_auto_send_live_handshake(peer_id, peers, invite_proofs)
}

pub(crate) fn should_send_iroh_handshake_for_live_session(
    handshake_tracker: &IrohHandshakeTracker,
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
) -> bool {
    let connected_at = liveness
        .get(&peer_id.to_string())
        .map(|state| state.connected_at);
    let Some(connected_at) = connected_at else {
        return false;
    };

    match handshake_tracker.get(peer_id) {
        Some(IrohHandshakeState::SuppressedUntilValidated)
        | Some(IrohHandshakeState::SentAwaitingConnectionObservation) => false,
        Some(IrohHandshakeState::SentForSession(sent_at)) => *sent_at != connected_at,
        None => true,
    }
}

pub(crate) fn record_iroh_handshake_sent(
    handshake_tracker: &mut IrohHandshakeTracker,
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
) {
    if let Some(connected_at) = liveness
        .get(&peer_id.to_string())
        .map(|state| state.connected_at)
    {
        handshake_tracker.insert(
            peer_id.to_owned(),
            IrohHandshakeState::SentForSession(connected_at),
        );
    } else {
        handshake_tracker.insert(
            peer_id.to_owned(),
            IrohHandshakeState::SentAwaitingConnectionObservation,
        );
    }
}

pub(crate) fn suppress_iroh_handshake_until_validated(
    handshake_tracker: &mut IrohHandshakeTracker,
    peer_id: &libp2p::PeerId,
) {
    handshake_tracker.insert(
        peer_id.to_owned(),
        IrohHandshakeState::SuppressedUntilValidated,
    );
}

pub(crate) fn clear_iroh_handshake_tracking(
    handshake_tracker: &mut IrohHandshakeTracker,
    peer_id: &libp2p::PeerId,
) {
    handshake_tracker.remove(peer_id);
}

pub(crate) fn note_iroh_handshake_message_sent(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
    message_id: &str,
) {
    let key = peer_id.to_string();
    if let Some(mut state) = handshake_sync.get_mut(&key) {
        if !state.sent_message_ids.iter().any(|id| id == message_id) {
            state.sent_message_ids.push(message_id.to_string());
            state.peer_acknowledged_live_session = false;
            if state.sent_message_ids.len() > 8 {
                state.sent_message_ids.remove(0);
            }
        }
    } else {
        handshake_sync.insert(
            key,
            IrohHandshakeSyncState {
                sent_message_ids: vec![message_id.to_string()],
                peer_acknowledged_live_session: false,
                last_received_message_id: None,
            },
        );
    }
}

pub(crate) fn note_iroh_handshake_received(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
    message_id: &str,
) {
    let key = peer_id.to_string();
    if let Some(mut state) = handshake_sync.get_mut(&key) {
        state.last_received_message_id = Some(message_id.to_string());
    } else {
        handshake_sync.insert(
            key,
            IrohHandshakeSyncState {
                sent_message_ids: Vec::new(),
                peer_acknowledged_live_session: false,
                last_received_message_id: Some(message_id.to_string()),
            },
        );
    }
}

pub(crate) fn latest_inbound_iroh_handshake_message_id(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
) -> Option<String> {
    handshake_sync
        .get(&peer_id.to_string())
        .and_then(|state| state.last_received_message_id.clone())
}

pub(crate) fn note_iroh_handshake_ack(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
    ack_message_id: Option<&str>,
) -> bool {
    let Some(ack_message_id) = ack_message_id.filter(|value| !value.trim().is_empty()) else {
        return false;
    };

    let key = peer_id.to_string();
    if let Some(mut state) = handshake_sync.get_mut(&key) {
        if state
            .sent_message_ids
            .last()
            .is_some_and(|id| id == ack_message_id)
        {
            state.peer_acknowledged_live_session = true;
            return true;
        }
    }
    false
}

pub(crate) fn peer_acked_current_iroh_handshake(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
) -> bool {
    handshake_sync
        .get(&peer_id.to_string())
        .is_some_and(|state| {
            !state.sent_message_ids.is_empty() && state.peer_acknowledged_live_session
        })
}

pub(crate) fn clear_iroh_handshake_sync(
    handshake_sync: &DashMap<String, IrohHandshakeSyncState>,
    peer_id: &libp2p::PeerId,
) {
    handshake_sync.remove(&peer_id.to_string());
}

pub(crate) fn note_iroh_authenticated_session(
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    peer_id: &libp2p::PeerId,
    stable_id: usize,
) {
    authenticated_sessions.insert(peer_id.to_string(), stable_id);
}

pub(crate) fn is_authenticated_iroh_session(
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    peer_id: &libp2p::PeerId,
    stable_id: usize,
) -> bool {
    authenticated_sessions
        .get(&peer_id.to_string())
        .is_some_and(|entry| *entry == stable_id)
}

pub(crate) fn clear_iroh_authenticated_session(
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    peer_id: &libp2p::PeerId,
) {
    authenticated_sessions.remove(&peer_id.to_string());
}

pub(crate) fn clear_iroh_authenticated_session_if_matches(
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    peer_id: &libp2p::PeerId,
    stable_id: usize,
) {
    if authenticated_sessions
        .get(&peer_id.to_string())
        .is_some_and(|entry| *entry == stable_id)
    {
        authenticated_sessions.remove(&peer_id.to_string());
    }
}

pub(crate) fn is_iroh_controlled_disconnect_reason(reason: Option<&str>) -> bool {
    reason.is_some_and(|text| {
        text.contains("qypha-policy-disconnect") || text.contains("qypha-manual-disconnect")
    })
}

pub(crate) fn is_iroh_manual_disconnect_reason(reason: Option<&str>) -> bool {
    reason.is_some_and(|text| text.contains("qypha-manual-disconnect"))
}

pub(crate) fn is_iroh_agent_shutdown_reason(reason: Option<&str>) -> bool {
    reason.is_some_and(|text| text.contains("qypha-agent-shutdown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::daemon::{ChunkSource, PendingChunkTransfer};
    use crate::artifact::chunked_transfer;

    fn sample_relay_only_iroh_endpoint_json(seed: u8) -> String {
        crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(seed)
    }

    #[test]
    fn observing_same_live_session_does_not_reopen_handshake_freshness() {
        let liveness = DashMap::new();
        let mut handshake_tracker = IrohHandshakeTracker::new();
        let peer_id = libp2p::PeerId::random();

        mark_iroh_peer_active(&liveness, &peer_id);
        let initial_connected_at = liveness
            .get(&peer_id.to_string())
            .expect("expected liveness after activity")
            .connected_at;

        record_iroh_handshake_sent(&mut handshake_tracker, &liveness, &peer_id);
        assert!(!should_send_iroh_handshake_for_live_session(
            &handshake_tracker,
            &liveness,
            &peer_id
        ));

        observe_iroh_peer_connection(&liveness, &mut handshake_tracker, &peer_id);
        let observed_connected_at = liveness
            .get(&peer_id.to_string())
            .expect("expected liveness after connection observe")
            .connected_at;

        assert_eq!(initial_connected_at, observed_connected_at);
        assert!(!should_send_iroh_handshake_for_live_session(
            &handshake_tracker,
            &liveness,
            &peer_id
        ));
    }

    #[test]
    fn iroh_handshake_tracking_refreshes_for_new_live_session() {
        let liveness = DashMap::new();
        let mut handshake_tracker = IrohHandshakeTracker::new();
        let peer_id = libp2p::PeerId::random();

        observe_iroh_peer_connection(&liveness, &mut handshake_tracker, &peer_id);
        assert!(should_send_iroh_handshake_for_live_session(
            &handshake_tracker,
            &liveness,
            &peer_id
        ));

        record_iroh_handshake_sent(&mut handshake_tracker, &liveness, &peer_id);
        assert!(!should_send_iroh_handshake_for_live_session(
            &handshake_tracker,
            &liveness,
            &peer_id
        ));

        liveness.remove(&peer_id.to_string());
        observe_iroh_peer_connection(&liveness, &mut handshake_tracker, &peer_id);
        assert!(should_send_iroh_handshake_for_live_session(
            &handshake_tracker,
            &liveness,
            &peer_id
        ));
    }

    #[test]
    fn iroh_shutdown_reason_is_distinct_from_manual_disconnect() {
        assert!(is_iroh_agent_shutdown_reason(Some(
            "stream closed: qypha-agent-shutdown"
        )));
        assert!(!is_iroh_agent_shutdown_reason(Some(
            "stream closed: qypha-policy-disconnect"
        )));
        assert!(is_iroh_manual_disconnect_reason(Some(
            "stream closed: qypha-manual-disconnect"
        )));
        assert!(!is_iroh_manual_disconnect_reason(Some(
            "stream closed: qypha-policy-disconnect"
        )));
        assert!(is_iroh_controlled_disconnect_reason(Some(
            "stream closed: qypha-policy-disconnect"
        )));
        assert!(is_iroh_controlled_disconnect_reason(Some(
            "stream closed: qypha-manual-disconnect"
        )));
        assert!(!is_iroh_controlled_disconnect_reason(Some(
            "stream closed: qypha-agent-shutdown"
        )));
    }

    #[test]
    fn iroh_handshake_sync_requires_matching_ack_for_latest_message() {
        let handshake_sync = DashMap::new();
        let peer_id = libp2p::PeerId::random();

        note_iroh_handshake_message_sent(&handshake_sync, &peer_id, "hs_1");
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
        assert!(!note_iroh_handshake_ack(
            &handshake_sync,
            &peer_id,
            Some("different")
        ));
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));

        assert!(note_iroh_handshake_ack(
            &handshake_sync,
            &peer_id,
            Some("hs_1")
        ));
        assert!(peer_acked_current_iroh_handshake(&handshake_sync, &peer_id));

        note_iroh_handshake_message_sent(&handshake_sync, &peer_id, "hs_2");
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
        assert!(!note_iroh_handshake_ack(
            &handshake_sync,
            &peer_id,
            Some("hs_1")
        ));
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
        assert!(note_iroh_handshake_ack(
            &handshake_sync,
            &peer_id,
            Some("hs_2")
        ));
        assert!(peer_acked_current_iroh_handshake(&handshake_sync, &peer_id));

        clear_iroh_handshake_sync(&handshake_sync, &peer_id);
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
    }

    #[test]
    fn iroh_handshake_sync_tracks_latest_inbound_message_id() {
        let handshake_sync = DashMap::new();
        let peer_id = libp2p::PeerId::random();

        assert!(latest_inbound_iroh_handshake_message_id(&handshake_sync, &peer_id).is_none());

        note_iroh_handshake_received(&handshake_sync, &peer_id, "hs_in_1");
        assert_eq!(
            latest_inbound_iroh_handshake_message_id(&handshake_sync, &peer_id).as_deref(),
            Some("hs_in_1")
        );

        note_iroh_handshake_message_sent(&handshake_sync, &peer_id, "hs_out_1");
        assert_eq!(
            latest_inbound_iroh_handshake_message_id(&handshake_sync, &peer_id).as_deref(),
            Some("hs_in_1")
        );

        note_iroh_handshake_received(&handshake_sync, &peer_id, "hs_in_2");
        assert_eq!(
            latest_inbound_iroh_handshake_message_id(&handshake_sync, &peer_id).as_deref(),
            Some("hs_in_2")
        );
    }

    #[test]
    fn auto_handshake_requires_known_peer_or_invite_binding() {
        let peer_id = libp2p::PeerId::random();
        let peers = DashMap::new();
        let invite_proofs = DashMap::new();

        assert!(!should_auto_send_live_handshake(
            &peer_id,
            &peers,
            &invite_proofs
        ));

        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: "did:nxf:test".to_string(),
                name: "agent".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );
        assert!(should_auto_send_live_handshake(
            &peer_id,
            &peers,
            &invite_proofs
        ));

        peers.remove(&peer_id.to_string());
        invite_proofs.insert(peer_id.to_string(), "invite-code".to_string());
        assert!(should_auto_send_live_handshake(
            &peer_id,
            &peers,
            &invite_proofs
        ));
    }

    #[test]
    fn demoting_iroh_peer_requires_live_session_reauthentication() {
        let peer_id = libp2p::PeerId::random();
        let endpoint_json = sample_relay_only_iroh_endpoint_json(51);
        let mut peer = PeerInfo {
            peer_id,
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            x25519_public_key: Some([1u8; 32]),
            kyber_public_key: Some(vec![2u8; 32]),
            verifying_key: Some([3u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([4u8; 32]),
        };

        demote_iroh_peer_for_live_reauthentication(&mut peer);

        assert!(peer.verifying_key.is_none());
        assert!(!peer.aegis_supported);
        assert!(peer.ratchet_dh_public.is_none());
        assert_eq!(peer.did, "did:nxf:test");
        assert!(peer.x25519_public_key.is_some());
        assert!(peer.kyber_public_key.is_some());
    }

    #[test]
    fn authenticated_live_iroh_peer_can_seed_known_peer() {
        let peer_id = libp2p::PeerId::random();
        let endpoint_json = sample_relay_only_iroh_endpoint_json(52);
        let peer = PeerInfo {
            peer_id,
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json.clone()),
            onion_port: 9090,
            x25519_public_key: Some([1u8; 32]),
            kyber_public_key: Some(vec![2u8; 32]),
            verifying_key: Some([3u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([4u8; 32]),
        };

        let known = known_peer_from_authenticated_live_iroh_peer(&peer)
            .expect("authenticated peer should seed a known peer");
        assert_eq!(known.did, "did:nxf:test");
        assert_eq!(
            known.iroh_endpoint_addr.as_deref(),
            Some(endpoint_json.as_str())
        );
        assert_eq!(known.verifying_key_hex, Some(hex::encode([3u8; 32])));
    }

    #[test]
    fn reconnecting_placeholder_requires_live_reauthentication() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(61)),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([1u8; 32])),
            verifying_key_hex: Some(hex::encode([3u8; 32])),
            kyber_public_key_hex: Some(hex::encode([2u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };

        let placeholder = reconnecting_iroh_placeholder(peer_id, &known);
        assert!(placeholder.verifying_key.is_none());
        assert_eq!(placeholder.kyber_public_key, Some(vec![2u8; 32]));
    }

    #[test]
    fn known_peer_lookup_by_live_peer_id_finds_reconnect_seed() {
        let peer_id = libp2p::PeerId::random();
        let mut peer_store = PeerStore::new(None);
        peer_store.upsert(KnownPeer {
            did: "did:nxf:tor-peer".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some(
                "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx".to_string(),
            ),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([9u8; 32])),
            verifying_key_hex: Some(hex::encode([8u8; 32])),
            kyber_public_key_hex: Some(hex::encode([7u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        });

        let known = known_peer_for_live_peer_id(&peer_store, &peer_id)
            .expect("expected persisted known peer for peer id");
        assert_eq!(known.did, "did:nxf:tor-peer");
        assert_eq!(known.name, "tor-peer");
        assert_eq!(known.peer_id, peer_id.to_string());
    }

    #[test]
    fn known_peer_lookup_by_live_peer_id_falls_back_to_iroh_endpoint_identity() {
        let endpoint_json = sample_relay_only_iroh_endpoint_json(78);
        let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(&endpoint_json)
            .expect("expected sample endpoint json");
        let peer_id = crate::network::iroh_transport::peer_id_from_endpoint_id(&endpoint_addr.id);
        let mut peer_store = PeerStore::new(None);
        peer_store.upsert(KnownPeer {
            did: "did:nxf:iroh-peer".to_string(),
            name: "iroh-peer".to_string(),
            role: "agent".to_string(),
            peer_id: "stale-peer-id".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([4u8; 32])),
            verifying_key_hex: Some(hex::encode([5u8; 32])),
            kyber_public_key_hex: Some(hex::encode([6u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        });

        let known = known_peer_for_live_peer_id(&peer_store, &peer_id)
            .expect("expected endpoint-derived known peer match");
        assert_eq!(known.did, "did:nxf:iroh-peer");
        assert_eq!(known.name, "iroh-peer");
        assert_eq!(known.peer_id, "stale-peer-id");
    }

    #[test]
    fn known_peer_lookup_prefers_iroh_endpoint_identity_over_stale_peer_id_hint() {
        let endpoint_json = sample_relay_only_iroh_endpoint_json(79);
        let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(&endpoint_json)
            .expect("expected sample endpoint json");
        let live_peer_id =
            crate::network::iroh_transport::peer_id_from_endpoint_id(&endpoint_addr.id);
        let mut peer_store = PeerStore::new(None);
        peer_store.upsert(KnownPeer {
            did: "did:nxf:stale-hint".to_string(),
            name: "stale-hint".to_string(),
            role: "agent".to_string(),
            peer_id: live_peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(80)),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([1u8; 32])),
            verifying_key_hex: Some(hex::encode([2u8; 32])),
            kyber_public_key_hex: Some(hex::encode([3u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        });
        peer_store.upsert(KnownPeer {
            did: "did:nxf:endpoint-owner".to_string(),
            name: "endpoint-owner".to_string(),
            role: "agent".to_string(),
            peer_id: "different-stale-hint".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([4u8; 32])),
            verifying_key_hex: Some(hex::encode([5u8; 32])),
            kyber_public_key_hex: Some(hex::encode([6u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        });

        let known = known_peer_for_live_peer_id(&peer_store, &live_peer_id)
            .expect("expected endpoint-derived known peer match to win");
        assert_eq!(known.did, "did:nxf:endpoint-owner");
        assert_eq!(known.name, "endpoint-owner");
    }

    #[test]
    fn queue_iroh_reconnect_notifies_only_on_insert_or_escalation() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(77)),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([1u8; 32])),
            verifying_key_hex: Some(hex::encode([3u8; 32])),
            kyber_public_key_hex: Some(hex::encode([2u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };
        let mut pending = HashMap::new();

        assert!(queue_iroh_reconnect(&mut pending, &known, false));
        assert!(!queue_iroh_reconnect(&mut pending, &known, false));
        assert!(queue_iroh_reconnect(&mut pending, &known, true));
        assert!(!queue_iroh_reconnect(&mut pending, &known, true));
    }

    #[test]
    fn stalled_incoming_iroh_transfer_sender_dids_only_returns_unpaused_stalled_senders() {
        let transfers = DashMap::new();
        transfers.insert(
            "sess-stalled".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-stalled".to_string(),
                sender_did: "did:nxf:stalled".to_string(),
                sender_name: "stalled".to_string(),
                total_chunks: 83,
                received_chunks: 29,
                last_progress_at: tokio::time::Instant::now()
                    - tokio::time::Duration::from_secs(10),
                pause_notified: false,
            },
        );
        transfers.insert(
            "sess-fresh".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-fresh".to_string(),
                sender_did: "did:nxf:fresh".to_string(),
                sender_name: "fresh".to_string(),
                total_chunks: 83,
                received_chunks: 30,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: false,
            },
        );
        transfers.insert(
            "sess-paused".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-paused".to_string(),
                sender_did: "did:nxf:paused".to_string(),
                sender_name: "paused".to_string(),
                total_chunks: 83,
                received_chunks: 31,
                last_progress_at: tokio::time::Instant::now()
                    - tokio::time::Duration::from_secs(10),
                pause_notified: true,
            },
        );

        let stalled = stalled_incoming_iroh_transfer_sender_dids(
            &transfers,
            tokio::time::Duration::from_secs(5),
        );
        assert_eq!(stalled, vec!["did:nxf:stalled".to_string()]);
    }

    #[test]
    fn tor_reconnect_uses_single_deterministic_dialer() {
        assert!(should_locally_initiate_tor_reconnect(
            "did:nxf:alice",
            "did:nxf:bob"
        ));
        assert!(!should_locally_initiate_tor_reconnect(
            "did:nxf:bob",
            "did:nxf:alice"
        ));
        assert!(!should_locally_initiate_tor_reconnect(
            "did:nxf:same",
            "did:nxf:same"
        ));
        assert!(should_locally_initiate_tor_reconnect("", "did:nxf:peer"));
    }

    #[test]
    fn active_incoming_pause_notice_dedupes_until_progress_resets_it() {
        let transfers = DashMap::new();
        transfers.insert(
            "sess-1".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-1".to_string(),
                sender_did: "did:nxf:sender".to_string(),
                sender_name: "sender".to_string(),
                total_chunks: 83,
                received_chunks: 20,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: false,
            },
        );

        let first = mark_active_incoming_iroh_transfers_paused(&transfers, "did:nxf:sender");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].received_chunks, 20);
        assert!(
            mark_active_incoming_iroh_transfers_paused(&transfers, "did:nxf:sender").is_empty()
        );

        transfers.insert(
            "sess-1".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-1".to_string(),
                sender_did: "did:nxf:sender".to_string(),
                sender_name: "sender".to_string(),
                total_chunks: 83,
                received_chunks: 21,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: false,
            },
        );

        let second = mark_active_incoming_iroh_transfers_paused(&transfers, "did:nxf:sender");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].received_chunks, 21);
    }

    #[test]
    fn active_incoming_transfer_presence_checks_sender_identity() {
        let transfers = DashMap::new();
        transfers.insert(
            "sess-1".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-1".to_string(),
                sender_did: "did:nxf:sender".to_string(),
                sender_name: "sender".to_string(),
                total_chunks: 83,
                received_chunks: 21,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: true,
            },
        );

        assert!(has_active_incoming_iroh_transfer_for_sender(
            &transfers,
            "did:nxf:sender"
        ));
        assert!(!has_active_incoming_iroh_transfer_for_sender(
            &transfers,
            "did:nxf:other"
        ));
        assert!(!has_active_incoming_iroh_transfer_for_sender(
            &transfers, ""
        ));
    }

    #[test]
    fn pending_chunk_transfer_presence_checks_peer_identity() {
        let sender = crate::crypto::identity::AgentKeyPair::generate("sender", "agent");
        let (session, chunks) = chunked_transfer::prepare_session(
            &sender,
            "did:nxf:peer",
            "payload.bin",
            "confidential",
            b"hello world over tor transfer",
            4,
        )
        .expect("sample transfer session");
        let peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            peer_id.to_string(),
            PendingChunkTransfer {
                peer_id,
                peer_name: "peer".to_string(),
                peer_did: "did:nxf:peer".to_string(),
                session,
                chunk_source: ChunkSource::InMemory(chunks),
                next_chunk: 1,
                chunk_size: 4,
                x25519_pk: [7u8; 32],
                kyber_pk: Some(vec![8u8; 32]),
                ttl: 0,
                path: "/tmp/payload.bin".to_string(),
                packed_mb: 0.0,
                packed_size: 16,
                inflight_request: None,
                retry_count: 0,
                backoff_until: None,
                reconnect_wait_secs: 0,
                reconnecting: false,
                last_bridge_at: tokio::time::Instant::now(),
                bridge_warming: false,
                peer_onion: Some("peerexample123.onion".to_string()),
                peer_onion_port: 9090,
                chunk_jitter_until: None,
                awaiting_receiver_accept: false,
                awaiting_started_at: tokio::time::Instant::now(),
                needs_reinit: false,
            },
        );

        assert!(has_pending_chunk_transfer_for_peer_did(
            &pending,
            "did:nxf:peer"
        ));
        assert!(!has_pending_chunk_transfer_for_peer_did(
            &pending,
            "did:nxf:other"
        ));
        assert!(!has_pending_chunk_transfer_for_peer_did(&pending, ""));
    }

    #[test]
    fn queue_tor_reconnect_keeps_single_pending_entry() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:tor-peer".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("torpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([9u8; 32])),
            verifying_key_hex: Some(hex::encode([8u8; 32])),
            kyber_public_key_hex: Some(hex::encode([7u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };
        let mut pending = HashMap::new();

        assert!(queue_tor_reconnect(&mut pending, &known, false));
        assert!(!queue_tor_reconnect(&mut pending, &known, false));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending["did:nxf:tor-peer"].peer_id, peer_id.to_string());
    }

    #[test]
    fn tor_reconnect_scheduler_marks_attempt_inflight_with_backoff() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:tor-peer".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("torpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let mut pending = HashMap::new();
        queue_tor_reconnect(&mut pending, &known, false);

        let scheduled = schedule_tor_reconnect_attempt(&mut pending, &known.did)
            .expect("expected tor reconnect attempt");
        assert!(scheduled.inflight);
        assert_eq!(scheduled.attempts, 1);
        assert!(next_due_tor_reconnect_did(&pending, tokio::time::Instant::now()).is_none());

        clear_tor_reconnect_inflight(&mut pending, &known.did);
        assert!(!pending[&known.did].inflight);
    }

    #[test]
    fn tor_reconnect_batch_returns_multiple_ready_peers() {
        let now = tokio::time::Instant::now();
        let mut pending = HashMap::new();

        let first = KnownPeer {
            did: "did:nxf:first".to_string(),
            name: "first".to_string(),
            role: "agent".to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("firstpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let second = KnownPeer {
            did: "did:nxf:second".to_string(),
            name: "second".to_string(),
            role: "agent".to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("secondpeeraddress12.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let third = KnownPeer {
            did: "did:nxf:third".to_string(),
            name: "third".to_string(),
            role: "agent".to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("thirdpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };

        queue_tor_reconnect(&mut pending, &first, false);
        queue_tor_reconnect(&mut pending, &second, false);
        queue_tor_reconnect(&mut pending, &third, false);

        pending.get_mut(&first.did).unwrap().next_attempt_at =
            now - tokio::time::Duration::from_secs(2);
        pending.get_mut(&second.did).unwrap().next_attempt_at =
            now - tokio::time::Duration::from_secs(1);
        pending.get_mut(&third.did).unwrap().next_attempt_at =
            now + tokio::time::Duration::from_secs(5);

        assert_eq!(
            next_due_tor_reconnect_dids(&pending, now, 2),
            vec![first.did.clone(), second.did.clone()]
        );
    }

    #[test]
    fn queue_tor_reconnect_force_resets_stale_backoff_and_inflight() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:tor-peer".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("torpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let mut pending = HashMap::new();
        assert!(queue_tor_reconnect(&mut pending, &known, false));

        let _ = schedule_tor_reconnect_attempt(&mut pending, &known.did)
            .expect("expected tor reconnect attempt");
        assert!(pending[&known.did].inflight);
        assert_eq!(pending[&known.did].attempts, 1);

        assert!(queue_tor_reconnect(&mut pending, &known, true));
        assert!(!pending[&known.did].inflight);
        assert_eq!(pending[&known.did].attempts, 0);
        assert!(
            next_due_tor_reconnect_did(&pending, tokio::time::Instant::now()).is_some(),
            "forced reconnect should be immediately due again"
        );
    }

    #[test]
    fn tor_reconnect_role_scheduler_delays_passive_fallback_dialer() {
        let peer_id = libp2p::PeerId::random();
        let known = KnownPeer {
            did: "did:nxf:bob".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("torpeeraddress123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let preferred_delay = tokio::time::Duration::from_secs(5);
        let fallback_delay = tokio::time::Duration::from_secs(15);

        let mut preferred_pending = HashMap::new();
        let before_preferred = tokio::time::Instant::now();
        assert!(queue_tor_reconnect_for_local_role(
            &mut preferred_pending,
            &known,
            "did:nxf:alice",
            preferred_delay,
            fallback_delay,
            false,
        ));
        let preferred_next = preferred_pending[&known.did].next_attempt_at;

        let mut passive_pending = HashMap::new();
        let before_passive = tokio::time::Instant::now();
        assert!(queue_tor_reconnect_for_local_role(
            &mut passive_pending,
            &known,
            "did:nxf:charlie",
            preferred_delay,
            fallback_delay,
            false,
        ));
        let passive_next = passive_pending[&known.did].next_attempt_at;

        assert!(preferred_next >= before_preferred + preferred_delay);
        assert!(passive_next >= before_passive + fallback_delay);
        assert!(passive_next > preferred_next);
    }

    #[test]
    fn unauthenticated_live_iroh_peer_does_not_seed_known_peer() {
        let peer_id = libp2p::PeerId::random();
        let endpoint_json = sample_relay_only_iroh_endpoint_json(53);
        let peer = PeerInfo {
            peer_id,
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            x25519_public_key: Some([1u8; 32]),
            kyber_public_key: Some(vec![2u8; 32]),
            verifying_key: None,
            aegis_supported: false,
            ratchet_dh_public: None,
        };

        assert!(known_peer_from_authenticated_live_iroh_peer(&peer).is_none());
    }

    #[test]
    fn bound_live_peer_slot_match_requires_same_did_on_current_slot() {
        let peers = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: "did:nxf:test".to_string(),
                name: "agent".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        assert!(bound_live_peer_slot_matches_did(
            &peers,
            &peer_id,
            "did:nxf:test"
        ));
        assert!(!bound_live_peer_slot_matches_did(
            &peers,
            &peer_id,
            "did:nxf:other"
        ));
    }

    #[test]
    fn direct_peer_roster_merges_known_and_live_entries() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        let live_peer = PeerInfo {
            peer_id,
            did: "did:nxf:alice".to_string(),
            name: "Alice Live".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: Some([1u8; 32]),
            kyber_public_key: None,
            verifying_key: Some([2u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: None,
        };
        direct_peer_dids.insert(live_peer.did.clone(), true);
        peers.insert(peer_id.to_string(), live_peer);

        let known_only = KnownPeer {
            did: "did:nxf:bob".to_string(),
            name: "Bob".to_string(),
            role: "agent".to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("bobonion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };
        let known_live = KnownPeer {
            did: "did:nxf:alice".to_string(),
            name: "Alice Stored".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        };

        let roster = collect_direct_peer_roster_entries(
            &peers,
            &direct_peer_dids,
            &[known_only, known_live],
        );

        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].did, "did:nxf:alice");
        assert_eq!(roster[0].name, "Alice Live");
        assert!(roster[0].online);
        assert!(roster[0].ready);
        assert!(roster[0].paired);
        assert_eq!(roster[1].did, "did:nxf:bob");
        assert!(!roster[1].online);
        assert!(roster[1].paired);
    }

    #[test]
    fn live_peer_ids_for_did_returns_only_matching_slots() {
        let peers = DashMap::new();
        let alice_id = libp2p::PeerId::random();
        let bob_id = libp2p::PeerId::random();
        peers.insert(
            alice_id.to_string(),
            PeerInfo {
                peer_id: alice_id,
                did: "did:nxf:alice".to_string(),
                name: "Alice".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );
        peers.insert(
            bob_id.to_string(),
            PeerInfo {
                peer_id: bob_id,
                did: "did:nxf:bob".to_string(),
                name: "Bob".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        let ids = live_peer_ids_for_did(&peers, "did:nxf:alice");

        assert_eq!(ids, vec![alice_id]);
    }
}

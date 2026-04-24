use super::incoming_connect_gate::IncomingConnectGate;
use super::*;
use zeroize::Zeroize;

pub(crate) struct IncomingMessageRuntime {
    pub(crate) active_receive_count: Arc<std::sync::atomic::AtomicUsize>,
}

const UNKNOWN_SESSION_STATUS_DEDUP_WINDOW_MS: u64 = 2_000;
const STALE_CHUNK_RECEIVE_SESSION_WINDOW_MS: u64 = 1_800_000;

fn latest_filesystem_activity_ms(path: &std::path::Path) -> u64 {
    fn metadata_mtime_ms(path: &std::path::Path) -> u64 {
        path.metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    let mut newest = metadata_mtime_ms(path);
    let mut stack = vec![path.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let child_path = entry.path();
            newest = newest.max(metadata_mtime_ms(&child_path));
            if child_path.is_dir() {
                stack.push(child_path);
            }
        }
    }
    newest
}

fn stale_orphan_chunk_receive_dirs(
    root: &std::path::Path,
    active_temp_dirs: &std::collections::HashSet<std::path::PathBuf>,
    now_ms: u64,
    stale_after_ms: u64,
) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };

    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| !active_temp_dirs.contains(path))
        .filter(|path| now_ms.saturating_sub(latest_filesystem_activity_ms(path)) > stale_after_ms)
        .collect()
}

fn record_unknown_session_status_notice(
    recent_unknown_session_statuses: &mut std::collections::HashMap<
        (String, String),
        tokio::time::Instant,
    >,
    sender_did: &str,
    session_id: &str,
    now: tokio::time::Instant,
) -> bool {
    recent_unknown_session_statuses.retain(|_, sent_at| {
        now.duration_since(*sent_at)
            < tokio::time::Duration::from_millis(UNKNOWN_SESSION_STATUS_DEDUP_WINDOW_MS)
    });
    let dedupe_key = (sender_did.to_string(), session_id.to_string());
    let should_notify = recent_unknown_session_statuses
        .get(&dedupe_key)
        .is_none_or(|sent_at| {
            now.duration_since(*sent_at)
                >= tokio::time::Duration::from_millis(UNKNOWN_SESSION_STATUS_DEDUP_WINDOW_MS)
        });
    if should_notify {
        recent_unknown_session_statuses.insert(dedupe_key, now);
    }
    should_notify
}

fn should_drop_inactive_iroh_envelope(
    iroh_stable_id: Option<usize>,
    iroh_active_session: Option<bool>,
    msg_type: &MessageKind,
) -> bool {
    matches!(iroh_stable_id, Some(_))
        && matches!(iroh_active_session, Some(false))
        && !matches!(msg_type, MessageKind::DisconnectNotice)
}

fn should_emit_iroh_connected_notice(
    transport_mode: &TransportMode,
    existing_peer: Option<&PeerInfo>,
    sender_did: &str,
    live_session_already_authenticated: bool,
) -> bool {
    let existing_ready_peer = existing_peer.is_some_and(|peer| {
        peer.did == sender_did && peer.x25519_public_key.is_some() && peer.verifying_key.is_some()
    });
    if !existing_ready_peer {
        return true;
    }

    if matches!(transport_mode, TransportMode::Internet) {
        return !live_session_already_authenticated;
    }

    false
}

fn should_send_manual_disconnect_notice_for_handshake_policy(
    locally_manually_disconnected: bool,
    did_explicitly_blocked: bool,
) -> bool {
    locally_manually_disconnected || did_explicitly_blocked
}

fn should_apply_manual_disconnect_policy_after_invite_use_check(
    locally_manually_disconnected: bool,
    did_explicitly_blocked: bool,
    invite_already_used: bool,
) -> bool {
    !invite_already_used
        && should_send_manual_disconnect_notice_for_handshake_policy(
            locally_manually_disconnected,
            did_explicitly_blocked,
        )
}

fn should_allow_trusted_reconnect_probe(
    transport_mode: &TransportMode,
    peer_acked_current_handshake: bool,
    has_existing_ratchet_session: bool,
    ratchet_matches_known_peer: bool,
    hybrid_ready: bool,
) -> bool {
    matches!(transport_mode, TransportMode::Internet | TransportMode::Tor)
        && should_accept_trusted_iroh_reconnect_probe(
            peer_acked_current_handshake,
            has_existing_ratchet_session,
            ratchet_matches_known_peer,
            hybrid_ready,
        )
}

fn should_persist_manual_disconnect_from_notice(kind: DisconnectNoticeKind) -> bool {
    matches!(kind, DisconnectNoticeKind::ManualDisconnect)
}

fn should_allow_preauthenticated_iroh_disconnect_notice(
    msg_type: &MessageKind,
    peer_vk_present: bool,
    authenticated_live_iroh_session: bool,
) -> bool {
    matches!(msg_type, MessageKind::DisconnectNotice)
        && peer_vk_present
        && !authenticated_live_iroh_session
}

fn should_send_tor_peer_supplied_hybrid_followup(
    transport_mode: &TransportMode,
    used_peer_supplied_hybrid_init: bool,
    is_initiator: bool,
    invite_consumer_reciprocal_pending: bool,
) -> TorPeerSuppliedHybridFollowup {
    if !matches!(transport_mode, TransportMode::Tor) || !used_peer_supplied_hybrid_init {
        return TorPeerSuppliedHybridFollowup::None;
    }

    if !invite_consumer_reciprocal_pending {
        return TorPeerSuppliedHybridFollowup::Handshake;
    }

    if is_initiator {
        TorPeerSuppliedHybridFollowup::Bootstrap
    } else {
        TorPeerSuppliedHybridFollowup::Handshake
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TorPeerSuppliedHybridFollowup {
    None,
    Bootstrap,
    Handshake,
}

async fn forget_persisted_peer(peer_store: &Arc<tokio::sync::Mutex<PeerStore>>, did: &str) {
    let mut store = peer_store.lock().await;
    store.remove(did);
    print_auto_reconnect_state(did, false);
}

async fn persisted_peer_verifying_key(
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    did: &str,
) -> Option<[u8; 32]> {
    let store = peer_store.lock().await;
    let known = store.get(did)?;
    let hex_str = known.verifying_key_hex.as_deref()?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn live_peer_verifying_key_for_handshake(
    peers: &DashMap<String, PeerInfo>,
    peer_id: &str,
    sender_did: &str,
) -> Option<[u8; 32]> {
    peers
        .get(peer_id)
        .and_then(|peer| peer.verifying_key)
        .or_else(|| {
            peers
                .iter()
                .find(|entry| entry.value().did == sender_did)
                .and_then(|entry| entry.value().verifying_key)
        })
}

fn should_reject_handshake_verifying_key_continuity(
    trusted_vk: Option<[u8; 32]>,
    handshake_vk: Option<[u8; 32]>,
) -> bool {
    matches!(
        (trusted_vk, handshake_vk),
        (Some(trusted), Some(handshake)) if trusted != handshake
    )
}

pub(crate) struct IncomingMessageContext {
    pub(crate) peers: Arc<DashMap<String, PeerInfo>>,
    pub(crate) invite_proof_by_peer: Arc<DashMap<String, String>>,
    pub(crate) agent_name: String,
    pub(crate) keypair: AgentKeyPair,
    pub(crate) audit: Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) replay_guard: Arc<tokio::sync::Mutex<ReplayGuard>>,
    pub(crate) rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    pub(crate) chunk_rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    pub(crate) log_mode: LogMode,
    pub(crate) peer_store: Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) used_invites: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) used_invites_path: Option<std::path::PathBuf>,
    pub(crate) used_invites_persist_key: Option<[u8; 32]>,
    pub(crate) default_ttl: u64,
    pub(crate) transport_mode: TransportMode,
    pub(crate) our_did: String,
    pub(crate) local_onion_address: Option<String>,
    pub(crate) rbac: Arc<tokio::sync::RwLock<RbacEngine>>,
    pub(crate) ratchet_mgr: Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) pending_hybrid_ratchet_inits: Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_secret: [u8; 32],
    pub(crate) cmd_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) transfer_decisions: Arc<tokio::sync::Mutex<TransferDecisionState>>,
    pub(crate) transfer_start_approvals:
        Arc<tokio::sync::Mutex<HashMap<String, TransferStartApproval>>>,
    pub(crate) pending_contact_requests: Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) incoming_connect_gate: Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) direct_peer_dids: Arc<DashMap<String, bool>>,
    pub(crate) active_chat_target_did: Arc<Mutex<Option<String>>>,
    pub(crate) active_chat_target_group_label: Arc<Mutex<Option<String>>>,
    pub(crate) manual_disconnect_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) remote_offline_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) iroh_peer_liveness: Arc<DashMap<String, IrohPeerLiveness>>,
    pub(crate) iroh_handshake_sync: Arc<DashMap<String, IrohHandshakeSyncState>>,
    pub(crate) iroh_authenticated_sessions: Arc<IrohAuthenticatedSessionMap>,
    pub(crate) active_incoming_iroh_transfers: Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) receive_dir_config: Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
}

fn normalized_onion_address(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches(".onion").to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn should_accept_remote_tor_onion_route(
    transport_mode: &TransportMode,
    local_did: &str,
    sender_did: &str,
    local_onion_address: Option<&str>,
    peer_onion: Option<&str>,
) -> bool {
    if !matches!(transport_mode, TransportMode::Tor) || sender_did == local_did {
        return true;
    }

    let Some(local_onion) = local_onion_address.and_then(normalized_onion_address) else {
        return true;
    };
    let Some(remote_onion) = peer_onion.and_then(normalized_onion_address) else {
        return true;
    };

    remote_onion != local_onion
}

enum IncomingChatDecode {
    Text(String),
    DecryptError(String),
    ParseError(String),
    LegacyEnvelope,
    Plaintext,
}

async fn decode_incoming_chat_text(
    ratchet_mgr: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    keypair: &AgentKeyPair,
    peers: &Arc<DashMap<String, PeerInfo>>,
    transport_mode: &TransportMode,
    peer_id: &libp2p::PeerId,
    sender_did: &str,
    ratchet_init_secret: [u8; 32],
    payload: &[u8],
) -> IncomingChatDecode {
    if !payload.is_empty() && payload[0] == 0x02 {
        use crate::network::protocol::RatchetChatPayload;
        match bincode::deserialize::<RatchetChatPayload>(&payload[1..]) {
            Ok(rp) => match decrypt_incoming_ratchet_payload(
                ratchet_mgr,
                pending_hybrid_ratchet_inits,
                keypair,
                peers,
                transport_mode,
                peer_id,
                sender_did,
                ratchet_init_secret,
                &rp,
            )
            .await
            {
                Ok(pt) => IncomingChatDecode::Text(String::from_utf8_lossy(&pt).to_string()),
                Err(e) => IncomingChatDecode::DecryptError(e),
            },
            Err(e) => IncomingChatDecode::ParseError(e.to_string()),
        }
    } else if !payload.is_empty() && payload[0] == 0x01 {
        IncomingChatDecode::LegacyEnvelope
    } else {
        IncomingChatDecode::Plaintext
    }
}

async fn decrypt_incoming_ratchet_payload(
    ratchet_mgr: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    keypair: &AgentKeyPair,
    peers: &Arc<DashMap<String, PeerInfo>>,
    transport_mode: &TransportMode,
    peer_id: &libp2p::PeerId,
    sender_did: &str,
    ratchet_init_secret: [u8; 32],
    ratchet_payload: &crate::network::protocol::RatchetChatPayload,
) -> Result<Vec<u8>, String> {
    let initial_error = {
        let mut rmgr = ratchet_mgr.lock().await;
        match rmgr.decrypt_from_peer(
            sender_did,
            &ratchet_payload.header,
            &ratchet_payload.ciphertext,
        ) {
            Ok(plaintext) => return Ok(plaintext),
            Err(error) => error.to_string(),
        }
    };

    if !matches!(transport_mode, TransportMode::Tor)
        || !initial_error.contains("No ratchet session for peer")
    {
        return Err(initial_error);
    }

    let Some(peer) = peers.get(&peer_id.to_string()) else {
        return Err(initial_error);
    };
    let Some(remote_x25519_public) = peer.x25519_public_key else {
        return Err(initial_error);
    };
    let Some(remote_verifying_key) = peer.verifying_key else {
        return Err(initial_error);
    };
    let Some(remote_handshake_ratchet_public) = peer.ratchet_dh_public else {
        return Err(initial_error);
    };
    drop(peer);

    let Some(pending) =
        take_pending_hybrid_ratchet_init(pending_hybrid_ratchet_inits, peer_id, sender_did)
    else {
        return Err(initial_error);
    };
    if pending.suite != HYBRID_RATCHET_KDF_SUITE_V1 {
        return Err(initial_error);
    }

    let shared_secret = keypair
        .encryption_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(remote_x25519_public));
    let local_verifying_key = keypair.verifying_key.to_bytes();
    let local_x25519_public = keypair.x25519_public_key_bytes();
    let local_handshake_ratchet_public =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(ratchet_init_secret))
            .as_bytes();
    let ratchet_seed = derive_hybrid_ratchet_seed(
        shared_secret.as_bytes(),
        pending.kyber_shared_secret.as_ref(),
        &keypair.did,
        &local_verifying_key,
        &local_x25519_public,
        &local_handshake_ratchet_public,
        sender_did,
        &remote_verifying_key,
        &remote_x25519_public,
        &remote_handshake_ratchet_public,
    );
    let is_initiator = keypair.did.as_str() < sender_did;
    {
        let mut rmgr = ratchet_mgr.lock().await;
        rmgr.reset_and_init(
            sender_did,
            &ratchet_seed,
            &x25519_dalek::PublicKey::from(remote_handshake_ratchet_public),
            is_initiator,
            if is_initiator {
                None
            } else {
                Some(ratchet_init_secret)
            },
        );
        match rmgr.decrypt_from_peer(
            sender_did,
            &ratchet_payload.header,
            &ratchet_payload.ciphertext,
        ) {
            Ok(plaintext) => {
                tracing::info!(
                    peer = %crate::agent::contact_identity::displayed_did(sender_did),
                    initiator = is_initiator,
                    "Recovered pending Tor ratchet session from first ratcheted payload"
                );
                Ok(plaintext)
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

fn prepare_receive_target(
    log_mode: &LogMode,
    config: &ReceiveDirConfig,
    sender_did: &str,
    sender_name: &str,
) -> Result<(std::path::PathBuf, Option<(String, std::path::PathBuf)>)> {
    if ghost_secure_handoff_enabled(log_mode) {
        let (handoff_id, handoff_dir) = create_ghost_handoff_dir()
            .map_err(|e| anyhow::anyhow!("failed to create secure handoff dir: {}", e))?;
        Ok((handoff_dir.clone(), Some((handoff_id, handoff_dir))))
    } else {
        Ok((effective_receive_dir(config, sender_did, sender_name), None))
    }
}

async fn finalize_chunk_receive(
    recv: ChunkedReceiveSession,
    received_dir: std::path::PathBuf,
) -> Result<(
    crate::artifact::manifest::ArtifactManifestLocal,
    std::path::PathBuf,
)> {
    tokio::task::spawn_blocking(move || recv.finalize_with_path(&received_dir))
        .await
        .map_err(|e| anyhow::anyhow!("chunk finalize task failed: {}", e))?
}

fn record_active_incoming_iroh_transfer(
    transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    session_id: &str,
    sender_did: &str,
    sender_name: &str,
    total_chunks: usize,
    received_chunks: usize,
) {
    transfers.insert(
        session_id.to_string(),
        ActiveIncomingIrohTransfer {
            session_id: session_id.to_string(),
            sender_did: sender_did.to_string(),
            sender_name: sender_name.to_string(),
            total_chunks,
            received_chunks,
            last_progress_at: tokio::time::Instant::now(),
            pause_notified: false,
        },
    );
}

pub(crate) fn spawn_incoming_message_handler(
    ctx: IncomingMessageContext,
    mut msg_rx: mpsc::Receiver<crate::network::IncomingRequestEnvelope>,
    mut priority_msg_rx: mpsc::Receiver<crate::network::IncomingRequestEnvelope>,
) -> IncomingMessageRuntime {
    let IncomingMessageContext {
        peers: peers_msg,
        invite_proof_by_peer: invite_proof_msg,
        agent_name: agent_name_msg,
        keypair: keypair_msg,
        audit: audit_msg,
        replay_guard: replay_guard_msg,
        rate_limiter: rate_limiter_msg,
        chunk_rate_limiter: chunk_rate_limiter_msg,
        log_mode: log_mode_msg,
        peer_store: peer_store_msg,
        used_invites: used_invites_msg,
        used_invites_path: used_invites_path_msg,
        used_invites_persist_key: used_invites_persist_key_msg,
        default_ttl,
        transport_mode: transport_mode_msg,
        our_did: our_did_msg,
        local_onion_address: local_onion_address_msg,
        rbac: rbac_msg,
        ratchet_mgr: ratchet_mgr_msg,
        pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits_msg,
        ratchet_init_secret: ratchet_init_secret_msg,
        cmd_tx: cmd_tx_msg,
        transfer_decisions: transfer_decisions_msg,
        transfer_start_approvals: transfer_start_approvals_msg,
        pending_contact_requests: pending_contact_requests_msg,
        incoming_connect_gate: incoming_connect_gate_msg,
        direct_peer_dids: direct_peer_dids_msg,
        active_chat_target_did: active_chat_target_did_msg,
        active_chat_target_group_label: active_chat_target_group_label_msg,
        manual_disconnect_dids: manual_disconnect_dids_msg,
        remote_offline_dids: remote_offline_dids_msg,
        iroh_peer_liveness: iroh_peer_liveness_msg,
        iroh_handshake_sync: iroh_handshake_sync_msg,
        iroh_authenticated_sessions: iroh_authenticated_sessions_msg,
        active_incoming_iroh_transfers: active_incoming_iroh_transfers_msg,
        receive_dir_config: receive_dir_config_msg,
    } = ctx;

    // Track incoming chunked transfers: session_id → receive state
    let chunked_sessions: Arc<
        tokio::sync::Mutex<std::collections::HashMap<String, ChunkedReceiveSession>>,
    > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    // Atomic counter for active receive sessions — used by swarm event loop
    // to suppress noisy OutboundFailure errors during chunk receive.
    let active_receive_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    const MAX_ACTIVE_RECEIVE_SESSIONS: usize = 32;

    // Stale session cleanup: remove sessions with no chunk activity for 30 minutes.
    // Uses last_chunk_at (not created_at) so long transfers over Tor aren't killed.
    {
        let sessions_cleanup = Arc::clone(&chunked_sessions);
        let arc_count = Arc::clone(&active_receive_count);
        let active_transfers_cleanup = Arc::clone(&active_incoming_iroh_transfers_msg);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let active_temp_dirs = {
                    let mut sessions = sessions_cleanup.lock().await;
                    let stale_ids: Vec<String> = sessions
                        .iter()
                        .filter(|(_, s)| {
                            now.saturating_sub(s.last_chunk_at)
                                > STALE_CHUNK_RECEIVE_SESSION_WINDOW_MS
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in &stale_ids {
                        tracing::warn!(
                            session = %id,
                            "Removing stale chunked session (>30 min inactive)"
                        );
                        sessions.remove(id);
                        active_transfers_cleanup.remove(id);
                        arc_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    sessions
                        .values()
                        .map(|session| session.temp_dir.clone())
                        .collect::<std::collections::HashSet<_>>()
                };

                let orphan_dirs = stale_orphan_chunk_receive_dirs(
                    &runtime_temp_path("qypha-chunk-recv"),
                    &active_temp_dirs,
                    now,
                    STALE_CHUNK_RECEIVE_SESSION_WINDOW_MS,
                );
                if !orphan_dirs.is_empty() {
                    let orphan_count = orphan_dirs.len();
                    if let Err(error) = tokio::task::spawn_blocking(move || {
                        for path in orphan_dirs {
                            crate::os_adapter::secure_wipe::secure_wipe_dir(&path);
                        }
                    })
                    .await
                    {
                        tracing::warn!(
                            %error,
                            "stale orphan chunk receive staging cleanup task failed"
                        );
                    } else {
                        tracing::info!(
                            orphan_count,
                            "Removed stale orphan chunk receive staging director{}",
                            if orphan_count == 1 { "y" } else { "ies" }
                        );
                    }
                }
            }
        });
    }

    let active_receive_count_task = Arc::clone(&active_receive_count);

    tokio::spawn(async move {
        let active_receive_count = active_receive_count_task;
        let mut recent_unknown_session_statuses: std::collections::HashMap<
            (String, String),
            tokio::time::Instant,
        > = std::collections::HashMap::new();
        let mut msg_open = true;
        let mut priority_open = true;
        loop {
            let envelope = tokio::select! {
                biased;
                maybe = priority_msg_rx.recv(), if priority_open => {
                    match maybe {
                        Some(envelope) => Some(envelope),
                        None => {
                            priority_open = false;
                            None
                        }
                    }
                }
                maybe = msg_rx.recv(), if msg_open => {
                    match maybe {
                        Some(envelope) => Some(envelope),
                        None => {
                            msg_open = false;
                            None
                        }
                    }
                }
                else => break,
            };
            let Some(envelope) = envelope else {
                if !msg_open && !priority_open {
                    break;
                }
                continue;
            };
            let peer_id = envelope.peer_id;
            let request = envelope.request;
            let visible_sender_did =
                crate::agent::contact_identity::displayed_did(&request.sender_did);
            let iroh_stable_id = envelope.iroh_stable_id;
            let iroh_active_session = envelope.iroh_active_session;
            if should_drop_inactive_iroh_envelope(
                iroh_stable_id,
                iroh_active_session,
                &request.msg_type,
            ) {
                tracing::debug!(
                    peer = %peer_id,
                    stable_id = ?iroh_stable_id,
                    msg_type = ?request.msg_type,
                    "dropping request from replaced/stale iroh live session"
                );
                continue;
            }
            if matches!(transport_mode_msg, TransportMode::Internet) {
                mark_iroh_peer_active(&iroh_peer_liveness_msg, &peer_id);
            }
            let pid_str = peer_id.to_string();
            let transfer_key = transfer_decision_key(&request);
            let local_approved_reinject = if let Some(ref key) = transfer_key {
                let mut gate = transfer_decisions_msg.lock().await;
                gate.consume_approved_key(key)
            } else {
                false
            };
            let mut predecoded_chat_text: Option<String> = None;
            let mut preopened_contact_request: Option<
                crate::network::contact_request::ContactRequestPayload,
            > = None;
            let mut preopened_contact_accept: Option<
                crate::network::contact_request::ContactAcceptPayload,
            > = None;
            let mut preopened_contact_reject: Option<
                crate::network::contact_request::ContactRejectPayload,
            > = None;

            // If this chunk session is pending user approval (or explicitly rejected),
            // silently drop chunk traffic so it does not trip rate-limit noise.
            if matches!(
                request.msg_type,
                MessageKind::ChunkData | MessageKind::TransferComplete
            ) {
                let session_id = match request.msg_type {
                    MessageKind::ChunkData => bincode::deserialize::<
                        crate::network::protocol::ChunkDataPayload,
                    >(&request.payload)
                    .ok()
                    .map(|p| p.session_id),
                    MessageKind::TransferComplete => bincode::deserialize::<
                        crate::network::protocol::TransferCompletePayload,
                    >(&request.payload)
                    .ok()
                    .map(|p| p.session_id),
                    _ => None,
                };
                if let Some(session_id) = session_id {
                    let gate = transfer_decisions_msg.lock().await;
                    if gate.is_pending_or_rejected_chunk_session(&session_id) {
                        continue;
                    }
                }
            }

            let strict_pqc_mode = matches!(log_mode_msg, LogMode::Ghost | LogMode::Safe)
                || matches!(transport_mode_msg, TransportMode::Tor);

            // ── Security Pipeline ────────────────────────────────────────
            // Heartbeat: skip (cover traffic, no sensitive data)
            // Handshake: rate-limit + replay guard applied, signature verified
            //            using the verifying_key embedded in the handshake payload
            //            (TOFU on first contact, key continuity check on subsequent)
            let skip_security = matches!(request.msg_type, MessageKind::Heartbeat);

            if !skip_security && !local_approved_reinject {
                // DID continuity check for all non-handshake messages.
                // Once a peer is associated with a DID, incoming messages on the same
                // transport peer_id must keep using that DID (prevents sender_did spoofing).
                if !matches!(request.msg_type, MessageKind::Handshake) {
                    if let Some(expected_did) = peers_msg.get(&pid_str).map(|p| p.did.clone()) {
                        // Only enforce continuity when we already have a real DID bound.
                        if expected_did.starts_with("did:nxf:")
                            && request.sender_did != expected_did
                        {
                            tracing::warn!(
                                peer_id = %pid_str,
                                claimed_did = %request.sender_did,
                                expected_did = %expected_did,
                                "DID mismatch on authenticated channel — message rejected"
                            );
                            println!(
                                "\n   {} {} (claimed DID does not match established peer identity)",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }
                }

                // 1. Rate limiting
                {
                    // Chunked transfer traffic is high-frequency by design.
                    // Route all chunk protocol messages through the transfer limiter.
                    let is_chunk_transfer_msg = matches!(
                        &request.msg_type,
                        MessageKind::ChunkTransferInit
                            | MessageKind::ChunkData
                            | MessageKind::ChunkAck
                            | MessageKind::TransferResume
                            | MessageKind::TransferStatus
                            | MessageKind::TransferReject
                            | MessageKind::TransferComplete
                    );
                    let mut rl = if is_chunk_transfer_msg {
                        chunk_rate_limiter_msg.lock().await
                    } else {
                        rate_limiter_msg.lock().await
                    };
                    if let Err(e) = rl.check_and_record(&request.sender_did) {
                        tracing::warn!(
                            from = %request.sender_did,
                            msg_type = ?request.msg_type,
                            "RATE LIMIT: {}",
                            e
                        );
                        println!(
                            "\n   {} {} (from {})",
                            "RATE LIMIT:".red().bold(),
                            e,
                            request.sender_name
                        );
                        print_prompt(&agent_name_msg);
                        continue;
                    }
                }

                // 2. Replay protection
                {
                    let ttl = if request.ttl_ms > 0 {
                        request.ttl_ms
                    } else {
                        default_ttl
                    };
                    let scoped_nonce = scoped_replay_nonce(&request.sender_did, request.nonce);
                    let mut rg = replay_guard_msg.lock().await;
                    if let Err(e) = rg.check_and_record(scoped_nonce, request.timestamp, ttl) {
                        tracing::warn!(
                            from = %request.sender_did,
                            nonce = request.nonce,
                            "REPLAY GUARD: {}",
                            e
                        );
                        println!(
                            "\n   {} {} (from {})",
                            "REPLAY BLOCKED:".red().bold(),
                            e,
                            request.sender_name
                        );
                        print_prompt(&agent_name_msg);
                        continue;
                    }
                }

                // 3. CRYPTOGRAPHIC Ed25519 signature verification
                // MANDATORY for ALL message types (including Handshake)
                // Handshake: self-signed (verifying key from payload, TOFU principle)
                // Others: verified against stored peer verifying key
                if matches!(request.msg_type, MessageKind::ContactRequest) {
                    match crate::network::contact_request::open_contact_request_agent_request(
                        &keypair_msg,
                        &request,
                    ) {
                        Ok(payload) => {
                            preopened_contact_request = Some(payload);
                        }
                        Err(error) => {
                            tracing::warn!(
                                from = %request.sender_did,
                                %error,
                                "Contact request rejected during authenticated open"
                            );
                            println!(
                                "\n   {} contact request from {} — invalid sealed request",
                                "SECURITY REJECT".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }
                } else if matches!(request.msg_type, MessageKind::ContactAccept) {
                    match crate::network::contact_request::open_contact_accept_agent_request(
                        &keypair_msg,
                        &request,
                    ) {
                        Ok(payload) => {
                            preopened_contact_accept = Some(payload);
                        }
                        Err(error) => {
                            tracing::warn!(
                                from = %request.sender_did,
                                %error,
                                "Contact accept rejected during authenticated open"
                            );
                            println!(
                                "\n   {} contact accept from {} — invalid sealed response",
                                "SECURITY REJECT".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }
                } else if matches!(request.msg_type, MessageKind::ContactReject) {
                    match crate::network::contact_request::open_contact_reject_agent_request(
                        &keypair_msg,
                        &request,
                    ) {
                        Ok(payload) => {
                            preopened_contact_reject = Some(payload);
                        }
                        Err(error) => {
                            tracing::warn!(
                                from = %request.sender_did,
                                %error,
                                "Contact reject rejected during authenticated open"
                            );
                            println!(
                                "\n   {} contact reject from {} — invalid sealed response",
                                "SECURITY REJECT".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }
                } else if matches!(request.msg_type, MessageKind::Handshake) {
                    // Handshake signature verification: extract verifying_key from payload
                    // First contact: TOFU (Trust On First Use) — accept self-signed key
                    // Subsequent: verify against stored key (key continuity)
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    let hs_vk: Option<[u8; 32]> =
                        serde_json::from_slice::<serde_json::Value>(&request.payload)
                            .ok()
                            .and_then(|v| v.get("verifying_key_hex")?.as_str().map(String::from))
                            .and_then(|hex_str| hex::decode(&hex_str).ok())
                            .and_then(|bytes| {
                                if bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    Some(arr)
                                } else {
                                    None
                                }
                            });

                    // If this transport peer_id already has an established DID,
                    // do not allow it to claim a different DID in a new handshake.
                    if let Some(expected_did) = peers_msg.get(&pid_str).map(|p| p.did.clone()) {
                        // Only enforce continuity when we already have a real DID bound.
                        if expected_did.starts_with("did:nxf:")
                            && request.sender_did != expected_did
                        {
                            tracing::warn!(
                                peer_id = %pid_str,
                                claimed_did = %request.sender_did,
                                expected_did = %expected_did,
                                "Handshake DID mismatch — rejected"
                            );
                            println!(
                                "\n   {} handshake from {} — DID mismatch",
                                "SECURITY REJECT".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }

                    // Cryptographic identity binding: sender_did must match the
                    // SHA-256 fingerprint of the Ed25519 verifying key.
                    if let Some(vk_bytes) = hs_vk {
                        let expected_did = derive_did_from_verifying_key(&vk_bytes);
                        if request.sender_did != expected_did {
                            tracing::warn!(
                                claimed_did = %request.sender_did,
                                derived_did = %expected_did,
                                "Handshake DID/key mismatch — rejected"
                            );
                            println!(
                                "\n   {} handshake from {} — DID/key mismatch",
                                "SECURITY REJECT".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }

                    // Check if we already have a trusted verifying key (key continuity).
                    // Prefer the live peer slot, then same-DID live peers, then persisted storage.
                    let stored_vk = match live_peer_verifying_key_for_handshake(
                        &peers_msg,
                        &pid_str,
                        &request.sender_did,
                    ) {
                        Some(vk) => Some(vk),
                        None => {
                            persisted_peer_verifying_key(&peer_store_msg, &request.sender_did).await
                        }
                    };
                    if should_reject_handshake_verifying_key_continuity(stored_vk, hs_vk) {
                        tracing::warn!(
                            sender_did = %request.sender_did,
                            "Handshake verifying key continuity mismatch — rejected"
                        );
                        println!(
                            "\n   {} handshake from {} — verifying key changed",
                            "SECURITY REJECT".red().bold(),
                            request.sender_name.cyan()
                        );
                        print_prompt(&agent_name_msg);
                        continue;
                    }
                    let vk_to_use = stored_vk.or(hs_vk);

                    match vk_to_use {
                        Some(vk_bytes) => {
                            match VerifyingKey::from_bytes(&vk_bytes) {
                                Ok(vk) => {
                                    let msg_type_bytes =
                                        serde_json::to_vec(&request.msg_type).unwrap_or_default();
                                    let mut signed_data = Vec::with_capacity(
                                        msg_type_bytes.len() + request.payload.len() + 16,
                                    );
                                    signed_data.extend_from_slice(&msg_type_bytes);
                                    signed_data.extend_from_slice(&request.payload);
                                    signed_data.extend_from_slice(&request.nonce.to_le_bytes());
                                    signed_data.extend_from_slice(&request.timestamp.to_le_bytes());

                                    if request.signature.len() == 64 {
                                        if let Ok(sig) = Signature::from_slice(&request.signature) {
                                            if vk.verify_strict(&signed_data, &sig).is_err() {
                                                tracing::warn!(
                                                    from = %request.sender_did,
                                                    "Handshake Ed25519 SIGNATURE INVALID — rejected"
                                                );
                                                println!(
                                                    "\n   {} handshake from {} — DROPPED",
                                                    "INVALID SIGNATURE".red().bold(),
                                                    request.sender_name.cyan()
                                                );
                                                print_prompt(&agent_name_msg);
                                                continue;
                                            }
                                            // Signature valid — proceed to handshake processing
                                        } else {
                                            tracing::warn!(from = %request.sender_did, "Handshake: malformed signature bytes");
                                            continue;
                                        }
                                    } else {
                                        // Unsigned handshake — reject (backward compat window expired)
                                        tracing::warn!(
                                            from = %request.sender_did,
                                            sig_len = request.signature.len(),
                                            "Unsigned handshake rejected (signature required)"
                                        );
                                        println!(
                                            "\n   {} from {} (unsigned handshake rejected)",
                                            "SECURITY REJECT".red().bold(),
                                            request.sender_name.cyan()
                                        );
                                        print_prompt(&agent_name_msg);
                                        continue;
                                    }
                                }
                                Err(_) => {
                                    tracing::warn!(from = %request.sender_did, "Handshake: invalid verifying key");
                                    continue;
                                }
                            }
                        }
                        None => {
                            // No verifying key available (not in payload, not stored)
                            tracing::warn!(
                                from = %request.sender_did,
                                "Handshake without verifying key — rejected"
                            );
                            continue;
                        }
                    }
                } else {
                    let peer_vk = match peers_msg.get(&pid_str).and_then(|p| p.verifying_key) {
                        Some(vk) => Some(vk),
                        None => {
                            persisted_peer_verifying_key(&peer_store_msg, &request.sender_did).await
                        }
                    };
                    let authenticated_live_iroh_session = match iroh_stable_id {
                        Some(stable_id) => is_authenticated_iroh_session(
                            &iroh_authenticated_sessions_msg,
                            &peer_id,
                            stable_id,
                        ),
                        None => true,
                    };
                    let allow_preauthenticated_disconnect_notice =
                        should_allow_preauthenticated_iroh_disconnect_notice(
                            &request.msg_type,
                            peer_vk.is_some(),
                            authenticated_live_iroh_session,
                        );

                    match peer_vk {
                        _ if !authenticated_live_iroh_session
                            && !allow_preauthenticated_disconnect_notice =>
                        {
                            let visible_sender_did =
                                crate::agent::contact_identity::displayed_did(&request.sender_did);
                            tracing::warn!(
                                from = %visible_sender_did,
                                msg_type = ?request.msg_type,
                                stable_id = ?iroh_stable_id,
                                "Live iroh session is not yet authenticated for this message"
                            );
                            continue;
                        }
                        Some(vk_bytes) => {
                            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                            let vk_result = VerifyingKey::from_bytes(&vk_bytes);
                            match vk_result {
                                Ok(vk) => {
                                    // Reconstruct signed data: msg_type || payload || nonce || timestamp
                                    let msg_type_bytes =
                                        serde_json::to_vec(&request.msg_type).unwrap_or_default();
                                    let mut signed_data = Vec::with_capacity(
                                        msg_type_bytes.len() + request.payload.len() + 16,
                                    );
                                    signed_data.extend_from_slice(&msg_type_bytes);
                                    signed_data.extend_from_slice(&request.payload);
                                    signed_data.extend_from_slice(&request.nonce.to_le_bytes());
                                    signed_data.extend_from_slice(&request.timestamp.to_le_bytes());

                                    if request.signature.len() == 64 {
                                        if let Ok(sig) = Signature::from_slice(&request.signature) {
                                            if vk.verify_strict(&signed_data, &sig).is_err() {
                                                tracing::warn!(
                                                    from = %request.sender_did,
                                                    "Ed25519 SIGNATURE INVALID — message rejected"
                                                );
                                                println!(
                                                    "\n   {} from {} — message DROPPED",
                                                    "INVALID SIGNATURE".red().bold(),
                                                    request.sender_name.cyan()
                                                );
                                                print_prompt(&agent_name_msg);
                                                continue;
                                            }
                                        } else {
                                            tracing::warn!(from = %visible_sender_did, "Malformed signature bytes");
                                            continue;
                                        }
                                    } else {
                                        tracing::warn!(
                                            from = %visible_sender_did,
                                            sig_len = request.signature.len(),
                                            "Missing or wrong-size signature — message rejected"
                                        );
                                        println!(
                                            "\n   {} from {} (sig {} bytes, expected 64)",
                                            "NO SIGNATURE".red().bold(),
                                            request.sender_name.cyan(),
                                            request.signature.len()
                                        );
                                        print_prompt(&agent_name_msg);
                                        continue;
                                    }
                                }
                                Err(_) => {
                                    tracing::warn!(from = %visible_sender_did, "Invalid verifying key in PeerInfo");
                                    continue;
                                }
                            }
                        }
                        None => {
                            // No verifying key from handshake yet — reject non-handshake messages
                            tracing::warn!(
                                from = %visible_sender_did,
                                msg_type = ?request.msg_type,
                                "No verifying key — cannot authenticate, message rejected"
                            );
                            continue;
                        }
                    }
                }

                // 4. RBAC authorization (fail-closed)
                // Enforce sender -> recipient permissions on authenticated messages.
                let allowed = match request.msg_type {
                    MessageKind::Chat => {
                        let allowed = {
                            let r = rbac_msg.read().await;
                            r.can_send_to(&request.sender_did, &our_did_msg)
                        };
                        if allowed {
                            true
                        } else {
                            match decode_incoming_chat_text(
                                &ratchet_mgr_msg,
                                &pending_hybrid_ratchet_inits_msg,
                                &keypair_msg,
                                &peers_msg,
                                &transport_mode_msg,
                                &peer_id,
                                &request.sender_did,
                                ratchet_init_secret_msg,
                                &request.payload,
                            )
                            .await
                            {
                                IncomingChatDecode::Text(text)
                                    if text.as_bytes() == RATCHET_BOOTSTRAP_MARKER =>
                                {
                                    tracing::debug!(
                                        from = %visible_sender_did,
                                        "Allowing internal ratchet bootstrap before RBAC registration"
                                    );
                                    predecoded_chat_text = Some(text);
                                    true
                                }
                                _ => false,
                            }
                        }
                    }
                    MessageKind::FileTransfer
                    | MessageKind::ChunkTransferInit
                    | MessageKind::ChunkData
                    | MessageKind::TransferResume
                    | MessageKind::TransferStatus
                    | MessageKind::TransferComplete => {
                        let r = rbac_msg.read().await;
                        r.can_transfer_to(&request.sender_did, &our_did_msg)
                    }
                    _ => true,
                };

                if !allowed {
                    tracing::warn!(
                        from = %request.sender_did,
                        msg_type = ?request.msg_type,
                        to = %our_did_msg,
                        "RBAC policy denied incoming request"
                    );
                    println!(
                        "\n   {} {} [{}] denied by RBAC policy",
                        "POLICY REJECT:".red().bold(),
                        request.sender_name.cyan(),
                        format!("{:?}", request.msg_type).yellow()
                    );
                    print_prompt(&agent_name_msg);
                    continue;
                }
            }

            // ── Message routing ─────────────────────────────────────────
            match request.msg_type {
                MessageKind::ContactRequest => {
                    let payload = match preopened_contact_request.take() {
                        Some(payload) => payload,
                        None => match crate::network::contact_request::open_contact_request_agent_request(
                            &keypair_msg,
                            &request,
                        ) {
                            Ok(payload) => payload,
                            Err(error) => {
                                tracing::warn!(
                                    from = %request.sender_did,
                                    %error,
                                    "Contact request could not be reopened during routing"
                                );
                                continue;
                            }
                        },
                    };
                    let sender_did = payload.sender_profile.did.clone();
                    let blocked = {
                        let gate = incoming_connect_gate_msg.lock().await;
                        gate.is_block_all() || gate.is_did_blocked(&sender_did)
                    };
                    if blocked {
                        tracing::info!(
                            sender_did = %sender_did,
                            peer_id = %peer_id,
                            "Blocked contact request dropped before surfacing"
                        );
                        {
                            let mut a = audit_msg.lock().await;
                            a.record(
                                "CONTACT_REQUEST_BLOCKED",
                                &our_did_msg,
                                &format!("from_did={} peer_id={}", sender_did, peer_id),
                            );
                        }
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::DisconnectPeer { peer_id })
                            .await;
                        continue;
                    }
                    let display_did =
                        crate::network::contact_did::encode_contact_did(&payload.sender_profile)
                            .unwrap_or_else(|_| sender_did.clone());
                    let is_new = {
                        let mut registry = pending_contact_requests_msg.lock().await;
                        registry.upsert_live(peer_id, request.sender_name.clone(), payload.clone())
                    };
                    println!(
                        "\n   {} {} ({})",
                        "Contact request:".green().bold(),
                        request.sender_name.cyan(),
                        display_did.dimmed()
                    );
                    if let Some(intro) = payload.intro_message.as_deref() {
                        println!("   {} {}", "Intro:".yellow().bold(), intro);
                    }
                    println!(
                        "   {} /accept {}   {} /reject {}",
                        "Review:".dimmed(),
                        display_did.white().bold(),
                        "or".dimmed(),
                        display_did.white().bold()
                    );
                    if is_new {
                        let mut a = audit_msg.lock().await;
                        a.record(
                            "CONTACT_REQUEST_PENDING",
                            &our_did_msg,
                            &format!("from_did={} peer_id={}", sender_did, peer_id),
                        );
                    }
                    print_prompt(&agent_name_msg);
                    continue;
                }
                MessageKind::ContactAccept => {
                    let payload = match preopened_contact_accept.take() {
                        Some(payload) => payload,
                        None => {
                            match crate::network::contact_request::open_contact_accept_agent_request(
                                &keypair_msg,
                                &request,
                            ) {
                                Ok(payload) => payload,
                                Err(error) => {
                                    tracing::warn!(
                                        from = %request.sender_did,
                                        %error,
                                        "Contact accept could not be reopened during routing"
                                    );
                                    continue;
                                }
                            }
                        }
                    };
                    let promotion = promote_accepted_contact(
                        &payload.responder_profile,
                        &request.sender_name,
                        &request.sender_role,
                        &log_mode_msg,
                        &peer_store_msg,
                        &direct_peer_dids_msg,
                        Some(&peers_msg),
                        Some(peer_id),
                        Some(&cmd_tx_msg),
                    )
                    .await;
                    let responder_display_did =
                        crate::network::contact_did::encode_contact_did(&payload.responder_profile)
                            .unwrap_or_else(|_| payload.responder_profile.did.clone());
                    println!(
                        "\n   {} {} ({})",
                        "Contact accepted:".green().bold(),
                        request.sender_name.cyan(),
                        responder_display_did.dimmed()
                    );
                    print_trusted_contact_promotion(promotion);
                    let mut a = audit_msg.lock().await;
                    a.record(
                        "CONTACT_REQUEST_ACCEPTED",
                        &our_did_msg,
                        &format!(
                            "request_id={} responder_did={}",
                            payload.request_id, payload.responder_profile.did
                        ),
                    );
                    print_prompt(&agent_name_msg);
                    continue;
                }
                MessageKind::ContactReject => {
                    let payload = match preopened_contact_reject.take() {
                        Some(payload) => payload,
                        None => {
                            match crate::network::contact_request::open_contact_reject_agent_request(
                                &keypair_msg,
                                &request,
                            ) {
                                Ok(payload) => payload,
                                Err(error) => {
                                    tracing::warn!(
                                        from = %request.sender_did,
                                        %error,
                                        "Contact reject could not be reopened during routing"
                                    );
                                    continue;
                                }
                            }
                        }
                    };
                    let responder_display_did =
                        crate::network::contact_did::encode_contact_did(&payload.responder_profile)
                            .unwrap_or_else(|_| payload.responder_profile.did.clone());
                    println!(
                        "\n   {} {} ({})",
                        "Contact rejected:".yellow().bold(),
                        request.sender_name.cyan(),
                        responder_display_did.dimmed()
                    );
                    if let Some(reason) = payload.reason.as_deref() {
                        println!("   {} {}", "Reason:".yellow().bold(), reason);
                    }
                    let mut a = audit_msg.lock().await;
                    a.record(
                        "CONTACT_REQUEST_REJECTED",
                        &our_did_msg,
                        &format!(
                            "request_id={} responder_did={}",
                            payload.request_id, payload.responder_profile.did
                        ),
                    );
                    print_prompt(&agent_name_msg);
                    continue;
                }
                // ── Handshake: peer sends identity + X25519 encryption key ──
                MessageKind::Handshake => {
                    let mut x25519_key: Option<[u8; 32]> = None;
                    let mut peer_onion: Option<String> = None;
                    let mut kyber_key: Option<Vec<u8>> = None;
                    let mut kyber_error: Option<String> = None;
                    let mut verifying_key: Option<[u8; 32]> = None;
                    let mut peer_aegis_supported = false;
                    let mut peer_hybrid_ratchet_kdf_suite: Option<String> = None;
                    let mut peer_hybrid_ratchet_ciphertext: Option<Vec<u8>> = None;
                    let mut peer_ratchet_dh: Option<[u8; 32]> = None;
                    let mut peer_pqc_enforced = false;
                    let mut peer_iroh_endpoint_addr: Option<String> = None;
                    let mut inbound_invite_code: Option<String> = None;
                    let mut ack_handshake_message_id: Option<String> = None;
                    let mut visible_sender_did =
                        crate::agent::contact_identity::displayed_did(&request.sender_did);

                    if !request.payload.is_empty() {
                        match serde_json::from_slice::<HandshakePayload>(&request.payload) {
                            Ok(hp) => {
                                x25519_key = Some(hp.x25519_public_key);
                                // Prefer the shareable contact DID in logs once the peer's
                                // verifying key is available, falling back to the canonical DID.
                                if let Some(ref vk_hex) = hp.verifying_key_hex {
                                    if let Ok(vk_bytes) = hex::decode(vk_hex) {
                                        if vk_bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&vk_bytes);
                                            verifying_key = Some(arr);
                                        }
                                    }
                                }
                                if let Some(vk) = verifying_key {
                                    visible_sender_did = crate::network::contact_did::contact_did_from_verifying_key_bytes(vk);
                                }
                                peer_onion = hp.onion_address.as_ref().and_then(|onion| {
                                    if crate::network::invite::is_valid_onion_v3(onion) {
                                        Some(onion.clone())
                                    } else {
                                        tracing::warn!(
                                            from = %visible_sender_did,
                                            onion = %onion,
                                            "Invalid onion address in handshake payload — ignored"
                                        );
                                        None
                                    }
                                });
                                // Parse required Kyber-1024 PQC key for hybrid bootstrap.
                                if hp.kyber_public_key_hex.is_empty() {
                                    kyber_error = Some(
                                        "missing required Kyber-1024 bootstrap key".to_string(),
                                    );
                                } else {
                                    match hex::decode(&hp.kyber_public_key_hex) {
                                        Ok(kb) if kb.len() == pqc_kyber::KYBER_PUBLICKEYBYTES => {
                                            kyber_key = Some(kb);
                                        }
                                        Ok(kb) => {
                                            kyber_error = Some(format!(
                                                "invalid Kyber-1024 bootstrap key length {}",
                                                kb.len()
                                            ));
                                        }
                                        Err(error) => {
                                            kyber_error = Some(format!(
                                                "invalid Kyber-1024 bootstrap key hex: {}",
                                                error
                                            ));
                                        }
                                    }
                                }
                                // Parse AEGIS-256 and Double Ratchet capabilities
                                peer_aegis_supported = hp.aegis_supported;
                                peer_pqc_enforced = hp.pqc_enforced || kyber_key.is_some();
                                peer_hybrid_ratchet_kdf_suite = hp.ratchet_hybrid_kdf_suite.clone();
                                peer_hybrid_ratchet_ciphertext = hp
                                    .ratchet_hybrid_kyber_ciphertext_hex
                                    .as_ref()
                                    .and_then(|hex_ct| hex::decode(hex_ct).ok());
                                inbound_invite_code = hp.invite_code.clone();
                                ack_handshake_message_id = hp.ack_handshake_message_id.clone();
                                peer_iroh_endpoint_addr = hp
                                    .iroh_endpoint_addr
                                    .as_ref()
                                    .and_then(|json| {
                                        match crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json(json) {
                                            Ok(sanitized) => {
                                                if sanitized != *json {
                                                    tracing::warn!(
                                                        from = %visible_sender_did,
                                                        "Stripped non-relay iroh transports from handshake payload"
                                                    );
                                                }
                                                Some(sanitized)
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    from = %visible_sender_did,
                                                    %e,
                                                    "Invalid or non-relay iroh endpoint in handshake payload — ignored"
                                                );
                                                None
                                            }
                                        }
                                    });
                                peer_ratchet_dh = hp.ratchet_dh_public_hex.as_ref().and_then(|h| {
                                    hex::decode(h).ok().and_then(|b| {
                                        if b.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&b);
                                            Some(arr)
                                        } else {
                                            None
                                        }
                                    })
                                });
                                if !should_accept_remote_tor_onion_route(
                                    &transport_mode_msg,
                                    &our_did_msg,
                                    &request.sender_did,
                                    local_onion_address_msg.as_deref(),
                                    peer_onion.as_deref(),
                                ) {
                                    tracing::warn!(
                                        from = %visible_sender_did,
                                        onion = ?peer_onion,
                                        local_onion = ?local_onion_address_msg,
                                        "Rejected foreign Tor handshake route that points at the local onion service"
                                    );
                                    peer_onion = None;
                                }
                                tracing::info!(
                                    did = %visible_sender_did,
                                    onion = ?hp.onion_address,
                                    pqc = kyber_key.is_some(),
                                    vk = verifying_key.is_some(),
                                    aegis = peer_aegis_supported,
                                    hybrid = peer_hybrid_ratchet_ciphertext.is_some(),
                                    ratchet = peer_ratchet_dh.is_some(),
                                    iroh = peer_iroh_endpoint_addr.is_some(),
                                    "Got X25519 key via handshake"
                                );
                            }
                            Err(e) => {
                                tracing::warn!("Could not parse handshake payload: {}", e);
                            }
                        }
                    }

                    if let Some(reason) = kyber_error {
                        tracing::warn!(
                            from = %visible_sender_did,
                            %reason,
                            "Handshake rejected: invalid or missing required Kyber bootstrap key"
                        );
                        println!(
                            "\n   {} handshake from {} — missing required hybrid bootstrap key",
                            "SECURITY REJECT:".red().bold(),
                            request.sender_name.cyan()
                        );
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::DisconnectPeer { peer_id })
                            .await;
                        print_prompt(&agent_name_msg);
                        continue;
                    }

                    // Invite-proof enforcement:
                    // - Direct invites: one-time, reserved on first verified use
                    // - Group invites: reusable, but issuer can kick/reject specific members
                    let trusted_live_peer_slot =
                        bound_live_peer_slot_matches_did(&peers_msg, &peer_id, &request.sender_did);

                    let locally_manually_disconnected = {
                        let manual = manual_disconnect_dids_msg.lock().await;
                        manual.contains(&request.sender_did)
                    };
                    let did_explicitly_blocked = {
                        let gate = incoming_connect_gate_msg.lock().await;
                        gate.is_did_blocked(&request.sender_did)
                    };
                    if inbound_invite_code.is_none()
                        && should_send_manual_disconnect_notice_for_handshake_policy(
                            locally_manually_disconnected,
                            did_explicitly_blocked,
                        )
                    {
                        tracing::info!(
                            sender_did = %visible_sender_did,
                            peer_id = %peer_id,
                            "Inbound handshake rejected by local manual disconnect policy"
                        );
                        println!(
                            "\n   {} handshake from {} — peer was disconnected locally",
                            "SECURITY REJECT:".red().bold(),
                            request.sender_name.cyan()
                        );
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::DisconnectPeerWithNotice {
                                peer_id,
                                notice_kind: DisconnectNoticeKind::ManualDisconnect,
                            })
                            .await;
                        print_prompt(&agent_name_msg);
                        continue;
                    }

                    if inbound_invite_code.is_none() {
                        let trusted_sender = trusted_live_peer_slot || {
                            let ps = peer_store_msg.lock().await;
                            is_trusted_peer_identity(&request.sender_did, &peers_msg, &ps)
                        };
                        if !trusted_sender {
                            tracing::warn!(
                                from = %visible_sender_did,
                                "Handshake rejected: unknown peer attempted first contact without invite proof"
                            );
                            println!(
                                "\n   {} handshake from {} — first contact requires a fresh invite",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeer { peer_id })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }

                    if let Some(ref invite_code) = inbound_invite_code {
                        let invite = match PeerInvite::from_code(invite_code) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(from = %visible_sender_did, %e, "Handshake invite proof decode failed");
                                println!(
                                    "\n   {} handshake from {} — invalid invite proof",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::DisconnectPeer { peer_id })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        };

                        match invite.verify_with_expiry(None) {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(from = %visible_sender_did, "Handshake invite proof signature invalid");
                                println!(
                                    "\n   {} handshake from {} — invite signature invalid",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::DisconnectPeer { peer_id })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(from = %visible_sender_did, %e, "Handshake invite proof rejected");
                                println!(
                                    "\n   {} handshake from {} — invite rejected",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::DisconnectPeer { peer_id })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        }

                        let invite_did = match invite.canonical_did() {
                            Ok(did) => did,
                            Err(e) => {
                                tracing::warn!(
                                    from = %visible_sender_did,
                                    %e,
                                    "Handshake invite proof carries invalid identity"
                                );
                                println!(
                                    "\n   {} handshake from {} — invite does not belong to this agent",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::DisconnectPeer { peer_id })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        };

                        if invite_did != our_did_msg
                            || invite.verifying_key != keypair_msg.verifying_key.to_bytes()
                        {
                            tracing::warn!(
                                from = %visible_sender_did,
                                invite_did = %crate::agent::contact_identity::displayed_did(&invite_did),
                                "Handshake invite proof not issued for this agent"
                            );
                            println!(
                                "\n   {} handshake from {} — invite does not belong to this agent",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeer { peer_id })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }

                        let invite_already_used =
                            direct_invite_already_used(&used_invites_msg, invite_code).await;
                        if invite_already_used {
                            tracing::warn!(from = %visible_sender_did, "Handshake invite proof already consumed");
                            println!(
                                "\n   {} handshake from {} — invite already used",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeerWithNotice {
                                    peer_id,
                                    notice_kind: DisconnectNoticeKind::InviteRejectedUsed,
                                })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }

                        if should_apply_manual_disconnect_policy_after_invite_use_check(
                            locally_manually_disconnected,
                            did_explicitly_blocked,
                            invite_already_used,
                        ) {
                            tracing::info!(
                                sender_did = %visible_sender_did,
                                peer_id = %peer_id,
                                "Inbound invite handshake rejected by local manual disconnect policy"
                            );
                            println!(
                                "\n   {} handshake from {} — peer was disconnected locally",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeerWithNotice {
                                    peer_id,
                                    notice_kind: DisconnectNoticeKind::ManualDisconnect,
                                })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }

                        let blocked = {
                            let gate = incoming_connect_gate_msg.lock().await;
                            gate.is_block_all() || gate.is_did_blocked(&request.sender_did)
                        };
                        if blocked {
                            tracing::info!(
                                sender_did = %visible_sender_did,
                                peer_id = %peer_id,
                                "Blocked invite-based first contact rejected before invite consumption"
                            );
                            {
                                let mut a = audit_msg.lock().await;
                                a.record(
                                    "INVITE_CONTACT_BLOCKED",
                                    &our_did_msg,
                                    &format!(
                                        "from_did={} peer_id={} delivery=direct_invite",
                                        request.sender_did, peer_id
                                    ),
                                );
                            }
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeer { peer_id })
                                .await;
                            continue;
                        }

                        if !try_reserve_direct_invite_use(
                            &used_invites_msg,
                            used_invites_path_msg.as_ref(),
                            used_invites_persist_key_msg.as_ref(),
                            invite_code,
                        )
                        .await
                        {
                            tracing::warn!(
                                from = %visible_sender_did,
                                "Handshake invite proof became consumed during concurrent verification"
                            );
                            println!(
                                "\n   {} handshake from {} — invite already used",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeerWithNotice {
                                    peer_id,
                                    notice_kind: DisconnectNoticeKind::InviteRejectedUsed,
                                })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                        invite_proof_msg.insert(
                            peer_id.to_string(),
                            INVITE_RESPONSE_BOUND_MARKER.to_string(),
                        );
                    }

                    let peer_acked_current_handshake =
                        if matches!(transport_mode_msg, TransportMode::Internet) {
                            note_iroh_handshake_received(
                                &iroh_handshake_sync_msg,
                                &peer_id,
                                &request.message_id,
                            );
                            note_iroh_handshake_ack(
                                &iroh_handshake_sync_msg,
                                &peer_id,
                                ack_handshake_message_id.as_deref(),
                            )
                        } else {
                            false
                        };
                    let live_known_ratchet_dh = peers_msg
                        .get(&pid_str)
                        .and_then(|peer| peer.ratchet_dh_public)
                        .or_else(|| {
                            peers_msg
                                .iter()
                                .find(|entry| entry.value().did == request.sender_did)
                                .and_then(|entry| entry.value().ratchet_dh_public)
                        });
                    let mut allow_ack_only_iroh_handshake = false;
                    let mut allow_trusted_reconnect_probe = false;
                    let mut allow_invite_bound_hybrid_defer = false;

                    if strict_pqc_mode {
                        let pqc_ready = kyber_key.is_some() && peer_pqc_enforced;
                        let identity_ready = verifying_key.is_some();
                        let peer_supplied_hybrid_ready = peer_hybrid_ratchet_kdf_suite.as_deref()
                            == Some(HYBRID_RATCHET_KDF_SUITE_V1)
                            && peer_hybrid_ratchet_ciphertext.is_some();
                        let local_pending_hybrid_ready = pending_hybrid_ratchet_inits_msg
                            .get(&peer_id.to_string())
                            .is_some_and(|pending| {
                                pending.suite == HYBRID_RATCHET_KDF_SUITE_V1
                                    && pending
                                        .expected_did
                                        .as_deref()
                                        .map_or(true, |expected| expected == request.sender_did)
                            });
                        let hybrid_ready = local_pending_hybrid_ready || peer_supplied_hybrid_ready;
                        let (has_existing_ratchet_session, persisted_session_ratchet_dh) = {
                            let rmgr = ratchet_mgr_msg.lock().await;
                            (
                                rmgr.has_session(&request.sender_did),
                                rmgr.session_remote_dh_public(&request.sender_did),
                            )
                        };
                        let ratchet_matches_known_peer =
                            ack_only_iroh_handshake_matches_trusted_ratchet(
                                peer_ratchet_dh,
                                live_known_ratchet_dh,
                                persisted_session_ratchet_dh,
                            );
                        allow_ack_only_iroh_handshake =
                            matches!(transport_mode_msg, TransportMode::Internet)
                                && should_accept_ack_only_iroh_handshake(
                                    peer_acked_current_handshake,
                                    has_existing_ratchet_session,
                                    ratchet_matches_known_peer,
                                    hybrid_ready,
                                );
                        allow_trusted_reconnect_probe = should_allow_trusted_reconnect_probe(
                            &transport_mode_msg,
                            peer_acked_current_handshake,
                            has_existing_ratchet_session,
                            ratchet_matches_known_peer,
                            hybrid_ready,
                        );
                        allow_invite_bound_hybrid_defer = inbound_invite_code.is_some()
                            && pqc_ready
                            && identity_ready
                            && peer_ratchet_dh.is_some()
                            && peer_aegis_supported
                            && !hybrid_ready;
                        let ratchet_ready = peer_ratchet_dh.is_some()
                            && peer_aegis_supported
                            && (hybrid_ready
                                || allow_ack_only_iroh_handshake
                                || allow_trusted_reconnect_probe
                                || allow_invite_bound_hybrid_defer);
                        if !(pqc_ready && identity_ready && ratchet_ready) {
                            tracing::warn!(
                                from = %visible_sender_did,
                                pqc_ready,
                                identity_ready,
                                peer_supplied_hybrid_ready,
                                local_pending_hybrid_ready,
                                hybrid_ready,
                                ratchet_ready,
                                "Strict mode handshake rejected — missing mandatory crypto capabilities"
                            );
                            println!(
                                "\n   {} handshake from {} — strict PQC/ratchet capabilities required",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                    }

                    // ── KEY CONTINUITY VERIFICATION ──────────────────────────
                    // If we already have an X25519 or Kyber key for this peer
                    // (from invite or a previous handshake), verify the new key
                    // matches. A mismatch means either:
                    //   (a) MITM attack substituting encryption keys, or
                    //   (b) peer re-generated identity (legitimate but rare)
                    // In both cases, ALERT the user loudly.
                    let mut key_mismatch = false;
                    if let Some(new_key) = x25519_key {
                        // Check by PeerId (primary) and DID (fallback)
                        let existing_key = peers_msg
                            .get(&pid_str)
                            .and_then(|p| p.x25519_public_key)
                            .or_else(|| {
                                // Also check by DID in case PeerId changed
                                peers_msg
                                    .iter()
                                    .find(|e| e.value().did == request.sender_did)
                                    .and_then(|e| e.value().x25519_public_key)
                            });

                        if let Some(old_key) = existing_key {
                            if old_key != new_key {
                                key_mismatch = true;
                                println!(
                                    "\n   {}",
                                    "╔══════════════════════════════════════════════════════════╗"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {} {}",
                                    "║  SECURITY ALERT: ENCRYPTION KEY CHANGED!".red().bold(),
                                    "                ║".red().bold()
                                );
                                println!(
                                    "   {}",
                                    "║  This could indicate a Man-in-the-Middle attack.       ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "║  The peer's X25519 encryption key does NOT match the   ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "║  previously known key (from invite or prior handshake).║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "╠══════════════════════════════════════════════════════════╣"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}  Peer: {} ({})",
                                    "║".red().bold(),
                                    request.sender_name.cyan(),
                                    visible_sender_did.dimmed()
                                );
                                println!(
                                    "   {}  Old key: {}",
                                    "║".red().bold(),
                                    hex::encode(old_key).dimmed()
                                );
                                println!(
                                    "   {}  New key: {}",
                                    "║".red().bold(),
                                    hex::encode(new_key).yellow()
                                );
                                println!(
                                    "   {}",
                                    "║                                                        ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "║  REJECTING HANDSHAKE — messages will NOT be encrypted  ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "║  to this key. If peer legitimately re-keyed, reconnect  ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "║  using a fresh /connect <invite> after verification.   ║"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "   {}",
                                    "╚══════════════════════════════════════════════════════════╝"
                                        .red()
                                        .bold()
                                );
                                // Keep the OLD trusted key — do not accept the new one
                                x25519_key = Some(old_key);
                                // Keep old kyber key too
                                if let Some(old_kyber) = peers_msg
                                    .get(&pid_str)
                                    .and_then(|p| p.kyber_public_key.clone())
                                {
                                    kyber_key = Some(old_kyber);
                                }
                            }
                        }
                    }

                    // ── KYBER KEY CONTINUITY VERIFICATION ─────────────────────
                    // Same principle for PQC keys: if we already have a Kyber
                    // public key for this peer and the new one differs, it's
                    // either a MITM key-swap attack on the PQC layer or a
                    // legitimate re-key. Alert loudly and reject.
                    if !key_mismatch {
                        if let Some(ref new_kyber) = kyber_key {
                            let existing_kyber = peers_msg
                                .get(&pid_str)
                                .and_then(|p| p.kyber_public_key.clone())
                                .or_else(|| {
                                    peers_msg
                                        .iter()
                                        .find(|e| e.value().did == request.sender_did)
                                        .and_then(|e| e.value().kyber_public_key.clone())
                                });

                            if let Some(ref old_kyber) = existing_kyber {
                                if old_kyber != new_kyber {
                                    key_mismatch = true;
                                    println!(
                                        "\n   {}",
                                        "╔══════════════════════════════════════════════════════════╗".red().bold()
                                    );
                                    println!(
                                        "   {} {}",
                                        "║  SECURITY ALERT: PQC KYBER KEY CHANGED!".red().bold(),
                                        "                 ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "║  The peer's Kyber-1024 post-quantum key does NOT match ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "║  the previously known key. This could indicate a MITM  ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "║  key-substitution attack targeting the PQC layer.      ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "╠══════════════════════════════════════════════════════════╣".red().bold()
                                    );
                                    println!(
                                        "   {}  Peer: {} ({})",
                                        "║".red().bold(),
                                        request.sender_name.cyan(),
                                        visible_sender_did.dimmed()
                                    );
                                    println!(
                                        "   {}  Old Kyber: {}...",
                                        "║".red().bold(),
                                        hex::encode(&old_kyber[..32.min(old_kyber.len())]).dimmed()
                                    );
                                    println!(
                                        "   {}  New Kyber: {}...",
                                        "║".red().bold(),
                                        hex::encode(&new_kyber[..32.min(new_kyber.len())]).yellow()
                                    );
                                    println!(
                                        "   {}",
                                        "║                                                        ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "║  REJECTING — keeping trusted Kyber key.                ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "║  Reconnect with fresh /connect <invite> to accept.     ║".red().bold()
                                    );
                                    println!(
                                        "   {}",
                                        "╚══════════════════════════════════════════════════════════╝".red().bold()
                                    );
                                    // Keep the OLD trusted Kyber key
                                    kyber_key = Some(old_kyber.clone());
                                    // Also reject X25519 if it was new (coordinated MITM)
                                    if let Some(old_x25519) =
                                        peers_msg.get(&pid_str).and_then(|p| p.x25519_public_key)
                                    {
                                        x25519_key = Some(old_x25519);
                                    }
                                }
                            }
                        }
                    }

                    let existing_peer = peers_msg.get(&pid_str).map(|entry| entry.value().clone());
                    let live_session_already_authenticated =
                        iroh_stable_id.is_some_and(|stable_id| {
                            is_authenticated_iroh_session(
                                &iroh_authenticated_sessions_msg,
                                &peer_id,
                                stable_id,
                            )
                        });

                    let info = PeerInfo {
                        peer_id,
                        did: request.sender_did.clone(),
                        name: request.sender_name.clone(),
                        role: DEFAULT_AGENT_ROLE.to_string(),
                        onion_address: peer_onion.clone(),
                        tcp_address: if matches!(
                            transport_mode_msg,
                            TransportMode::Internet | TransportMode::Tor
                        ) {
                            None
                        } else {
                            peers_msg
                                .get(&pid_str)
                                .and_then(|peer| peer.tcp_address.clone())
                        },
                        iroh_endpoint_addr: peer_iroh_endpoint_addr.or_else(|| {
                            peers_msg
                                .get(&pid_str)
                                .and_then(|peer| peer.iroh_endpoint_addr.clone())
                        }),
                        onion_port: peers_msg.get(&pid_str).map_or(9090, |peer| peer.onion_port),
                        x25519_public_key: x25519_key,
                        kyber_public_key: kyber_key.clone(),
                        verifying_key,
                        aegis_supported: peer_aegis_supported,
                        ratchet_dh_public: peer_ratchet_dh,
                    };

                    let key_status = if key_mismatch {
                        "KEY MISMATCH — using old trusted key".red().bold()
                    } else if x25519_key.is_some() && verifying_key.is_some() {
                        "E2EE + SigVerify ready".green().bold()
                    } else if x25519_key.is_some() {
                        "E2EE ready".green().bold()
                    } else {
                        "no E2EE key".yellow()
                    };

                    let onion_label = if let Some(ref onion) = peer_onion {
                        format!(
                            " [{}]",
                            format!("{}.onion", onion_prefix(onion, 8)).magenta()
                        )
                    } else {
                        String::new()
                    };
                    let should_emit_connected_notice = should_emit_iroh_connected_notice(
                        &transport_mode_msg,
                        existing_peer.as_ref(),
                        &request.sender_did,
                        live_session_already_authenticated,
                    );
                    let invite_consumer_reciprocal_pending =
                        take_invite_consumer_reciprocal_pending(&invite_proof_msg, &peer_id);
                    let blocked_incoming_reconnect = if locally_manually_disconnected {
                        true
                    } else if did_explicitly_blocked {
                        true
                    } else {
                        let trusted_sender = {
                            let store = peer_store_msg.lock().await;
                            is_trusted_peer_identity(&request.sender_did, &peers_msg, &store)
                        };
                        if trusted_sender {
                            false
                        } else {
                            let gate = incoming_connect_gate_msg.lock().await;
                            gate.is_block_all() || gate.is_did_blocked(&request.sender_did)
                        }
                    };
                    if blocked_incoming_reconnect {
                        tracing::info!(
                            sender_did = %visible_sender_did,
                            peer_id = %peer_id,
                            "Direct reconnect rejected by local disconnect/connect policy"
                        );
                        println!(
                            "\n   {} reconnect from {} — peer was disconnected locally",
                            "SECURITY REJECT:".red().bold(),
                            request.sender_name.cyan()
                        );
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::DisconnectPeerWithNotice {
                                peer_id,
                                notice_kind: DisconnectNoticeKind::ManualDisconnect,
                            })
                            .await;
                        print_prompt(&agent_name_msg);
                        continue;
                    }

                    peers_msg.insert(pid_str, info.clone());
                    if let Some(stable_id) = iroh_stable_id {
                        note_iroh_authenticated_session(
                            &iroh_authenticated_sessions_msg,
                            &peer_id,
                            stable_id,
                        );
                    }
                    direct_peer_dids_msg.insert(request.sender_did.clone(), true);
                    sync_active_direct_prompt_target(
                        &peers_msg,
                        &active_chat_target_did_msg,
                        &direct_peer_dids_msg,
                        Some(&active_chat_target_group_label_msg),
                    );
                    if matches!(transport_mode_msg, TransportMode::Tor) {
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::RebindTorTransferPeer {
                                peer_id,
                                peer_did: request.sender_did.clone(),
                                peer_name: request.sender_name.clone(),
                            })
                            .await;
                    }
                    {
                        let mut offline = remote_offline_dids_msg.lock().await;
                        offline.remove(&request.sender_did);
                    }
                    {
                        let mut r = rbac_msg.write().await;
                        r.register_agent_by_role(&request.sender_did, DEFAULT_AGENT_ROLE);
                    }
                    if should_emit_connected_notice {
                        emit_headless_direct_peer_event(
                            "connected",
                            &request.sender_did,
                            &request.sender_name,
                            Some(&peer_id.to_string()),
                            if x25519_key.is_some() && verifying_key.is_some() {
                                "ready"
                            } else {
                                "connected"
                            },
                            inbound_invite_code.as_ref().map(|_| "invite_linked"),
                        );

                        print_async_notice(
                            &agent_name_msg,
                            format!(
                                "   {} {} ({}) — {}{}",
                                "Peer connected:".green().bold(),
                                request.sender_name.cyan(),
                                visible_sender_did.dimmed(),
                                key_status,
                                onion_label
                            ),
                        );
                    }

                    if inbound_invite_code.is_some() {
                        print_async_notice(
                            &agent_name_msg,
                            format!(
                                "   {} {} ({})",
                                "Direct member linked:".dimmed(),
                                request.sender_name.cyan(),
                                visible_sender_did.dimmed()
                            ),
                        );
                    }

                    // ── Initialize Double Ratchet session for forward secrecy ──
                    // Only init if peer sent ratchet DH key in handshake
                    let mut needs_final_iroh_bootstrap_ack = false;
                    let mut needs_iroh_hybrid_ack_before_bootstrap = false;
                    if allow_ack_only_iroh_handshake
                        && matches!(transport_mode_msg, TransportMode::Internet)
                        && keypair_msg.did < request.sender_did
                        && peer_acked_current_handshake
                    {
                        tracing::debug!(
                            peer = %visible_sender_did,
                            "Accepted ack-only iroh handshake for existing live session; sending deferred ratchet bootstrap"
                        );
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::SendRatchetBootstrap {
                                peer_id,
                                peer_did: request.sender_did.clone(),
                            })
                            .await;
                    }
                    if allow_trusted_reconnect_probe {
                        tracing::debug!(
                            peer = %visible_sender_did,
                            "Accepted trusted reconnect probe without hybrid bootstrap; preserving existing ratchet session"
                        );
                    }
                    if !allow_ack_only_iroh_handshake && !allow_trusted_reconnect_probe {
                        if let (Some(ref pk), Some(rdh), Some(peer_vk)) =
                            (x25519_key, peer_ratchet_dh, verifying_key)
                        {
                            let ss = keypair_msg
                                .encryption_secret
                                .diffie_hellman(&x25519_dalek::PublicKey::from(*pk));
                            let is_initiator = keypair_msg.did < request.sender_did;
                            let local_x25519_public = keypair_msg.x25519_public_key_bytes();
                            let local_verifying_key = keypair_msg.verifying_key.to_bytes();
                            let local_ratchet_secret =
                                x25519_dalek::StaticSecret::from(ratchet_init_secret_msg);
                            let local_handshake_ratchet_public =
                                *x25519_dalek::PublicKey::from(&local_ratchet_secret).as_bytes();
                            let mut ratchet_seed = ss.as_bytes().to_vec();
                            let mut hybrid_ready = false;
                            let mut used_local_pending_hybrid_init = false;
                            let mut used_peer_supplied_hybrid_init = false;
                            if let Some(pending) = take_pending_hybrid_ratchet_init(
                                &pending_hybrid_ratchet_inits_msg,
                                &peer_id,
                                &request.sender_did,
                            ) {
                                if pending.suite == HYBRID_RATCHET_KDF_SUITE_V1 {
                                    ratchet_seed = derive_hybrid_ratchet_seed(
                                        ss.as_bytes(),
                                        pending.kyber_shared_secret.as_ref(),
                                        &keypair_msg.did,
                                        &local_verifying_key,
                                        &local_x25519_public,
                                        &local_handshake_ratchet_public,
                                        &request.sender_did,
                                        &peer_vk,
                                        pk,
                                        &rdh,
                                    )
                                    .to_vec();
                                    hybrid_ready = true;
                                    used_local_pending_hybrid_init = true;
                                    tracing::info!(
                                        peer = %visible_sender_did,
                                        initiator = is_initiator,
                                        "Using locally staged hybrid ratchet init"
                                    );
                                } else {
                                    tracing::warn!(
                                        peer = %visible_sender_did,
                                        suite = %pending.suite,
                                        "Unsupported pending hybrid ratchet suite"
                                    );
                                }
                            } else if peer_hybrid_ratchet_kdf_suite.as_deref()
                                == Some(HYBRID_RATCHET_KDF_SUITE_V1)
                            {
                                if let Some(ref kyber_ct) = peer_hybrid_ratchet_ciphertext {
                                    match pqc_kyber::decapsulate(
                                        kyber_ct,
                                        keypair_msg.kyber_secret.as_slice(),
                                    ) {
                                        Ok(shared_secret) => {
                                            let mut kyber_shared_secret = shared_secret.to_vec();
                                            ratchet_seed = derive_hybrid_ratchet_seed(
                                                ss.as_bytes(),
                                                &kyber_shared_secret,
                                                &keypair_msg.did,
                                                &local_verifying_key,
                                                &local_x25519_public,
                                                &local_handshake_ratchet_public,
                                                &request.sender_did,
                                                &peer_vk,
                                                pk,
                                                &rdh,
                                            )
                                            .to_vec();
                                            kyber_shared_secret.zeroize();
                                            hybrid_ready = true;
                                            used_peer_supplied_hybrid_init = true;
                                            tracing::info!(
                                                peer = %visible_sender_did,
                                                initiator = is_initiator,
                                                "Using peer-supplied hybrid ratchet init"
                                            );
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                peer = %visible_sender_did,
                                                ?error,
                                                "Hybrid ratchet Kyber decapsulation failed"
                                            );
                                        }
                                    }
                                }
                            }

                            if strict_pqc_mode && !hybrid_ready {
                                if allow_invite_bound_hybrid_defer {
                                    tracing::info!(
                                        peer = %visible_sender_did,
                                        initiator = is_initiator,
                                        "Deferring strict hybrid ratchet init until reciprocal invite-bound handshake"
                                    );
                                } else {
                                    tracing::warn!(
                                        peer = %visible_sender_did,
                                        initiator = is_initiator,
                                        "Strict mode ratchet init rejected — hybrid seed unavailable"
                                    );
                                    println!(
                                        "\n   {} handshake from {} — hybrid ratchet init required",
                                        "SECURITY REJECT:".red().bold(),
                                        request.sender_name.cyan()
                                    );
                                    print_prompt(&agent_name_msg);
                                    continue;
                                }
                            }

                            if !allow_invite_bound_hybrid_defer {
                                // Use peer's RATCHET DH key (not X25519 identity key)
                                let remote_ratchet_dh = x25519_dalek::PublicKey::from(rdh);
                                let mut rmgr = ratchet_mgr_msg.lock().await;
                                rmgr.reset_and_init(
                                    &request.sender_did,
                                    &ratchet_seed,
                                    &remote_ratchet_dh,
                                    is_initiator,
                                    if is_initiator {
                                        None
                                    } else {
                                        Some(ratchet_init_secret_msg)
                                    },
                                );
                                tracing::info!(
                                    peer = %visible_sender_did,
                                    initiator = is_initiator,
                                    hybrid = hybrid_ready,
                                    "Double Ratchet session initialized"
                                );
                                drop(rmgr);

                                if matches!(transport_mode_msg, TransportMode::Internet) {
                                    if used_peer_supplied_hybrid_init {
                                        needs_iroh_hybrid_ack_before_bootstrap = true;
                                        tracing::debug!(
                                            peer = %visible_sender_did,
                                            "Deferring ratchet bootstrap until peer acknowledges peer-supplied hybrid init handshake"
                                        );
                                    } else if is_initiator && peer_acked_current_handshake {
                                        let _ = cmd_tx_msg
                                            .send(NetworkCommand::SendRatchetBootstrap {
                                                peer_id,
                                                peer_did: request.sender_did.clone(),
                                            })
                                            .await;
                                    } else if is_initiator {
                                        tracing::debug!(
                                            peer = %visible_sender_did,
                                            "Deferring ratchet bootstrap until peer acknowledges current handshake"
                                        );
                                    }
                                    let readiness = direct_chat_readiness(
                                        &peers_msg,
                                        &ratchet_mgr_msg,
                                        &request.sender_did,
                                    )
                                    .await;
                                    needs_final_iroh_bootstrap_ack =
                                        should_send_final_iroh_bootstrap_ack(
                                            peer_acked_current_handshake,
                                            is_initiator,
                                            readiness,
                                        );
                                } else if used_local_pending_hybrid_init {
                                    let _ = cmd_tx_msg
                                        .send(NetworkCommand::SendRatchetBootstrap {
                                            peer_id,
                                            peer_did: request.sender_did.clone(),
                                        })
                                        .await;
                                } else if is_initiator
                                    && inbound_invite_code.is_none()
                                    && !used_peer_supplied_hybrid_init
                                {
                                    let _ = cmd_tx_msg
                                        .send(NetworkCommand::SendRatchetBootstrap {
                                            peer_id,
                                            peer_did: request.sender_did.clone(),
                                        })
                                        .await;
                                } else if is_initiator && !used_peer_supplied_hybrid_init {
                                    let cmd_tx = cmd_tx_msg.clone();
                                    let peer_did = request.sender_did.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(tokio::time::Duration::from_millis(150))
                                            .await;
                                        let _ = cmd_tx
                                            .send(NetworkCommand::SendRatchetBootstrap {
                                                peer_id,
                                                peer_did,
                                            })
                                            .await;
                                    });
                                }

                                match should_send_tor_peer_supplied_hybrid_followup(
                                    &transport_mode_msg,
                                    used_peer_supplied_hybrid_init,
                                    is_initiator,
                                    invite_consumer_reciprocal_pending,
                                ) {
                                    TorPeerSuppliedHybridFollowup::Bootstrap => {
                                        let _ = cmd_tx_msg
                                            .send(NetworkCommand::SendRatchetBootstrap {
                                                peer_id,
                                                peer_did: request.sender_did.clone(),
                                            })
                                            .await;
                                    }
                                    TorPeerSuppliedHybridFollowup::Handshake => {
                                        invite_proof_msg.insert(
                                            peer_id.to_string(),
                                            INVITE_RESPONSE_BOUND_MARKER.to_string(),
                                        );
                                        let _ = cmd_tx_msg
                                            .send(NetworkCommand::EnsurePeerHandshake {
                                                peer_id,
                                                ack_handshake_message_id: None,
                                                trusted_known_peer_bootstrap: false,
                                            })
                                            .await;
                                    }
                                    TorPeerSuppliedHybridFollowup::None => {}
                                }
                            }
                        }
                    }

                    // Save to known peers for auto-reconnect (respects log mode)
                    let auto_reconnect_enabled = {
                        let mut ps = peer_store_msg.lock().await;
                        let existing = ps.get(&request.sender_did).cloned().map(|mut known| {
                            if !should_accept_remote_tor_onion_route(
                                &transport_mode_msg,
                                &our_did_msg,
                                &request.sender_did,
                                local_onion_address_msg.as_deref(),
                                known.onion_address.as_deref(),
                            ) {
                                tracing::warn!(
                                    did = %visible_sender_did,
                                    onion = ?known.onion_address,
                                    local_onion = ?local_onion_address_msg,
                                    "Discarding persisted Tor reconnect route that points at the local onion service"
                                );
                                known.onion_address = None;
                            }
                            known
                        });
                        let auto_reconnect =
                            desired_auto_reconnect(&log_mode_msg, existing.as_ref());
                        let trusted_new_peer =
                            inbound_invite_code.is_some() || trusted_live_peer_slot;
                        if should_persist_known_peer(
                            &log_mode_msg,
                            existing.as_ref(),
                            trusted_new_peer,
                        ) {
                            ps.upsert(build_known_peer(&info, existing.as_ref(), auto_reconnect));
                        }
                        auto_reconnect
                    };
                    print_auto_reconnect_state(&request.sender_did, auto_reconnect_enabled);

                    if matches!(transport_mode_msg, TransportMode::Internet)
                        && !peer_acked_current_handshake
                    {
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::EnsurePeerHandshake {
                                peer_id,
                                ack_handshake_message_id: Some(request.message_id.clone()),
                                trusted_known_peer_bootstrap: false,
                            })
                            .await;
                    } else if matches!(transport_mode_msg, TransportMode::Internet)
                        && (needs_iroh_hybrid_ack_before_bootstrap
                            || needs_final_iroh_bootstrap_ack)
                    {
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::EnsurePeerHandshake {
                                peer_id,
                                ack_handshake_message_id: Some(request.message_id.clone()),
                                trusted_known_peer_bootstrap: false,
                            })
                            .await;
                    } else if matches!(transport_mode_msg, TransportMode::Tor)
                        && allow_trusted_reconnect_probe
                    {
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::EnsurePeerHandshake {
                                peer_id,
                                ack_handshake_message_id: None,
                                trusted_known_peer_bootstrap: true,
                            })
                            .await;
                    } else if allow_invite_bound_hybrid_defer {
                        let _ = cmd_tx_msg
                            .send(NetworkCommand::EnsurePeerHandshake {
                                peer_id,
                                ack_handshake_message_id: None,
                                trusted_known_peer_bootstrap: false,
                            })
                            .await;
                    }

                    {
                        let mut a = audit_msg.lock().await;
                        a.record(
                            "PEER_CONNECT",
                            &request.sender_did,
                            &format!(
                                "name={} onion={}",
                                request.sender_name,
                                peer_onion.as_deref().unwrap_or("none")
                            ),
                        );
                    }

                    print_prompt(&agent_name_msg);
                }

                // ── Chat message ─────────────────────────────────────────
                MessageKind::Chat => {
                    let text = if let Some(text) = predecoded_chat_text.take() {
                        text
                    } else {
                        match decode_incoming_chat_text(
                            &ratchet_mgr_msg,
                            &pending_hybrid_ratchet_inits_msg,
                            &keypair_msg,
                            &peers_msg,
                            &transport_mode_msg,
                            &peer_id,
                            &request.sender_did,
                            ratchet_init_secret_msg,
                            &request.payload,
                        )
                        .await
                        {
                            IncomingChatDecode::Text(text) => text,
                            IncomingChatDecode::DecryptError(e) => {
                                tracing::warn!(from = %visible_sender_did, %e, "Ratchet decrypt failed — message rejected");
                                println!(
                                    "\n   {} from {} — ratchet decrypt failed: {}",
                                    "E2EE REJECT:".red().bold(),
                                    request.sender_name.cyan(),
                                    e
                                );
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                            IncomingChatDecode::ParseError(e) => {
                                tracing::warn!(from = %visible_sender_did, %e, "Ratchet parse failed — message rejected");
                                println!(
                                    "\n   {} from {} — ratchet parse failed: {}",
                                    "E2EE REJECT:".red().bold(),
                                    request.sender_name.cyan(),
                                    e
                                );
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                            IncomingChatDecode::LegacyEnvelope => {
                                tracing::warn!(
                                    from = %visible_sender_did,
                                    "Legacy chat envelope (0x01) rejected — ratcheted E2EE required"
                                );
                                println!(
                                    "\n   {} from {} — legacy E2EE disabled (ratcheted 0x02 required)",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                            IncomingChatDecode::Plaintext => {
                                tracing::warn!(
                                    from = %visible_sender_did,
                                    "PLAINTEXT message rejected — no encryption magic byte (fail-closed)"
                                );
                                println!(
                                    "\n   {} from {} — plaintext message rejected (E2EE required)",
                                    "SECURITY REJECT:".red().bold(),
                                    request.sender_name.cyan()
                                );
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        }
                    };

                    // If we reached here, signature was already cryptographically verified
                    // in the pipeline above (Ed25519 verify_strict passed)
                    let sig_indicator = if request.signature.len() == 64 {
                        "[sig verified]".green().to_string()
                    } else {
                        "[sig ok]".green().to_string()
                    };

                    // Internal ratchet bootstrap frame is protocol traffic, not user-visible chat.
                    if text.as_bytes() == RATCHET_BOOTSTRAP_MARKER {
                        tracing::debug!(from = %visible_sender_did, "Ratchet bootstrap received");
                        continue;
                    }

                    // Check if sender has E2EE key
                    let e2ee_tag = if peers_msg
                        .get(&pid_str)
                        .map(|p| p.x25519_public_key.is_some())
                        .unwrap_or(false)
                    {
                        "[E2EE]".green().to_string()
                    } else {
                        String::new()
                    };

                    println!(
                        "\n   {}{} {}: {}",
                        sig_indicator,
                        e2ee_tag,
                        request.sender_name.cyan().bold(),
                        text
                    );
                    emit_headless_direct_message_event(
                        "incoming",
                        &request.sender_did,
                        &request.sender_name,
                        &text,
                    );

                    {
                        let mut a = audit_msg.lock().await;
                        a.record(
                            "MSG_RECV",
                            &request.sender_did,
                            &format!("sig_verified=true len={}", request.payload.len()),
                        );
                    }

                    print_prompt(&agent_name_msg);
                }

                // ── File transfer ────────────────────────────────────────
                MessageKind::FileTransfer => {
                    if !local_approved_reinject {
                        let policy = {
                            let gate = transfer_decisions_msg.lock().await;
                            gate.policy_for_sender(&request.sender_did)
                        };
                        if matches!(policy, IncomingTransferPolicy::AskEveryTime) {
                            let decision_key = transfer_key.clone().unwrap_or_else(|| {
                                format!(
                                    "file|{}|{}|{}",
                                    request.sender_did, request.nonce, request.timestamp
                                )
                            });
                            let meta =
                                bincode::deserialize::<FileTransferPayload>(&request.payload)
                                    .ok()
                                    .map(|p| (p.filename, p.encrypted_size))
                                    .unwrap_or_else(|| ("unknown.bin".to_string(), 0));

                            let queued = {
                                let mut gate = transfer_decisions_msg.lock().await;
                                gate.queue_pending(PendingIncomingTransfer {
                                    peer_id,
                                    sender_did: request.sender_did.clone(),
                                    sender_name: request.sender_name.clone(),
                                    request: request.clone(),
                                    decision_key,
                                    kind: PendingTransferKind::File {
                                        filename: meta.0.clone(),
                                        encrypted_size: meta.1,
                                    },
                                })
                            };

                            if queued {
                                let visible_sender_did =
                                    crate::agent::contact_identity::displayed_did(
                                        &request.sender_did,
                                    );
                                let size_mb = meta.1 as f64 / (1024.0 * 1024.0);
                                print_async_notice(
                                    &agent_name_msg,
                                    format!(
                                        "\n   {} {} → {} ({:.1} MB, encrypted)\n   {} {}\n   {} /accept {}\n   {} /accept_always {}\n   {} /accept_ask {}\n   {} /reject {}",
                                        "Incoming file transfer pending approval:".yellow().bold(),
                                        request.sender_name.cyan(),
                                        meta.0.cyan(),
                                        size_mb,
                                        "Sender DID:".dimmed(),
                                        visible_sender_did.dimmed(),
                                        "Allow once:".dimmed(),
                                        visible_sender_did,
                                        "Always allow this sender:".dimmed(),
                                        visible_sender_did,
                                        "Ask on each transfer:".dimmed(),
                                        visible_sender_did,
                                        "Reject this transfer:".dimmed(),
                                        visible_sender_did
                                    ),
                                );
                                emit_transfer_event(
                                    "incoming_pending",
                                    "in",
                                    Some(&request.sender_did),
                                    Some(&request.sender_name),
                                    None,
                                    Some(&meta.0),
                                    Some("awaiting_receiver_decision"),
                                );
                            }
                            continue;
                        }
                    }

                    let inline_filename =
                        bincode::deserialize::<FileTransferPayload>(&request.payload)
                            .ok()
                            .map(|payload| payload.filename)
                            .filter(|value| !value.trim().is_empty());

                    let (received_dir, handoff) = {
                        let config = receive_dir_config_msg.lock().await;
                        match prepare_receive_target(
                            &log_mode_msg,
                            &config,
                            &request.sender_did,
                            &request.sender_name,
                        ) {
                            Ok(value) => value,
                            Err(e) => {
                                println!(
                                    "   {} could not prepare secure handoff target: {}",
                                    "SECURITY REJECT:".red().bold(),
                                    e
                                );
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        }
                    };

                    println!(
                        "\n   {} {} -> decrypting...",
                        "File transfer from:".yellow().bold(),
                        request.sender_name.cyan()
                    );

                    if let Err(e) = ensure_private_receive_dir(&received_dir) {
                        println!(
                            "   {} could not prepare receive directory: {}",
                            "SECURITY REJECT:".red().bold(),
                            e
                        );
                        print_prompt(&agent_name_msg);
                        continue;
                    }

                    let auto_accept_policy = {
                        let gate = transfer_decisions_msg.lock().await;
                        gate.policy_for_sender(&request.sender_did)
                    };
                    if !local_approved_reinject
                        && matches!(auto_accept_policy, IncomingTransferPolicy::AlwaysAccept)
                    {
                        emit_transfer_event(
                            "incoming_accepted",
                            "in",
                            Some(&request.sender_did),
                            Some(&request.sender_name),
                            None,
                            inline_filename.as_deref(),
                            Some("approved_by_policy_always_accept"),
                        );
                    }
                    let _ = cmd_tx_msg
                        .send(NetworkCommand::SendTransferStatus {
                            peer_id,
                            session_id: None,
                            request_message_id: Some(request.message_id.clone()),
                            filename: inline_filename.clone(),
                            status: "accepted".to_string(),
                            detail: Some("approved_by_receiver".to_string()),
                        })
                        .await;

                    match transfer::receive_encrypted_transfer_with_path(
                        &keypair_msg,
                        &request.payload,
                        &received_dir,
                        peers_msg.get(&pid_str).and_then(|p| p.verifying_key),
                    ) {
                        Ok(received) => {
                            let manifest = received.manifest;
                            {
                                let mut a = audit_msg.lock().await;
                                a.record(
                                    "FILE_RECV",
                                    &request.sender_did,
                                    &format!(
                                        "artifact_id={} size={} sha256={}",
                                        manifest.artifact_id,
                                        manifest.total_size,
                                        &manifest.sha256[..16]
                                    ),
                                );
                            }
                            if let Some((handoff_id, handoff_dir)) = handoff {
                                println!(
                                    "   {} {} ({} bytes) -> {}",
                                    "File staged for secure handoff:".green().bold(),
                                    manifest.sha256[..16].dimmed(),
                                    manifest.total_size,
                                    handoff_dir.display(),
                                );
                                emit_transfer_event_with_handoff(
                                    "incoming_staged",
                                    "in",
                                    Some(&request.sender_did),
                                    Some(&request.sender_name),
                                    None,
                                    inline_filename.as_deref(),
                                    Some("ghost_secure_handoff_ready"),
                                    Some(&handoff_id),
                                    Some(&handoff_dir),
                                );
                            } else {
                                println!(
                                    "   {} {} ({} bytes) -> {}",
                                    "File received:".green().bold(),
                                    manifest.sha256[..16].dimmed(),
                                    manifest.total_size,
                                    received.final_path.display(),
                                );
                                emit_transfer_event(
                                    "incoming_completed",
                                    "in",
                                    Some(&request.sender_did),
                                    Some(&request.sender_name),
                                    None,
                                    inline_filename.as_deref(),
                                    Some("file_received"),
                                );
                            }
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::SendTransferStatus {
                                    peer_id,
                                    session_id: None,
                                    request_message_id: Some(request.message_id.clone()),
                                    filename: inline_filename.clone(),
                                    status: "completed".to_string(),
                                    detail: Some("received_by_peer".to_string()),
                                })
                                .await;
                        }
                        Err(e) => {
                            if handoff.is_some() {
                                secure_wipe_dir_async(received_dir.clone()).await;
                            }
                            println!("   {} {}", "File transfer FAILED:".red().bold(), e);
                            tracing::error!("File transfer receive error: {}", e);
                            emit_transfer_event(
                                "incoming_failed",
                                "in",
                                Some(&request.sender_did),
                                Some(&request.sender_name),
                                None,
                                None,
                                Some(&format!("{}", e)),
                            );
                        }
                    }

                    print_prompt(&agent_name_msg);
                }

                // ── Chunked transfer: init ────────────────────────────────
                MessageKind::ChunkTransferInit => {
                    let visible_sender_did =
                        crate::agent::contact_identity::displayed_did(&request.sender_did);
                    match bincode::deserialize::<crate::network::protocol::ChunkTransferInitPayload>(
                        &request.payload,
                    ) {
                        Ok(init) => {
                            // Nested sender key in transfer init must match the
                            // authenticated outer peer identity.
                            if let Some(expected_vk) =
                                peers_msg.get(&pid_str).and_then(|p| p.verifying_key)
                            {
                                let expected_hex = hex::encode(expected_vk);
                                if init.sender_verifying_key_hex != expected_hex {
                                    tracing::warn!(
                                        peer_id = %pid_str,
                                        "ChunkTransferInit sender key mismatch with authenticated peer"
                                    );
                                    println!(
                                        "\n   {} {} (chunk init sender key mismatch)",
                                        "SECURITY REJECT:".red().bold(),
                                        request.sender_name.cyan()
                                    );
                                    print_prompt(&agent_name_msg);
                                    continue;
                                }
                            }

                            let mut resumed_received_chunks: Option<Vec<usize>> = None;
                            {
                                let mut sessions = chunked_sessions.lock().await;
                                if let Some(existing) = sessions.get_mut(&init.session_id) {
                                    if existing.can_auto_resume(&init, &request.sender_did) {
                                        existing.last_chunk_at =
                                            chrono::Utc::now().timestamp_millis() as u64;
                                        resumed_received_chunks =
                                            Some(existing.received_indices_sorted());
                                    }
                                }
                            }
                            if let Some(received_chunks) = resumed_received_chunks {
                                record_active_incoming_iroh_transfer(
                                    &active_incoming_iroh_transfers_msg,
                                    &init.session_id,
                                    &request.sender_did,
                                    &request.sender_name,
                                    init.total_chunks,
                                    received_chunks.len(),
                                );
                                let visible_sender_did =
                                    crate::agent::contact_identity::displayed_did(
                                        &request.sender_did,
                                    );
                                print_async_notice(
                                    &agent_name_msg,
                                    format!(
                                        "   {} {} ({}) continuing from chunk {}/{}",
                                        "Transfer resume:".green().bold(),
                                        request.sender_name.cyan(),
                                        visible_sender_did.dimmed(),
                                        received_chunks.len().saturating_add(1),
                                        init.total_chunks
                                    ),
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::SendTransferAccept {
                                        peer_id,
                                        session_id: init.session_id.clone(),
                                        received_chunks,
                                    })
                                    .await;
                                continue;
                            }

                            if !local_approved_reinject {
                                let policy = {
                                    let gate = transfer_decisions_msg.lock().await;
                                    gate.policy_for_sender(&request.sender_did)
                                };
                                if init.requires_reapproval
                                    || init.resume_requested
                                    || matches!(policy, IncomingTransferPolicy::AskEveryTime)
                                {
                                    let decision_key = transfer_key.clone().unwrap_or_else(|| {
                                        format!(
                                            "chunk_init|{}|{}|{}",
                                            request.sender_did, request.nonce, request.timestamp
                                        )
                                    });
                                    let queued = {
                                        let mut gate = transfer_decisions_msg.lock().await;
                                        gate.queue_pending(PendingIncomingTransfer {
                                            peer_id,
                                            sender_did: request.sender_did.clone(),
                                            sender_name: request.sender_name.clone(),
                                            request: request.clone(),
                                            decision_key,
                                            kind: PendingTransferKind::ChunkInit {
                                                session_id: init.session_id.clone(),
                                                total_chunks: init.total_chunks,
                                                sealed_v2: init.version >= 2,
                                                filename_hint: if init.version >= 2 {
                                                    None
                                                } else {
                                                    Some(init.filename.clone())
                                                },
                                                total_size_hint: if init.version >= 2 {
                                                    None
                                                } else {
                                                    Some(init.total_size)
                                                },
                                            },
                                        })
                                    };
                                    if queued {
                                        let visible_sender_did =
                                            crate::agent::contact_identity::displayed_did(
                                                &request.sender_did,
                                            );
                                        let prompt_target = visible_sender_did.clone();
                                        let header = if init.requires_reapproval
                                            || init.resume_requested
                                        {
                                            format!(
                                                "\n   {} {} ({}) (restart after reconnect, {} chunks)",
                                                "Incoming chunked transfer requires approval:"
                                                    .yellow()
                                                    .bold(),
                                                request.sender_name.cyan(),
                                                visible_sender_did.dimmed(),
                                                init.total_chunks
                                            )
                                        } else if init.version >= 2 {
                                            format!(
                                                "\n   {} {} ({}) ({} chunks, sealed v2)",
                                                "Incoming chunked transfer pending approval:"
                                                    .yellow()
                                                    .bold(),
                                                request.sender_name.cyan(),
                                                visible_sender_did.dimmed(),
                                                init.total_chunks
                                            )
                                        } else {
                                            let mb = init.total_size as f64 / (1024.0 * 1024.0);
                                            format!(
                                                "\n   {} {} ({}) → {} ({:.1} MB, {} chunks)",
                                                "Incoming chunked transfer pending approval:"
                                                    .yellow()
                                                    .bold(),
                                                request.sender_name.cyan(),
                                                visible_sender_did.dimmed(),
                                                init.filename.cyan(),
                                                mb,
                                                init.total_chunks
                                            )
                                        };
                                        print_async_notice(
                                            &agent_name_msg,
                                            format!(
                                                "{header}\n   {} /accept {}\n   {} /accept_always {}\n   {} /accept_ask {}\n   {} /reject {}",
                                                "Allow once:".dimmed(),
                                                prompt_target,
                                                "Always allow this sender:".dimmed(),
                                                prompt_target,
                                                "Ask on each transfer:".dimmed(),
                                                prompt_target,
                                                "Reject this transfer:".dimmed(),
                                                prompt_target
                                            ),
                                        );
                                        emit_transfer_event(
                                            "incoming_pending",
                                            "in",
                                            Some(&request.sender_did),
                                            Some(&request.sender_name),
                                            Some(&init.session_id),
                                            if init.version >= 2 {
                                                None
                                            } else {
                                                Some(&init.filename)
                                            },
                                            Some("awaiting_receiver_decision"),
                                        );
                                    }
                                    continue;
                                }
                            }

                            // Prevent unbounded receive-session growth (memory DoS).
                            let active =
                                active_receive_count.load(std::sync::atomic::Ordering::Relaxed);
                            if active >= MAX_ACTIVE_RECEIVE_SESSIONS {
                                tracing::warn!(
                                    active,
                                    limit = MAX_ACTIVE_RECEIVE_SESSIONS,
                                    from = %visible_sender_did,
                                    "ChunkTransferInit rejected: too many active receive sessions"
                                );
                                println!(
                                    "\n   {} too many active incoming transfers (limit {}).",
                                    "TRANSFER REJECTED:".red().bold(),
                                    MAX_ACTIVE_RECEIVE_SESSIONS
                                );
                                emit_transfer_event(
                                    "incoming_rejected",
                                    "in",
                                    Some(&request.sender_did),
                                    Some(&request.sender_name),
                                    Some(&init.session_id),
                                    None,
                                    Some("too_many_active_incoming_transfers"),
                                );
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::SendTransferReject {
                                        peer_id,
                                        session_id: Some(init.session_id.clone()),
                                        request_message_id: Some(request.message_id.clone()),
                                        reason: "too_many_active_incoming_transfers".to_string(),
                                    })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }

                            let is_sealed = init.version >= 2;
                            if is_sealed {
                                println!(
                                    "\n   {} {} ({} chunks, sealed v2 — metadata in chunk[0])",
                                    "Chunked transfer from:".yellow().bold(),
                                    request.sender_name.cyan(),
                                    init.total_chunks,
                                );
                            } else {
                                let total_mb = init.total_size as f64 / (1024.0 * 1024.0);
                                println!(
                                    "\n   {} {} → {} ({:.1} MB, {} chunks)",
                                    "Chunked transfer from:".yellow().bold(),
                                    request.sender_name.cyan(),
                                    init.filename.cyan(),
                                    total_mb,
                                    init.total_chunks,
                                );
                            }

                            let session_id = init.session_id.clone();
                            let recv_session = match ChunkedReceiveSession::new(
                                init,
                                request.sender_did.clone(),
                                request.sender_name.clone(),
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::error!("Transfer rejected: {}", e);
                                    println!("   {} {}", "Transfer REJECTED:".red().bold(), e);
                                    emit_transfer_event(
                                        "incoming_rejected",
                                        "in",
                                        Some(&request.sender_did),
                                        Some(&request.sender_name),
                                        Some(&session_id),
                                        None,
                                        Some(&format!("{}", e)),
                                    );
                                    let _ = cmd_tx_msg
                                        .send(NetworkCommand::SendTransferReject {
                                            peer_id,
                                            session_id: Some(session_id.clone()),
                                            request_message_id: Some(request.message_id.clone()),
                                            reason: format!("{}", e),
                                        })
                                        .await;
                                    continue;
                                }
                            };
                            let initial_received_chunks = recv_session.received_count;
                            let total_chunks = recv_session.init.total_chunks;

                            {
                                let mut sessions = chunked_sessions.lock().await;
                                let replaced = sessions.insert(session_id.clone(), recv_session);
                                if replaced.is_none() {
                                    active_receive_count
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            record_active_incoming_iroh_transfer(
                                &active_incoming_iroh_transfers_msg,
                                &session_id,
                                &request.sender_did,
                                &request.sender_name,
                                total_chunks,
                                initial_received_chunks,
                            );

                            tracing::info!(
                                session_id = %session_id,
                                from = %visible_sender_did,
                                sealed = is_sealed,
                                "Chunked receive session created"
                            );

                            // Tell sender to start streaming chunks only after we accepted init.
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::SendTransferAccept {
                                    peer_id,
                                    session_id,
                                    received_chunks: Vec::new(),
                                })
                                .await;
                        }
                        Err(e) => {
                            println!(
                                "\n   {} {}",
                                "ChunkTransferInit decode FAILED:".red().bold(),
                                e
                            );
                        }
                    }
                    print_prompt(&agent_name_msg);
                }

                // ── Chunked transfer: chunk data ─────────────────────────
                MessageKind::ChunkData => {
                    match bincode::deserialize::<crate::network::protocol::ChunkDataPayload>(
                        &request.payload,
                    ) {
                        Ok(chunk_payload) => {
                            let session_id = chunk_payload.session_id.clone();
                            let chunk_idx = chunk_payload.chunk_index;
                            let total = chunk_payload.total_chunks;

                            // Strip padding: if actual_encrypted_size > 0, the data was padded to 10MB
                            let actual_data = if chunk_payload.actual_encrypted_size > 0 {
                                chunked_transfer::strip_padding(
                                    &chunk_payload.encrypted_data,
                                    chunk_payload.actual_encrypted_size,
                                )
                                .to_vec()
                            } else {
                                chunk_payload.encrypted_data
                            };

                            // Convert to EncryptedChunk for verification
                            let encrypted_chunk = chunked_transfer::EncryptedChunk {
                                session_id: chunk_payload.session_id,
                                chunk_index: chunk_payload.chunk_index,
                                total_chunks: chunk_payload.total_chunks,
                                encrypted_data: actual_data,
                                key_envelope: chunk_payload.key_envelope,
                                signature: chunk_payload.signature,
                                merkle_proof: chunk_payload.merkle_proof,
                                chunk_sha256: chunk_payload.chunk_sha256,
                            };

                            let mut sessions = chunked_sessions.lock().await;

                            // For chunk[0] with sealed metadata: decrypt and apply to session
                            if chunk_idx == 0 {
                                if let (Some(sealed_data), Some(sealed_env)) = (
                                    &chunk_payload.sealed_metadata,
                                    &chunk_payload.sealed_metadata_key_envelope,
                                ) {
                                    match chunked_transfer::decrypt_sealed_metadata(
                                        sealed_data,
                                        sealed_env,
                                        &keypair_msg,
                                    ) {
                                        Ok(meta) => {
                                            if let Some(recv) = sessions.get_mut(&session_id) {
                                                let total_mb =
                                                    meta.total_size as f64 / (1024.0 * 1024.0);
                                                print_async_notice(
                                                    &agent_name_msg,
                                                    format!(
                                                        "   {} {} → {} ({:.1} MB)",
                                                        "Sealed metadata decrypted:".green(),
                                                        meta.filename.cyan(),
                                                        meta.classification.dimmed(),
                                                        total_mb,
                                                    ),
                                                );
                                                recv.apply_sealed_metadata(meta);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                session = %session_id,
                                                %e,
                                                "Failed to decrypt sealed metadata from chunk[0]"
                                            );
                                        }
                                    }
                                }
                            }

                            if let Some(recv) = sessions.get_mut(&session_id) {
                                // Decrypt and verify chunk
                                match chunked_transfer::receive_chunk(
                                    &keypair_msg,
                                    &encrypted_chunk,
                                    &recv.init.merkle_root,
                                    &recv.init.sender_verifying_key_hex,
                                ) {
                                    Ok(decrypted) => {
                                        if let Err(e) = recv.store_chunk(chunk_idx, decrypted) {
                                            println!(
                                                "\n   {} chunk {}/{}: {}",
                                                "Chunk store FAILED:".red().bold(),
                                                chunk_idx,
                                                total,
                                                e
                                            );
                                            continue;
                                        }
                                        // Rate-limited progress: update every ~2% or first/last chunk
                                        let print_interval = std::cmp::max(1, total / 50);
                                        if recv.received_count == 1
                                            || recv.received_count % print_interval == 0
                                            || recv.received_count == total
                                        {
                                            let recv_mb = (recv.received_count as f64
                                                * recv.init.chunk_size as f64)
                                                / (1024.0 * 1024.0);
                                            let total_mb =
                                                recv.init.total_size as f64 / (1024.0 * 1024.0);
                                            let pct_done =
                                                (recv.received_count as f64 / total as f64 * 100.0)
                                                    as u32;
                                            print_async_progress_notice(format!(
                                                "   {} [{}/{}] {:.1}/{:.1} MB ({}%)",
                                                "Receiving:".yellow(),
                                                recv.received_count,
                                                total,
                                                recv_mb,
                                                total_mb,
                                                pct_done,
                                            ));
                                            let filename_hint =
                                                (!recv.init.filename.trim().is_empty())
                                                    .then_some(recv.init.filename.as_str());
                                            emit_transfer_progress_event(
                                                "incoming_progress",
                                                "in",
                                                Some(&recv.sender_did),
                                                Some(&recv.sender_name),
                                                Some(&recv.init.session_id),
                                                filename_hint,
                                                recv.received_count,
                                                total,
                                                (recv.received_count as u64)
                                                    .saturating_mul(recv.init.chunk_size as u64),
                                                recv.init.total_size,
                                            );
                                        }

                                        tracing::debug!(
                                            session = %session_id,
                                            chunk = chunk_idx,
                                            "Chunk received and verified ✓"
                                        );
                                        record_active_incoming_iroh_transfer(
                                            &active_incoming_iroh_transfers_msg,
                                            &session_id,
                                            &recv.sender_did,
                                            &recv.sender_name,
                                            recv.init.total_chunks,
                                            recv.received_count,
                                        );

                                        // Auto-assemble if all chunks received (handles out-of-order TransferComplete over Tor)
                                        if recv.is_complete() {
                                            let recv = sessions.remove(&session_id).unwrap();
                                            active_incoming_iroh_transfers_msg.remove(&session_id);
                                            active_receive_count
                                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                            let staged_filename =
                                                (!recv.init.filename.trim().is_empty())
                                                    .then_some(recv.init.filename.clone());
                                            let (received_dir, handoff) = {
                                                let config = receive_dir_config_msg.lock().await;
                                                match prepare_receive_target(
                                                    &log_mode_msg,
                                                    &config,
                                                    &recv.sender_did,
                                                    &recv.sender_name,
                                                ) {
                                                    Ok(value) => value,
                                                    Err(e) => {
                                                        print_async_notice(
                                                            &agent_name_msg,
                                                            format!(
                                                                "   {} receive dir setup failed: {}",
                                                                "SECURITY REJECT:".red().bold(),
                                                                e
                                                            ),
                                                        );
                                                        continue;
                                                    }
                                                }
                                            };

                                            if let Err(e) =
                                                ensure_private_receive_dir(&received_dir)
                                            {
                                                print_async_notice(
                                                    &agent_name_msg,
                                                    format!(
                                                        "   {} receive dir setup failed: {}",
                                                        "SECURITY REJECT:".red().bold(),
                                                        e
                                                    ),
                                                );
                                                continue;
                                            }

                                            match finalize_chunk_receive(recv, received_dir.clone())
                                                .await
                                            {
                                                Ok((manifest, final_path)) => {
                                                    {
                                                        let mut a = audit_msg.lock().await;
                                                        a.record(
                                                            "CHUNKED_FILE_RECV",
                                                            &request.sender_did,
                                                            &format!(
                                                                "artifact_id={} size={} chunks={} sha256={}",
                                                                manifest.artifact_id,
                                                                manifest.total_size,
                                                                total,
                                                                &manifest.sha256[..16]
                                                            ),
                                                        );
                                                    }
                                                    let size_mb = manifest.total_size as f64
                                                        / (1024.0 * 1024.0);
                                                    if let Some((handoff_id, handoff_dir)) = handoff
                                                    {
                                                        print_async_notice(
                                                            &agent_name_msg,
                                                            format!(
                                                                "   {} {} ({:.1} MB) -> {}",
                                                                "Chunked transfer staged for secure handoff:"
                                                                    .green()
                                                                    .bold(),
                                                                manifest.sha256[..16].dimmed(),
                                                                size_mb,
                                                                handoff_dir.display(),
                                                            ),
                                                        );
                                                        emit_transfer_event_with_handoff(
                                                            "incoming_staged",
                                                            "in",
                                                            Some(&request.sender_did),
                                                            Some(&request.sender_name),
                                                            Some(&session_id),
                                                            staged_filename.as_deref(),
                                                            Some("ghost_secure_handoff_ready"),
                                                            Some(&handoff_id),
                                                            Some(&handoff_dir),
                                                        );
                                                    } else {
                                                        print_async_notice(
                                                            &agent_name_msg,
                                                            format!(
                                                                "   {} {} ({:.1} MB) -> {}",
                                                                "Chunked transfer complete:"
                                                                    .green()
                                                                    .bold(),
                                                                manifest.sha256[..16].dimmed(),
                                                                size_mb,
                                                                final_path.display(),
                                                            ),
                                                        );
                                                        emit_transfer_event(
                                                            "incoming_completed",
                                                            "in",
                                                            Some(&request.sender_did),
                                                            Some(&request.sender_name),
                                                            Some(&session_id),
                                                            staged_filename.as_deref(),
                                                            Some("chunked_transfer_complete"),
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    if handoff.is_some() {
                                                        secure_wipe_dir_async(received_dir.clone())
                                                            .await;
                                                    }
                                                    print_async_notice(
                                                        &agent_name_msg,
                                                        format!(
                                                            "   {} {}",
                                                            "Chunked transfer reassembly FAILED:"
                                                                .red()
                                                                .bold(),
                                                            e
                                                        ),
                                                    );
                                                    emit_transfer_event(
                                                        "incoming_failed",
                                                        "in",
                                                        Some(&request.sender_did),
                                                        Some(&request.sender_name),
                                                        Some(&session_id),
                                                        None,
                                                        Some(&format!("{}", e)),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        print_async_notice(
                                            &agent_name_msg,
                                            format!(
                                                "   {} chunk {}/{}: {}",
                                                "Chunk verify FAILED:".red().bold(),
                                                chunk_idx,
                                                total,
                                                e
                                            ),
                                        );
                                    }
                                }
                            } else {
                                let now = tokio::time::Instant::now();
                                let should_notify = record_unknown_session_status_notice(
                                    &mut recent_unknown_session_statuses,
                                    &request.sender_did,
                                    &session_id,
                                    now,
                                );
                                if should_notify {
                                    tracing::debug!(
                                        session = %session_id,
                                        "Received chunk for unknown session — requesting restart"
                                    );
                                    let _ = cmd_tx_msg
                                        .send(NetworkCommand::SendTransferStatus {
                                            peer_id,
                                            session_id: Some(session_id.clone()),
                                            request_message_id: Some(request.message_id.clone()),
                                            filename: None,
                                            status: "session_unknown".to_string(),
                                            detail: Some(
                                                "receiver_restart_or_lost_session".to_string(),
                                            ),
                                        })
                                        .await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("ChunkData decode failed: {}", e);
                        }
                    }
                    // No prompt here — chunks arrive rapidly (prompt printed on auto-assembly)
                }

                MessageKind::ChunkAck => {
                    tracing::debug!(
                        from = %crate::agent::contact_identity::displayed_did(&request.sender_did),
                        "Chunk ACK received"
                    );
                }

                MessageKind::TransferResume => {
                    let visible_sender_did =
                        crate::agent::contact_identity::displayed_did(&request.sender_did);
                    match bincode::deserialize::<crate::network::protocol::TransferResumePayload>(
                        &request.payload,
                    ) {
                        Ok(resume) => {
                            let mut approvals = transfer_start_approvals_msg.lock().await;
                            approvals.insert(
                                resume.session_id.clone(),
                                TransferStartApproval {
                                    peer_did: request.sender_did.clone(),
                                    received_chunks: resume.received_chunks.clone(),
                                },
                            );
                            tracing::info!(
                                from = %visible_sender_did,
                                session = %resume.session_id,
                                "Transfer start approved by receiver"
                            );
                            emit_transfer_event(
                                "outgoing_accepted",
                                "out",
                                Some(&request.sender_did),
                                Some(&request.sender_name),
                                Some(&resume.session_id),
                                None,
                                Some("approved_by_receiver"),
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                from = %visible_sender_did,
                                %e,
                                "TransferResume decode failed"
                            );
                        }
                    }
                }

                MessageKind::TransferStatus => {
                    let visible_sender_did =
                        crate::agent::contact_identity::displayed_did(&request.sender_did);
                    match bincode::deserialize::<crate::network::protocol::TransferStatusPayload>(
                        &request.payload,
                    ) {
                        Ok(status) => {
                            let filename = status
                                .filename
                                .as_deref()
                                .filter(|value| !value.trim().is_empty());
                            let detail = status
                                .detail
                                .as_deref()
                                .filter(|value| !value.trim().is_empty());
                            match status.status.as_str() {
                                "accepted" => {
                                    print_async_notice(
                                        &agent_name_msg,
                                        format!(
                                            "   {} {} accepted transfer{}",
                                            "Transfer accepted:".green().bold(),
                                            request.sender_name.cyan(),
                                            filename
                                                .map(|name| format!(" • {}", name))
                                                .unwrap_or_default()
                                        ),
                                    );
                                    emit_transfer_event(
                                        "outgoing_accepted",
                                        "out",
                                        Some(&request.sender_did),
                                        Some(&request.sender_name),
                                        status.session_id.as_deref(),
                                        filename,
                                        detail.or(Some("approved_by_receiver")),
                                    );
                                }
                                "completed" => {
                                    print_async_notice(
                                        &agent_name_msg,
                                        format!(
                                            "   {} {} completed transfer{}",
                                            "Delivery confirmed:".green().bold(),
                                            request.sender_name.cyan(),
                                            filename
                                                .map(|name| format!(" • {}", name))
                                                .unwrap_or_default()
                                        ),
                                    );
                                    emit_transfer_event(
                                        "outgoing_completed",
                                        "out",
                                        Some(&request.sender_did),
                                        Some(&request.sender_name),
                                        status.session_id.as_deref(),
                                        filename,
                                        detail.or(Some("received_by_peer")),
                                    );
                                }
                                "session_unknown" => {
                                    print_async_notice(
                                        &agent_name_msg,
                                        format!(
                                            "   {} {} lost the active transfer session{}",
                                            "Transfer restart needed:".yellow().bold(),
                                            request.sender_name.cyan(),
                                            status
                                                .session_id
                                                .as_deref()
                                                .map(|sid| format!(
                                                    " {}",
                                                    sid[..std::cmp::min(16, sid.len())].dimmed()
                                                ))
                                                .unwrap_or_default()
                                        ),
                                    );
                                    emit_transfer_event(
                                        "outgoing_restart_required",
                                        "out",
                                        Some(&request.sender_did),
                                        Some(&request.sender_name),
                                        status.session_id.as_deref(),
                                        filename,
                                        detail.or(Some("receiver_session_unknown")),
                                    );
                                    let _ = cmd_tx_msg
                                        .send(NetworkCommand::TransferRejectedByPeer {
                                            peer_id,
                                            session_id: status.session_id.clone(),
                                            reason: "session_unknown".to_string(),
                                        })
                                        .await;
                                }
                                other => {
                                    tracing::warn!(
                                        from = %visible_sender_did,
                                        status = %other,
                                        "Unknown transfer status payload"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                from = %visible_sender_did,
                                %e,
                                "TransferStatus decode failed"
                            );
                        }
                    }
                }

                MessageKind::TransferReject => {
                    let visible_sender_did =
                        crate::agent::contact_identity::displayed_did(&request.sender_did);
                    match bincode::deserialize::<crate::network::protocol::TransferRejectPayload>(
                        &request.payload,
                    ) {
                        Ok(reject) => {
                            let reason = if reject.reason.trim().is_empty() {
                                "rejected_by_receiver".to_string()
                            } else {
                                reject.reason.clone()
                            };
                            print_async_notice(
                                &agent_name_msg,
                                format!(
                                    "\n   {} {} rejected transfer{}{}",
                                    "Transfer rejected:".yellow().bold(),
                                    request.sender_name.cyan(),
                                    reject
                                        .session_id
                                        .as_deref()
                                        .map(|sid| format!(
                                            " session {}",
                                            sid[..std::cmp::min(16, sid.len())].dimmed()
                                        ))
                                        .unwrap_or_default(),
                                    if reason.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" ({})", reason)
                                    }
                                ),
                            );
                            emit_transfer_event(
                                "outgoing_rejected",
                                "out",
                                Some(&request.sender_did),
                                Some(&request.sender_name),
                                reject.session_id.as_deref(),
                                None,
                                Some(&reason),
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::TransferRejectedByPeer {
                                    peer_id,
                                    session_id: reject.session_id,
                                    reason,
                                })
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                from = %visible_sender_did,
                                %e,
                                "TransferReject decode failed"
                            );
                        }
                    }
                }

                // ── Chunked transfer: complete ───────────────────────────
                // NOTE: Over Tor, TransferComplete (small msg) can arrive BEFORE
                // large chunk data. If chunks are missing, we just mark the flag
                // and let ChunkData auto-assemble when the last chunk arrives.
                MessageKind::TransferComplete => {
                    match bincode::deserialize::<crate::network::protocol::TransferCompletePayload>(
                        &request.payload,
                    ) {
                        Ok(complete) => {
                            let session_id = complete.session_id.clone();

                            let mut sessions = chunked_sessions.lock().await;
                            if let Some(recv) = sessions.get_mut(&session_id) {
                                if recv.is_complete() {
                                    // All chunks already here — assemble now
                                    let recv = sessions.remove(&session_id).unwrap();
                                    active_incoming_iroh_transfers_msg.remove(&session_id);

                                    let staged_filename = (!recv.init.filename.trim().is_empty())
                                        .then_some(recv.init.filename.clone());
                                    let (received_dir, handoff) = {
                                        let config = receive_dir_config_msg.lock().await;
                                        match prepare_receive_target(
                                            &log_mode_msg,
                                            &config,
                                            &recv.sender_did,
                                            &recv.sender_name,
                                        ) {
                                            Ok(value) => value,
                                            Err(e) => {
                                                print_async_notice(
                                                    &agent_name_msg,
                                                    format!(
                                                        "   {} receive dir setup failed: {}",
                                                        "SECURITY REJECT:".red().bold(),
                                                        e
                                                    ),
                                                );
                                                continue;
                                            }
                                        }
                                    };

                                    if let Err(e) = ensure_private_receive_dir(&received_dir) {
                                        print_async_notice(
                                            &agent_name_msg,
                                            format!(
                                                "   {} receive dir setup failed: {}",
                                                "SECURITY REJECT:".red().bold(),
                                                e
                                            ),
                                        );
                                        continue;
                                    }

                                    match finalize_chunk_receive(recv, received_dir.clone()).await {
                                        Ok((manifest, final_path)) => {
                                            {
                                                let mut a = audit_msg.lock().await;
                                                a.record(
                                                    "CHUNKED_FILE_RECV",
                                                    &request.sender_did,
                                                    &format!(
                                                        "artifact_id={} size={} chunks={} sha256={}",
                                                        manifest.artifact_id,
                                                        manifest.total_size,
                                                        complete.total_chunks,
                                                        &manifest.sha256[..16]
                                                    ),
                                                );
                                            }
                                            let size_mb =
                                                manifest.total_size as f64 / (1024.0 * 1024.0);
                                            if let Some((handoff_id, handoff_dir)) = handoff {
                                                print_async_notice(
                                                    &agent_name_msg,
                                                    format!(
                                                        "   {} {} ({:.1} MB) -> {}",
                                                        "Chunked transfer staged for secure handoff:"
                                                            .green()
                                                            .bold(),
                                                        manifest.sha256[..16].dimmed(),
                                                        size_mb,
                                                        handoff_dir.display(),
                                                    ),
                                                );
                                                emit_transfer_event_with_handoff(
                                                    "incoming_staged",
                                                    "in",
                                                    Some(&request.sender_did),
                                                    Some(&request.sender_name),
                                                    Some(&session_id),
                                                    staged_filename.as_deref(),
                                                    Some("ghost_secure_handoff_ready"),
                                                    Some(&handoff_id),
                                                    Some(&handoff_dir),
                                                );
                                            } else {
                                                print_async_notice(
                                                    &agent_name_msg,
                                                    format!(
                                                        "   {} {} ({:.1} MB) -> {}",
                                                        "Chunked transfer complete:".green().bold(),
                                                        manifest.sha256[..16].dimmed(),
                                                        size_mb,
                                                        final_path.display(),
                                                    ),
                                                );
                                                emit_transfer_event(
                                                    "incoming_completed",
                                                    "in",
                                                    Some(&request.sender_did),
                                                    Some(&request.sender_name),
                                                    Some(&session_id),
                                                    staged_filename.as_deref(),
                                                    Some("chunked_transfer_complete"),
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            if handoff.is_some() {
                                                secure_wipe_dir_async(received_dir.clone()).await;
                                            }
                                            print_async_notice(
                                                &agent_name_msg,
                                                format!(
                                                    "   {} {}",
                                                    "Chunked transfer reassembly FAILED:"
                                                        .red()
                                                        .bold(),
                                                    e
                                                ),
                                            );
                                            emit_transfer_event(
                                                "incoming_failed",
                                                "in",
                                                Some(&request.sender_did),
                                                Some(&request.sender_name),
                                                Some(&session_id),
                                                None,
                                                Some(&format!("{}", e)),
                                            );
                                        }
                                    }
                                } else {
                                    // Chunks still in transit — DON'T remove the session.
                                    // Mark flag so ChunkData handler knows TransferComplete was seen.
                                    recv.transfer_complete_received = true;
                                    tracing::info!(
                                        session = %session_id,
                                        received = recv.received_count,
                                        total = recv.init.total_chunks,
                                        "TransferComplete arrived before all chunks — waiting for remaining chunks"
                                    );
                                }
                            } else {
                                // Session already assembled by ChunkData auto-assembly — safe to ignore
                                tracing::debug!(
                                    session = %session_id,
                                    "TransferComplete for already-completed session — ignoring"
                                );
                            }
                        }
                        Err(e) => {
                            print_async_notice(
                                &agent_name_msg,
                                format!(
                                    "   {} {}",
                                    "TransferComplete decode FAILED:".red().bold(),
                                    e
                                ),
                            );
                        }
                    }
                }

                MessageKind::Heartbeat => {
                    tracing::debug!(
                        from = %crate::agent::contact_identity::displayed_did(&request.sender_did),
                        "Heartbeat"
                    );
                }

                MessageKind::DisconnectNotice => {
                    match decode_disconnect_notice_kind(&request.payload) {
                        kind if should_persist_manual_disconnect_from_notice(kind) => {
                            {
                                let mut manual = manual_disconnect_dids_msg.lock().await;
                                manual.insert(request.sender_did.clone());
                            }
                            {
                                let mut rmgr = ratchet_mgr_msg.lock().await;
                                rmgr.remove_session(&request.sender_did);
                            }
                            forget_persisted_peer(&peer_store_msg, &request.sender_did).await;
                            println!(
                                "\n   {} {} ended the session (/disconnect)",
                                "Peer notice:".yellow().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::RemotePeerManualDisconnect {
                                    peer_id,
                                    peer_did: request.sender_did.clone(),
                                    peer_name: request.sender_name.clone(),
                                })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                        DisconnectNoticeKind::AgentOffline => {
                            {
                                let mut manual = manual_disconnect_dids_msg.lock().await;
                                manual.remove(&request.sender_did);
                            }
                            {
                                let mut offline = remote_offline_dids_msg.lock().await;
                                offline.insert(request.sender_did.clone());
                            }
                            let paused_incoming_transfers =
                                mark_active_incoming_iroh_transfers_paused(
                                    &active_incoming_iroh_transfers_msg,
                                    &request.sender_did,
                                );
                            super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                                &agent_name_msg,
                                &paused_incoming_transfers,
                                false,
                            );
                            let mut cleared_target = false;
                            if let Ok(mut target) = active_chat_target_did_msg.lock() {
                                if target.as_deref() == Some(request.sender_did.as_str()) {
                                    *target = None;
                                    cleared_target = true;
                                }
                            }
                            if cleared_target {
                                set_active_prompt_target_label(None);
                            }
                            println!(
                                "\n   {} {} went offline",
                                "Peer notice:".yellow().bold(),
                                request.sender_name.cyan()
                            );
                            if matches!(transport_mode_msg, TransportMode::Internet) {
                                let _ = cmd_tx_msg
                                    .send(NetworkCommand::RemotePeerOffline {
                                        peer_id,
                                        peer_did: request.sender_did.clone(),
                                        peer_name: request.sender_name.clone(),
                                    })
                                    .await;
                                print_prompt(&agent_name_msg);
                                continue;
                            }
                        }
                        DisconnectNoticeKind::InviteRejectedUsed => {
                            println!(
                                "\n   {} invite from {} was already consumed. Request a new /invite.",
                                "SECURITY REJECT:".red().bold(),
                                request.sender_name.cyan()
                            );
                            let _ = cmd_tx_msg
                                .send(NetworkCommand::DisconnectPeer { peer_id })
                                .await;
                            print_prompt(&agent_name_msg);
                            continue;
                        }
                        DisconnectNoticeKind::ManualDisconnect => unreachable!(),
                    }
                    let _ = cmd_tx_msg
                        .send(NetworkCommand::DisconnectPeer { peer_id })
                        .await;
                    print_prompt(&agent_name_msg);
                }

                MessageKind::KeyRotation => {
                    println!(
                        "\n   {} from {}",
                        "Key rotation announcement:".yellow().bold(),
                        request.sender_name.cyan()
                    );
                    print_prompt(&agent_name_msg);
                }

                // No extra transport-specific application handlers are needed here.
                _ => {
                    println!(
                        "\n   {} from {}",
                        format!("{:?}", request.msg_type).yellow(),
                        request.sender_name
                    );
                    print_prompt(&agent_name_msg);
                }
            }
        }
    });

    IncomingMessageRuntime {
        active_receive_count,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        forget_persisted_peer, live_peer_verifying_key_for_handshake,
        record_unknown_session_status_notice, should_accept_remote_tor_onion_route,
        should_allow_preauthenticated_iroh_disconnect_notice, should_allow_trusted_reconnect_probe,
        should_apply_manual_disconnect_policy_after_invite_use_check,
        should_drop_inactive_iroh_envelope, should_emit_iroh_connected_notice,
        should_persist_manual_disconnect_from_notice,
        should_reject_handshake_verifying_key_continuity,
        should_send_manual_disconnect_notice_for_handshake_policy,
        should_send_tor_peer_supplied_hybrid_followup, stale_orphan_chunk_receive_dirs,
        TorPeerSuppliedHybridFollowup, UNKNOWN_SESSION_STATUS_DEDUP_WINDOW_MS,
    };
    use crate::agent::daemon::{DisconnectNoticeKind, PeerInfo};
    use crate::config::TransportMode;
    use crate::network::peer_store::{KnownPeer, PeerStore};
    use crate::network::protocol::MessageKind;
    use dashmap::DashMap;
    use std::sync::Arc;

    #[test]
    fn drops_only_replaced_iroh_sessions() {
        assert!(should_drop_inactive_iroh_envelope(
            Some(7),
            Some(false),
            &MessageKind::Chat,
        ));
        assert!(!should_drop_inactive_iroh_envelope(
            Some(7),
            Some(false),
            &MessageKind::DisconnectNotice,
        ));
        assert!(!should_drop_inactive_iroh_envelope(
            Some(7),
            Some(true),
            &MessageKind::Chat,
        ));
        assert!(!should_drop_inactive_iroh_envelope(
            Some(7),
            None,
            &MessageKind::Chat,
        ));
        assert!(!should_drop_inactive_iroh_envelope(
            None,
            Some(false),
            &MessageKind::Chat,
        ));
    }

    #[test]
    fn duplicate_connected_notice_is_suppressed_for_authenticated_internet_session() {
        let peer_id = libp2p::PeerId::random();
        let existing_peer = PeerInfo {
            peer_id,
            did: "did:qypha:peer".to_string(),
            name: "peer".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some("relay-only".to_string()),
            onion_port: 9090,
            x25519_public_key: Some([7u8; 32]),
            kyber_public_key: None,
            verifying_key: Some([9u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([5u8; 32]),
        };

        assert!(!should_emit_iroh_connected_notice(
            &TransportMode::Internet,
            Some(&existing_peer),
            "did:qypha:peer",
            true,
        ));
        assert!(should_emit_iroh_connected_notice(
            &TransportMode::Internet,
            Some(&existing_peer),
            "did:qypha:peer",
            false,
        ));
        assert!(!should_emit_iroh_connected_notice(
            &TransportMode::Tor,
            Some(&existing_peer),
            "did:qypha:peer",
            true,
        ));
        assert!(!should_emit_iroh_connected_notice(
            &TransportMode::Tor,
            Some(&existing_peer),
            "did:qypha:peer",
            false,
        ));
    }

    #[test]
    fn blocked_or_manual_disconnect_handshakes_use_manual_disconnect_notice_path() {
        assert!(should_send_manual_disconnect_notice_for_handshake_policy(
            true, false
        ));
        assert!(should_send_manual_disconnect_notice_for_handshake_policy(
            false, true
        ));
        assert!(should_send_manual_disconnect_notice_for_handshake_policy(
            true, true
        ));
        assert!(!should_send_manual_disconnect_notice_for_handshake_policy(
            false, false
        ));
    }

    #[test]
    fn used_invite_rejection_preempts_manual_disconnect_policy() {
        assert!(should_apply_manual_disconnect_policy_after_invite_use_check(true, false, false));
        assert!(should_apply_manual_disconnect_policy_after_invite_use_check(false, true, false));
        assert!(!should_apply_manual_disconnect_policy_after_invite_use_check(true, false, true));
        assert!(!should_apply_manual_disconnect_policy_after_invite_use_check(false, true, true));
        assert!(!should_apply_manual_disconnect_policy_after_invite_use_check(false, false, true));
    }

    #[test]
    fn tor_peer_supplied_hybrid_followup_is_invite_specific() {
        assert_eq!(
            should_send_tor_peer_supplied_hybrid_followup(&TransportMode::Tor, true, true, true),
            TorPeerSuppliedHybridFollowup::Bootstrap
        );
        assert_eq!(
            should_send_tor_peer_supplied_hybrid_followup(&TransportMode::Tor, true, false, true),
            TorPeerSuppliedHybridFollowup::Handshake
        );
        assert_eq!(
            should_send_tor_peer_supplied_hybrid_followup(
                &TransportMode::Internet,
                true,
                true,
                true,
            ),
            TorPeerSuppliedHybridFollowup::None
        );
        assert_eq!(
            should_send_tor_peer_supplied_hybrid_followup(&TransportMode::Tor, false, true, true),
            TorPeerSuppliedHybridFollowup::None
        );
        assert_eq!(
            should_send_tor_peer_supplied_hybrid_followup(&TransportMode::Tor, true, true, false),
            TorPeerSuppliedHybridFollowup::Handshake
        );
    }

    #[test]
    fn trusted_reconnect_probe_is_allowed_for_tor_and_internet() {
        assert!(should_allow_trusted_reconnect_probe(
            &TransportMode::Internet,
            false,
            true,
            true,
            false,
        ));
        assert!(should_allow_trusted_reconnect_probe(
            &TransportMode::Tor,
            false,
            true,
            true,
            false,
        ));
        assert!(!should_allow_trusted_reconnect_probe(
            &TransportMode::Tcp,
            false,
            true,
            true,
            false,
        ));
        assert!(!should_allow_trusted_reconnect_probe(
            &TransportMode::Tor,
            true,
            true,
            true,
            false,
        ));
        assert!(!should_allow_trusted_reconnect_probe(
            &TransportMode::Tor,
            false,
            false,
            true,
            false,
        ));
        assert!(!should_allow_trusted_reconnect_probe(
            &TransportMode::Tor,
            false,
            true,
            false,
            false,
        ));
        assert!(!should_allow_trusted_reconnect_probe(
            &TransportMode::Tor,
            false,
            true,
            true,
            true,
        ));
    }

    #[test]
    fn handshake_live_verifying_key_falls_back_to_matching_did() {
        let peers = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        let other_peer_id = libp2p::PeerId::random();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: String::new(),
                name: "placeholder".to_string(),
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
            other_peer_id.to_string(),
            PeerInfo {
                peer_id: other_peer_id,
                did: "did:qypha:peer".to_string(),
                name: "peer".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: Some([7u8; 32]),
                kyber_public_key: None,
                verifying_key: Some([9u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([5u8; 32]),
            },
        );

        assert_eq!(
            live_peer_verifying_key_for_handshake(&peers, &peer_id.to_string(), "did:qypha:peer"),
            Some([9u8; 32])
        );
    }

    #[test]
    fn handshake_verifying_key_continuity_rejects_changed_payload_key() {
        assert!(should_reject_handshake_verifying_key_continuity(
            Some([7u8; 32]),
            Some([8u8; 32])
        ));
        assert!(!should_reject_handshake_verifying_key_continuity(
            Some([7u8; 32]),
            Some([7u8; 32])
        ));
        assert!(!should_reject_handshake_verifying_key_continuity(
            Some([7u8; 32]),
            None
        ));
        assert!(!should_reject_handshake_verifying_key_continuity(
            None,
            Some([8u8; 32])
        ));
    }

    #[test]
    fn unknown_session_status_notice_is_deduped_per_sender_and_session() {
        let mut recent = std::collections::HashMap::new();
        let now = tokio::time::Instant::now();

        assert!(record_unknown_session_status_notice(
            &mut recent,
            "did:qypha:peer",
            "sess-1",
            now,
        ));
        assert!(!record_unknown_session_status_notice(
            &mut recent,
            "did:qypha:peer",
            "sess-1",
            now + tokio::time::Duration::from_millis(500),
        ));
        assert!(record_unknown_session_status_notice(
            &mut recent,
            "did:qypha:peer",
            "sess-1",
            now + tokio::time::Duration::from_millis(UNKNOWN_SESSION_STATUS_DEDUP_WINDOW_MS + 1,),
        ));
        assert!(record_unknown_session_status_notice(
            &mut recent,
            "did:qypha:peer",
            "sess-2",
            now + tokio::time::Duration::from_millis(500),
        ));
    }

    #[test]
    fn only_manual_disconnect_notice_persists_local_disconnect_state() {
        assert!(should_persist_manual_disconnect_from_notice(
            DisconnectNoticeKind::ManualDisconnect
        ));
        assert!(!should_persist_manual_disconnect_from_notice(
            DisconnectNoticeKind::InviteRejectedUsed
        ));
        assert!(!should_persist_manual_disconnect_from_notice(
            DisconnectNoticeKind::AgentOffline
        ));
    }

    #[test]
    fn only_signed_disconnect_notice_bypasses_preauthenticated_iroh_gate() {
        assert!(should_allow_preauthenticated_iroh_disconnect_notice(
            &MessageKind::DisconnectNotice,
            true,
            false,
        ));
        assert!(!should_allow_preauthenticated_iroh_disconnect_notice(
            &MessageKind::DisconnectNotice,
            false,
            false,
        ));
        assert!(!should_allow_preauthenticated_iroh_disconnect_notice(
            &MessageKind::Chat,
            true,
            false,
        ));
        assert!(!should_allow_preauthenticated_iroh_disconnect_notice(
            &MessageKind::DisconnectNotice,
            true,
            true,
        ));
    }

    #[test]
    fn foreign_tor_handshake_route_must_not_point_to_local_onion() {
        assert!(!should_accept_remote_tor_onion_route(
            &TransportMode::Tor,
            "did:nxf:local",
            "did:nxf:remote",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX.onion"),
        ));
        assert!(should_accept_remote_tor_onion_route(
            &TransportMode::Tor,
            "did:nxf:local",
            "did:nxf:remote",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        ));
    }

    #[test]
    fn local_tor_handshake_route_is_allowed_for_our_own_did() {
        assert!(should_accept_remote_tor_onion_route(
            &TransportMode::Tor,
            "did:nxf:local",
            "did:nxf:local",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
        ));
        assert!(should_accept_remote_tor_onion_route(
            &TransportMode::Internet,
            "did:nxf:local",
            "did:nxf:remote",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
        ));
    }

    #[test]
    fn stale_orphan_chunk_receive_dirs_skip_active_temp_dirs() {
        let root = tempfile::tempdir().unwrap();
        let active_dir = root.path().join("active");
        let stale_dir = root.path().join("stale");
        std::fs::create_dir_all(&active_dir).unwrap();
        std::fs::create_dir_all(&stale_dir).unwrap();
        std::fs::write(active_dir.join("00000000.chunk"), b"active").unwrap();
        std::fs::write(stale_dir.join("00000000.chunk"), b"stale").unwrap();

        let mut active = std::collections::HashSet::new();
        active.insert(active_dir.clone());

        let stale = stale_orphan_chunk_receive_dirs(root.path(), &active, u64::MAX, 0);

        assert_eq!(stale, vec![stale_dir]);
    }

    #[test]
    fn stale_orphan_chunk_receive_dirs_ignore_missing_root() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let active = std::collections::HashSet::new();

        let stale = stale_orphan_chunk_receive_dirs(&missing, &active, u64::MAX, 0);

        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn manual_disconnect_forgets_persisted_peer() {
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: "did:qypha:peer".to_string(),
                name: "peer".to_string(),
                role: "agent".to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: None,
                verifying_key_hex: None,
                kyber_public_key_hex: None,
                last_seen: 1,
                auto_reconnect: true,
            });
        }

        forget_persisted_peer(&peer_store, "did:qypha:peer").await;

        let store = peer_store.lock().await;
        assert!(store.get("did:qypha:peer").is_none());
    }

    #[tokio::test]
    async fn persisted_peer_verifying_key_uses_known_peer_identity() {
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: "did:qypha:peer".to_string(),
                name: "peer".to_string(),
                role: "agent".to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: None,
                verifying_key_hex: Some(hex::encode([7u8; 32])),
                kyber_public_key_hex: None,
                last_seen: 1,
                auto_reconnect: true,
            });
        }

        assert_eq!(
            super::persisted_peer_verifying_key(&peer_store, "did:qypha:peer").await,
            Some([7u8; 32])
        );
    }
}

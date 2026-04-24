use super::handshake_request_gate::HandshakeRequestGate;
use super::incoming_connect_gate::IncomingConnectGate;
use super::libp2p_command_handlers::{
    handle_libp2p_command, Libp2pCommandHandlerShared, Libp2pCommandHandlerState,
};
use super::libp2p_event_handlers::{
    handle_libp2p_event, Libp2pEventHandlerShared, Libp2pEventHandlerState,
};
use super::*;

const TOR_BACKGROUND_RECONNECT_TICK_SECS: u64 = 3;
const TOR_STARTUP_RECONNECT_DELAY_SECS: u64 = 8;
const TOR_STARTUP_RECONNECT_FALLBACK_DELAY_SECS: u64 = 12;
const LIBP2P_DISCONNECT_NOTICE_TICK_MS: u64 = 250;
const LIBP2P_SHUTDOWN_NOTICE_GRACE_MS: u64 = 350;
const LIBP2P_TOR_SHUTDOWN_NOTICE_GRACE_MS: u64 = 1_200;
const LIBP2P_TOR_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS: u64 = 3_000;
const TOR_RECONNECTS_PER_TICK_BUDGET: usize = 2;

fn should_suspend_remote_offline_tor_reconnect(
    remote_offline: bool,
    _pending_chunk_transfers: &HashMap<String, PendingChunkTransfer>,
    _active_incoming_iroh_transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    _did: &str,
) -> bool {
    // Remote offline is a user-visible status, not a reconnect blocker.
    // Only manual disconnect is allowed to fully disable background reconnect.
    let _ = remote_offline;
    false
}

fn tor_transfer_can_stream_chunks(pending: &PendingChunkTransfer) -> bool {
    !pending.awaiting_receiver_accept
}

fn take_expired_disconnect_notice_peers(
    pending_disconnect_notices: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        PendingDisconnectNotice,
    >,
    now: tokio::time::Instant,
) -> Vec<libp2p::PeerId> {
    let expired = pending_disconnect_notices
        .iter()
        .filter(|(_, pending)| pending.deadline <= now)
        .map(|(request_id, _)| *request_id)
        .collect::<Vec<_>>();
    let mut peers = Vec::with_capacity(expired.len());
    for request_id in expired {
        if let Some(pending) = pending_disconnect_notices.remove(&request_id) {
            peers.push(pending.peer_id);
        }
    }
    peers
}

fn seed_initial_tor_reconnects(
    pending: &mut HashMap<String, PendingTorReconnect>,
    peer_store: &PeerStore,
    local_did: &str,
) {
    let preferred_delay = tokio::time::Duration::from_secs(TOR_STARTUP_RECONNECT_DELAY_SECS);
    let fallback_delay =
        tokio::time::Duration::from_secs(TOR_STARTUP_RECONNECT_FALLBACK_DELAY_SECS);
    for known in peer_store.auto_reconnect_peers() {
        if known.onion_address.is_some() {
            queue_tor_reconnect_for_local_role(
                pending,
                &known,
                local_did,
                preferred_delay,
                fallback_delay,
                false,
            );
        }
    }
}

fn normalized_tor_onion_address(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches(".onion").to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn tor_reconnect_seed_targets_local_identity(
    pending: &PendingTorReconnect,
    local_did: &str,
    local_onion_address: Option<&str>,
    our_peer_id: libp2p::PeerId,
) -> bool {
    if pending.did == local_did {
        return true;
    }

    if pending
        .peer_id
        .parse::<libp2p::PeerId>()
        .ok()
        .is_some_and(|peer_id| peer_id == our_peer_id)
    {
        return true;
    }

    let Some(local_onion) = local_onion_address.and_then(normalized_tor_onion_address) else {
        return false;
    };

    normalized_tor_onion_address(&pending.onion_address).as_deref() == Some(local_onion.as_str())
}

fn defer_invalid_tor_reconnect_seed(
    pending_tor_reconnects: &mut HashMap<String, PendingTorReconnect>,
    did: &str,
) {
    let now = tokio::time::Instant::now();
    if let Some(entry) = pending_tor_reconnects.get_mut(did) {
        entry.inflight = false;
        entry.attempts = entry.attempts.saturating_add(1);
        entry.next_attempt_at = now + tor_reconnect_backoff(entry.attempts);
    }
}

async fn resolve_tor_reconnect_seed_from_contact_bundle(
    agent_data_dir: &std::path::Path,
    config: &AppConfig,
    contact_bundle_transport: &Arc<
        crate::network::contact_bundle_transport::ContactBundleTransport,
    >,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    did: &str,
    fallback_name: &str,
) -> Option<KnownPeer> {
    let existing = {
        let peer_store = peer_store.lock().await;
        peer_store.get(did).cloned()
    };
    let endpoint =
        crate::network::discovery::tor::resolve_public_bundle_endpoint_from_config(config, did)?;
    let contact_did = crate::network::contact_did::contact_did_from_canonical_did(did).ok()?;
    let response = contact_bundle_transport
        .get_from_endpoint(
            &endpoint,
            &crate::network::contact_bundle::ContactBundleGetRequest::new(contact_did),
        )
        .await
        .ok()?;
    let profile = response.into_verified_profile().ok()??;
    let role = existing
        .as_ref()
        .map(|known| known.role.as_str())
        .unwrap_or(DEFAULT_AGENT_ROLE);
    let name = {
        let trimmed = fallback_name.trim();
        if trimmed.is_empty() {
            existing
                .as_ref()
                .map(|known| known.name.clone())
                .unwrap_or_else(|| did.to_string())
        } else {
            trimmed.to_string()
        }
    };
    let mut known =
        super::tor_direct_delivery::known_peer_from_tor_direct_profile(&profile, &name, role)?;
    if let Some(existing) = existing.as_ref() {
        known.auto_reconnect = existing.auto_reconnect;
    }

    if let Err(error) =
        super::did_profile_cache::import_verified_did_profile(agent_data_dir, &profile)
    {
        tracing::debug!(
            %error,
            did = %profile.did,
            "failed to cache refreshed Tor contact bundle profile"
        );
    }

    {
        let mut peer_store = peer_store.lock().await;
        peer_store.upsert(known.clone());
    }

    Some(known)
}

async fn repair_invalid_tor_reconnect_seed(
    pending_tor_reconnects: &mut HashMap<String, PendingTorReconnect>,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    contact_bundle_transport: &Arc<
        crate::network::contact_bundle_transport::ContactBundleTransport,
    >,
    agent_data_dir: &std::path::Path,
    config: &AppConfig,
    did: &str,
    local_did: &str,
    local_onion_address: Option<&str>,
    our_peer_id: libp2p::PeerId,
) -> bool {
    let Some(pending) = pending_tor_reconnects.get(did).cloned() else {
        return false;
    };

    if !tor_reconnect_seed_targets_local_identity(
        &pending,
        local_did,
        local_onion_address,
        our_peer_id,
    ) {
        return true;
    }

    if pending.did == local_did {
        tracing::warn!(
            did = %pending.did,
            peer = %pending.name,
            "dropping invalid Tor reconnect seed that points to the local DID"
        );
        pending_tor_reconnects.remove(did);
        return false;
    }

    tracing::warn!(
        did = %pending.did,
        peer = %pending.name,
        onion = %pending.onion_address,
        peer_id = %pending.peer_id,
        "Tor reconnect seed resolved to local identity; refreshing from contact bundle"
    );

    let Some(refreshed) = resolve_tor_reconnect_seed_from_contact_bundle(
        agent_data_dir,
        config,
        contact_bundle_transport,
        peer_store,
        did,
        &pending.name,
    )
    .await
    else {
        defer_invalid_tor_reconnect_seed(pending_tor_reconnects, did);
        return false;
    };

    if refreshed.did == local_did
        || refreshed
            .onion_address
            .as_deref()
            .and_then(normalized_tor_onion_address)
            == local_onion_address.and_then(normalized_tor_onion_address)
    {
        tracing::warn!(
            did = %pending.did,
            peer = %pending.name,
            "refreshed Tor reconnect seed still resolves to local identity; deferring retry"
        );
        defer_invalid_tor_reconnect_seed(pending_tor_reconnects, did);
        return false;
    }

    queue_tor_reconnect(pending_tor_reconnects, &refreshed, true);
    true
}

fn has_live_authenticated_tor_peer<F>(
    peers: &DashMap<String, PeerInfo>,
    did: &str,
    mut is_connected: F,
) -> bool
where
    F: FnMut(&PeerInfo) -> bool,
{
    peers.iter().any(|entry| {
        let peer = entry.value();
        peer.did == did && peer.verifying_key.is_some() && is_connected(peer)
    })
}

fn queue_shutdown_disconnect_notices(
    network: &mut NetworkNode,
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
    pending_chunk_transfers: &HashMap<String, PendingChunkTransfer>,
    sign_key: &ed25519_dalek::SigningKey,
    config: &AppConfig,
) -> usize {
    let direct_peers = super::selectors::sorted_direct_peer_list(peers, direct_peer_dids);
    let notice =
        build_disconnect_notice_request(sign_key, config, DisconnectNoticeKind::AgentOffline);
    let mut noticed_peer_ids = std::collections::HashSet::new();
    for peer in &direct_peers {
        network
            .swarm
            .behaviour_mut()
            .messaging
            .send_request(&peer.peer_id, notice.clone());
        noticed_peer_ids.insert(peer.peer_id);
    }
    for transfer in pending_chunk_transfers.values() {
        if noticed_peer_ids.insert(transfer.peer_id) {
            network
                .swarm
                .behaviour_mut()
                .messaging
                .send_request(&transfer.peer_id, notice.clone());
        }
    }
    noticed_peer_ids.len()
}

fn shutdown_notice_grace_ms(transport_mode: &TransportMode, has_pending_transfers: bool) -> u64 {
    if matches!(transport_mode, TransportMode::Tor) {
        if has_pending_transfers {
            LIBP2P_TOR_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS
        } else {
            LIBP2P_TOR_SHUTDOWN_NOTICE_GRACE_MS
        }
    } else {
        LIBP2P_SHUTDOWN_NOTICE_GRACE_MS
    }
}

async fn yield_before_processing_ready_tor_transfer() {
    // Outgoing Tor chunk streaming can remain perpetually ready; yield once so
    // shutdown/reconnect/control-plane work keeps making progress.
    tokio::task::yield_now().await;
}

pub(crate) struct Libp2pRuntimeContext {
    pub(crate) agent_data_dir: std::path::PathBuf,
    pub(crate) peers: Arc<DashMap<String, PeerInfo>>,
    pub(crate) config: AppConfig,
    pub(crate) sign_key: ed25519_dalek::SigningKey,
    pub(crate) keypair: AgentKeyPair,
    pub(crate) audit: Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) rbac: Arc<tokio::sync::RwLock<RbacEngine>>,
    pub(crate) peer_store: Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) used_invites: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) used_invites_path: Option<std::path::PathBuf>,
    pub(crate) used_invites_persist_key: Option<[u8; 32]>,
    pub(crate) group_mailboxes: Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) handshake_request_gate: Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    pub(crate) mailbox_transport: Arc<TorMailboxTransport>,
    pub(crate) contact_mailbox_transport: Arc<ContactMailboxTransport>,
    pub(crate) contact_bundle_transport:
        Arc<crate::network::contact_bundle_transport::ContactBundleTransport>,
    pub(crate) group_invite_bundle_transport:
        Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    pub(crate) public_group_invite_bundle_service:
        Option<Arc<crate::network::group_invite_bundle_iroh::IrohGroupInviteBundleService>>,
    pub(crate) direct_peer_dids: Arc<DashMap<String, bool>>,
    pub(crate) invite_proof_by_peer: Arc<DashMap<String, String>>,
    pub(crate) manual_disconnect_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) remote_offline_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) ip_hidden: Arc<AtomicBool>,
    pub(crate) cmd_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) ratchet_mgr: Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) pending_hybrid_ratchet_inits: Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_pub_hex: String,
    pub(crate) transfer_start_approvals:
        Arc<tokio::sync::Mutex<HashMap<String, TransferStartApproval>>>,
    pub(crate) pending_contact_requests: Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) incoming_connect_gate: Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) log_mode: LogMode,
    pub(crate) receive_dir_config: Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    pub(crate) msg_tx: mpsc::Sender<crate::network::IncomingRequestEnvelope>,
    pub(crate) active_receive_count: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) active_incoming_iroh_transfers: Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) active_chat_target_did: Arc<Mutex<Option<String>>>,
    pub(crate) our_peer_id: libp2p::PeerId,
    pub(crate) no_resume_session_persistence: bool,
    pub(crate) no_persistent_artifact_store: bool,
    pub(crate) ram_only_chunk_staging: bool,
}

pub(crate) fn spawn_libp2p_runtime(
    ctx: Libp2pRuntimeContext,
    mut network: NetworkNode,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
) {
    clear_graceful_shutdown_requested();
    let Libp2pRuntimeContext {
        agent_data_dir,
        peers: peers_net,
        config: config_net,
        sign_key,
        keypair: keypair_net,
        audit: audit_net,
        rbac: rbac_net,
        peer_store: peer_store_net,
        used_invites: used_invites_net,
        used_invites_path: used_invites_path_net,
        used_invites_persist_key: used_invites_persist_key_net,
        group_mailboxes: group_mailboxes_net,
        handshake_request_gate,
        mailbox_transport: mailbox_transport_net,
        contact_mailbox_transport: contact_mailbox_transport_net,
        contact_bundle_transport: contact_bundle_transport_net,
        group_invite_bundle_transport: group_invite_bundle_transport_net,
        public_group_invite_bundle_service: public_group_invite_bundle_service_net,
        direct_peer_dids: direct_peer_dids_net,
        invite_proof_by_peer: invite_proof_net,
        manual_disconnect_dids: manual_disconnect_dids_net,
        remote_offline_dids: remote_offline_dids_net,
        ip_hidden: ip_hidden_net,
        cmd_tx: cmd_tx_net,
        ratchet_mgr: ratchet_mgr_net,
        pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits_net,
        ratchet_init_pub_hex: ratchet_init_pub_hex_net,
        transfer_start_approvals: transfer_start_approvals_net,
        pending_contact_requests: pending_contact_requests_net,
        incoming_connect_gate: incoming_connect_gate_net,
        log_mode: log_mode_net,
        receive_dir_config: receive_dir_config_net,
        msg_tx,
        active_receive_count: active_recv_for_swarm,
        active_incoming_iroh_transfers: active_incoming_iroh_transfers_net,
        active_chat_target_did: active_chat_target_did_net,
        our_peer_id,
        no_resume_session_persistence,
        no_persistent_artifact_store,
        ram_only_chunk_staging,
    } = ctx;
    let config = config_net.clone();
    let bootstrap_peer: Option<String> = None;

    tokio::spawn(async move {
        let mut handshake_sent: std::collections::HashSet<libp2p::PeerId> =
            std::collections::HashSet::new();
        let mut dialing: std::collections::HashSet<libp2p::PeerId> =
            std::collections::HashSet::new();
        // Flow-controlled outbound chunked transfers keyed by peer_id.
        // Enables concurrent multi-peer sends while keeping per-peer sequencing.
        let mut pending_chunk_transfers: HashMap<String, PendingChunkTransfer> = HashMap::new();
        let mut pending_disconnect_notices: HashMap<
            libp2p::request_response::OutboundRequestId,
            PendingDisconnectNotice,
        > = HashMap::new();
        let mut pending_tor_reconnects: HashMap<String, PendingTorReconnect> = HashMap::new();
        let mut pending_tor_dial_seeds: HashMap<u16, KnownPeer> = HashMap::new();
        let mut pending_tor_direct_contact_requests: HashMap<
            String,
            PendingTorDirectContactRequest,
        > = HashMap::new();
        let mut pending_user_chat_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            PendingLibp2pUserChatRequest,
        > = HashMap::new();
        let mut shutdown_done: Option<tokio::sync::oneshot::Sender<()>> = None;
        let mut shutdown_notice_deadline: Option<tokio::time::Instant> = None;
        let mut disconnect_notice_ticker = tokio::time::interval(
            tokio::time::Duration::from_millis(LIBP2P_DISCONNECT_NOTICE_TICK_MS),
        );
        disconnect_notice_ticker.reset();
        if matches!(config_net.network.transport_mode, TransportMode::Tor) {
            let ps = peer_store_net.lock().await;
            seed_initial_tor_reconnects(&mut pending_tor_reconnects, &ps, &config_net.agent.did);
        }

        // Cover traffic emitter — sends random noise packets to all peers at fixed intervals
        // to defeat traffic timing analysis. Active in Ghost mode or if explicitly enabled.
        let cover_active = {
            let mode = &config.security.cover_traffic.mode;
            mode == "always"
                || (mode == "auto" && matches!(log_mode_net, LogMode::Ghost | LogMode::Safe))
        };
        // Cover traffic interval: random 15-30s with 1s granularity.
        // Each emission picks a new random wait — no fixed cadence for timing analysis.
        let cover_base_ms: u64 = if cover_active {
            15_000 + (rand::random::<u64>() % 16) * 1_000
        } else {
            3600_000
        };
        let mut cover_ticker =
            tokio::time::interval(tokio::time::Duration::from_millis(cover_base_ms));
        // Skip the first immediate tick — interval fires instantly on creation.
        // Without this, cover traffic fires before any peer has completed handshake.
        cover_ticker.reset();
        let mailbox_poll_interval_ms = config_net.network.mailbox.poll_interval_ms.max(1);
        let mailbox_poll_jitter_ms = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&config_net.agent.did, &mut hasher);
            let max_jitter_ms = mailbox_poll_interval_ms.clamp(250, 1_500);
            if max_jitter_ms <= 1 {
                0
            } else {
                std::hash::Hasher::finish(&hasher) % max_jitter_ms
            }
        };
        let mut mailbox_poll_ticker = tokio::time::interval_at(
            tokio::time::Instant::now()
                + tokio::time::Duration::from_millis(mailbox_poll_jitter_ms),
            tokio::time::Duration::from_millis(mailbox_poll_interval_ms),
        );
        let mut tor_reconnect_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            TOR_BACKGROUND_RECONNECT_TICK_SECS,
        ));
        tor_reconnect_ticker.reset();
        let mut tor_direct_contact_request_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(1));
        tor_direct_contact_request_ticker.reset();
        let mut anonymous_cover_ticker =
            tokio::time::interval(tokio::time::Duration::from_millis(250));
        anonymous_cover_ticker.reset();
        spawn_startup_identified_membership_announcements(
            Arc::clone(&group_mailboxes_net),
            Arc::clone(&mailbox_transport_net),
            sign_key.clone(),
        );

        // Track peers we're already dialing via --peer flag
        if bootstrap_peer.is_some() {
            // We don't know the PeerId yet, but we'll get it on ConnectionEstablished.
            // For mDNS race prevention, we rely on the connected_peers check below.
        }

        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => {
                    handle_libp2p_event(
                        event,
                        Libp2pEventHandlerState {
                            network: &mut network,
                            handshake_sent: &mut handshake_sent,
                            dialing: &mut dialing,
                            pending_chunk_transfers: &mut pending_chunk_transfers,
                            pending_disconnect_notices: &mut pending_disconnect_notices,
                            pending_tor_reconnects: &mut pending_tor_reconnects,
                            pending_tor_dial_seeds: &mut pending_tor_dial_seeds,
                            pending_tor_direct_contact_requests:
                                &mut pending_tor_direct_contact_requests,
                            pending_user_chat_requests: &mut pending_user_chat_requests,
                        },
                        Libp2pEventHandlerShared {
                            peers_net: &peers_net,
                            config_net: &config_net,
                            keypair_net: &keypair_net,
                            audit_net: &audit_net,
                            peer_store_net: &peer_store_net,
                            group_mailboxes_net: &group_mailboxes_net,
                            direct_peer_dids_net: &direct_peer_dids_net,
                            invite_proof_net: &invite_proof_net,
                            manual_disconnect_dids_net: &manual_disconnect_dids_net,
                            remote_offline_dids_net: &remote_offline_dids_net,
                            incoming_connect_gate_net: &incoming_connect_gate_net,
                            cmd_tx_net: &cmd_tx_net,
                            pending_hybrid_ratchet_inits_net:
                                &pending_hybrid_ratchet_inits_net,
                            ratchet_mgr_net: &ratchet_mgr_net,
                            ratchet_init_pub_hex_net: &ratchet_init_pub_hex_net,
                            msg_tx: &msg_tx,
                            active_recv_for_swarm: &active_recv_for_swarm,
                            active_incoming_iroh_transfers_net:
                                &active_incoming_iroh_transfers_net,
                            active_chat_target_did_net: &active_chat_target_did_net,
                            our_peer_id,
                            no_resume_session_persistence,
                        },
                    )
                    .await;
                }

                _ = tor_reconnect_ticker.tick(), if matches!(config_net.network.transport_mode, TransportMode::Tor) && shutdown_notice_deadline.is_none() && !graceful_shutdown_requested() => {
                    let now = tokio::time::Instant::now();
                    let due_reconnects = next_due_tor_reconnect_dids(
                        &pending_tor_reconnects,
                        now,
                        TOR_RECONNECTS_PER_TICK_BUDGET,
                    );
                    if due_reconnects.is_empty() {
                        continue;
                    }

                    for did in due_reconnects {
                        let manually_disconnected = {
                            let manual = manual_disconnect_dids_net.lock().await;
                            manual.contains(&did)
                        };
                        if manually_disconnected {
                            pending_tor_reconnects.remove(&did);
                            continue;
                        }
                        let remotely_offline = {
                            let offline = remote_offline_dids_net.lock().await;
                            offline.contains(&did)
                        };
                        if should_suspend_remote_offline_tor_reconnect(
                            remotely_offline,
                            &pending_chunk_transfers,
                            &active_incoming_iroh_transfers_net,
                            &did,
                        ) {
                            pending_tor_reconnects.remove(&did);
                            continue;
                        }

                        if !repair_invalid_tor_reconnect_seed(
                            &mut pending_tor_reconnects,
                            &peer_store_net,
                            &contact_bundle_transport_net,
                            &agent_data_dir,
                            &config_net,
                            &did,
                            &config_net.agent.did,
                            network.onion_address.as_deref(),
                            our_peer_id,
                        )
                        .await
                        {
                            continue;
                        }

                        let already_connected = pending_tor_reconnects
                            .get(&did)
                            .and_then(|pending| pending.peer_id.parse::<libp2p::PeerId>().ok())
                            .is_some_and(|peer_id| {
                                network.swarm.is_connected(&peer_id) || dialing.contains(&peer_id)
                            })
                            || has_live_authenticated_tor_peer(&peers_net, &did, |peer| {
                                network.swarm.is_connected(&peer.peer_id)
                            });
                        if already_connected {
                            pending_tor_reconnects.remove(&did);
                            continue;
                        }

                        let Some(pending) =
                            schedule_tor_reconnect_attempt(&mut pending_tor_reconnects, &did)
                        else {
                            continue;
                        };
                        let Some(ref tor_mgr) = network.tor_manager else {
                            clear_tor_reconnect_inflight(&mut pending_tor_reconnects, &did);
                            continue;
                        };

                        let reconnect_tx = cmd_tx_net.clone();
                        let tor_mgr_clone = Arc::clone(tor_mgr);
                        tokio::spawn(async move {
                            match tor_bridge::create_tor_bridge_isolated(
                                &tor_mgr_clone,
                                &pending.onion_address,
                                pending.onion_port,
                                Some(&pending.did),
                            )
                            .await
                            {
                                Ok(bridge_port) => {
                                    let _ = reconnect_tx
                                        .send(NetworkCommand::TorBackgroundDial {
                                            did: pending.did,
                                            bridge_port,
                                        })
                                        .await;
                                }
                                Err(error) => {
                                    tracing::debug!(
                                        did = %pending.did,
                                        peer = %pending.name,
                                        attempt = pending.attempts,
                                        %error,
                                        "background Tor reconnect bridge failed"
                                    );
                                    let _ = reconnect_tx
                                        .send(NetworkCommand::TorBackgroundDialFailed {
                                            did: pending.did,
                                        })
                                        .await;
                                }
                            }
                        });
                        tokio::task::yield_now().await;
                    }
                }

                _ = disconnect_notice_ticker.tick(), if shutdown_notice_deadline.is_none() => {
                    let expired_peers = take_expired_disconnect_notice_peers(
                        &mut pending_disconnect_notices,
                        tokio::time::Instant::now(),
                    );
                    for peer_id in expired_peers {
                        let _ = remove_connected_peer_state(
                            &peers_net,
                            &invite_proof_net,
                            &mut handshake_sent,
                            &peer_id,
                        )
                        .await;
                        if network.swarm.is_connected(&peer_id)
                            && network.swarm.disconnect_peer_id(peer_id).is_err()
                        {
                            tracing::warn!(
                                %peer_id,
                                "disconnect_peer_id failed after manual-disconnect notice timeout"
                            );
                        }
                    }
                }

                _ = tor_direct_contact_request_ticker.tick(), if matches!(config_net.network.transport_mode, TransportMode::Tor) && shutdown_notice_deadline.is_none() => {
                    flush_due_tor_direct_contact_request_fallbacks(
                        &mut pending_tor_direct_contact_requests,
                        &mut pending_tor_dial_seeds,
                        &contact_mailbox_transport_net,
                        &audit_net,
                        &config_net.agent.did,
                        tokio::time::Instant::now(),
                    )
                    .await;
                }

                _ = mailbox_poll_ticker.tick() => {
                    poll_group_mailboxes_once(
                        &group_mailboxes_net,
                        &handshake_request_gate,
                        &mailbox_transport_net,
                        &audit_net,
                        &config_net.agent.did,
                        &config_net.agent.name,
                        &keypair_net,
                        &receive_dir_config_net,
                        &log_mode_net,
                        &agent_data_dir,
                    ).await;
                    poll_contact_mailbox_once(
                        &contact_mailbox_transport_net,
                        &config_net,
                        &keypair_net,
                        &pending_contact_requests_net,
                        &incoming_connect_gate_net,
                        &audit_net,
                        &peer_store_net,
                        &direct_peer_dids_net,
                        &log_mode_net,
                        &config_net.agent.name,
                    ).await;
                }

                _ = anonymous_cover_ticker.tick() => {
                    emit_due_anonymous_cover_traffic_once(
                        &group_mailboxes_net,
                        &mailbox_transport_net,
                    ).await;
                }

                // ── Chunked transfer: flow-controlled chunk sending ──────
                // Sends one chunk per ready transfer iteration.
                // Random inter-chunk delay + ack-before-next preserves timing hardening.
                _ = yield_before_processing_ready_tor_transfer(), if shutdown_notice_deadline.is_none() && !graceful_shutdown_requested() && pending_chunk_transfers.values().any(|p| {
                    !p.reconnecting
                        && p.inflight_request.is_none()
                        && p.backoff_until
                            .map_or(true, |t| tokio::time::Instant::now() >= t)
                        && p.chunk_jitter_until
                            .map_or(true, |t| tokio::time::Instant::now() >= t)
                }) =>
                {
                    let ready_transfer_key = pending_chunk_transfers
                        .iter()
                        .find(|(_, p)| {
                            !p.reconnecting
                                && p.inflight_request.is_none()
                                && p.backoff_until
                                    .map_or(true, |t| tokio::time::Instant::now() >= t)
                                && p.chunk_jitter_until
                                    .map_or(true, |t| tokio::time::Instant::now() >= t)
                        })
                        .map(|(k, _)| k.clone());
                    let Some(transfer_key) = ready_transfer_key else {
                        continue;
                    };

                    let Some(mut pct) = pending_chunk_transfers.remove(&transfer_key) else {
                        continue;
                    };
                    let mut keep_transfer = true;

                    // Connection liveness check — don't send if peer disconnected.
                    let peer_alive = network.swarm.is_connected(&pct.peer_id);
                    if !peer_alive {
                        // Wait before checking again (don't spin).
                        pct.backoff_until = Some(
                            tokio::time::Instant::now() + tokio::time::Duration::from_secs(3),
                        );
                        tracing::debug!(
                            peer = %pct.peer_id,
                            "Peer disconnected — waiting for reconnection before resuming transfer"
                        );
                    } else {
                        let waiting_timed_out = pct.awaiting_receiver_accept
                            && pct.awaiting_started_at.elapsed()
                                > tokio::time::Duration::from_secs(300);
                        if waiting_timed_out {
                            println!(
                                "   {} receiver did not accept transfer {} within timeout; transfer aborted",
                                "Timeout:".red().bold(),
                                pct.session.session_id[..16].dimmed()
                            );
                            pct.chunk_source.secure_cleanup();
                            keep_transfer = false;
                        }

                        // Receiver must explicitly accept ChunkTransferInit before any chunk flows.
                        if keep_transfer && pct.awaiting_receiver_accept {
                            if pct.needs_reinit {
                                {
                                    let mut approvals = transfer_start_approvals_net.lock().await;
                                    approvals.remove(&pct.session.session_id);
                                }
                                let (mut init_payload, _) =
                                    chunked_transfer::build_sealed_init_payload(
                                        &pct.session,
                                        &keypair_net,
                                    );
                                init_payload.resume_requested = pct.next_chunk > 0;
                                init_payload.requires_reapproval = true;
                                match bincode::serialize(&init_payload)
                                    .ok()
                                    .and_then(|init_bytes| {
                                        chunked_transfer::wrap_chunk_request(
                                            &keypair_net,
                                            MessageKind::ChunkTransferInit,
                                            init_bytes,
                                            pct.ttl,
                                        )
                                        .ok()
                                    }) {
                                    Some(init_request) => {
                                        network
                                            .swarm
                                            .behaviour_mut()
                                            .messaging
                                            .send_request(&pct.peer_id, init_request);
                                        pct.needs_reinit = false;
                                        pct.backoff_until = Some(
                                            tokio::time::Instant::now()
                                                + tokio::time::Duration::from_millis(250),
                                        );
                                        print_async_notice(
                                            &config_net.agent.name,
                                            format!(
                                                "   {} {} transfer init re-sent, waiting for resume/accept",
                                                "Pending:".yellow().bold(),
                                                pct.peer_name.cyan(),
                                            ),
                                        );
                                    }
                                    None => {
                                        pct.backoff_until = Some(
                                            tokio::time::Instant::now()
                                                + tokio::time::Duration::from_secs(1),
                                        );
                                    }
                                }
                            } else {
                                let approval = {
                                    let mut approvals = transfer_start_approvals_net.lock().await;
                                    approvals.remove(&pct.session.session_id)
                                };
                                let approved_by_expected_peer = approval
                                    .as_ref()
                                    .is_some_and(|approval| approval.peer_did == pct.peer_did);
                                if !approved_by_expected_peer {
                                    pct.backoff_until = Some(
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_millis(250),
                                    );
                                } else {
                                    if let Some(approval) = approval.as_ref() {
                                        pct.next_chunk =
                                            super::libp2p_command_transfer::apply_tor_transfer_resume_snapshot(
                                                &mut pct.session,
                                                &approval.received_chunks,
                                            );
                                    }
                                    pct.awaiting_receiver_accept = false;
                                    pct.backoff_until = None;
                                    println!(
                                        "   {} {} approved transfer {}, starting chunk stream...",
                                        "Start:".green().bold(),
                                        pct.peer_name.cyan(),
                                        pct.session.session_id[..16].dimmed()
                                    );
                                }
                            }
                        }

                        // ── Proactive Tor bridge rotation ──────────────────────
                        // Tor circuits die after ~10-25 min. Every 8 min, create
                        // a warm standby bridge so libp2p has 2 connections.
                        // When the old circuit dies, the new one is already there.
                        // Transfer never sees a disconnection.
                        const BRIDGE_REFRESH_SECS: u64 = 480; // 8 minutes
                        if keep_transfer
                            && !pct.bridge_warming
                            && pct.peer_onion.is_some()
                            && pct.last_bridge_at.elapsed()
                                > tokio::time::Duration::from_secs(BRIDGE_REFRESH_SECS)
                        {
                            pct.bridge_warming = true;
                            let onion_addr = pct.peer_onion.clone().unwrap_or_default();
                            let onion_port = pct.peer_onion_port;
                            let bridge_peer_did = pct.peer_did.clone();
                            let bridge_peer_id = pct.peer_id.clone();
                            if let Some(ref tor_mgr) = network.tor_manager {
                                let tor_mgr_c = Arc::clone(tor_mgr);
                                let warmup_tx = cmd_tx_net.clone();
                                tokio::spawn(async move {
                                    tracing::info!(
                                        peer = %bridge_peer_id,
                                        "Proactive bridge rotation: creating warm standby..."
                                    );
                                    match tor_bridge::create_tor_bridge_isolated(
                                        &tor_mgr_c,
                                        &onion_addr,
                                        onion_port,
                                        Some(&bridge_peer_did),
                                    )
                                    .await
                                    {
                                        Ok(bridge_port) => {
                                            let _ = warmup_tx
                                                .send(NetworkCommand::TorRedial {
                                                    peer_id: bridge_peer_id.clone(),
                                                    peer_did: bridge_peer_did.clone(),
                                                    bridge_port,
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                peer = %bridge_peer_id,
                                                %e,
                                                "Warm standby bridge failed (will retry next cycle)"
                                            );
                                            // Send a signal to reset bridge_warming flag.
                                            let _ = warmup_tx
                                                .send(NetworkCommand::TorRedialFailed {
                                                    peer_id: bridge_peer_id,
                                                    peer_did: bridge_peer_did,
                                                })
                                                .await;
                                        }
                                    }
                                });
                            }
                        }

                        if keep_transfer && tor_transfer_can_stream_chunks(&pct) {
                            let i = pct.next_chunk;

                            if i < pct.session.total_chunks {
                                // Prepare and send one chunk (padded to 10MB for traffic analysis resistance).
                                let ok = (|| -> Result<libp2p::request_response::OutboundRequestId> {
                                    let chunk_data = pct.chunk_source.read_chunk(&pct.session, i)?;
                                    let (encrypted_chunk, padded_data, actual_size) =
                                        chunked_transfer::encrypt_chunk_padded(
                                            &pct.session,
                                            i,
                                            &chunk_data,
                                            &keypair_net,
                                            &pct.x25519_pk,
                                            pct.kyber_pk.as_deref(),
                                        )?;
                                    let mut chunk_payload = chunked_transfer::build_chunk_payload_padded(
                                        &encrypted_chunk,
                                        padded_data,
                                        actual_size,
                                    );

                                    // For chunk[0]: attach encrypted sealed metadata.
                                    if i == 0 {
                                        let (_, sealed_meta) =
                                            chunked_transfer::build_sealed_init_payload(
                                                &pct.session,
                                                &keypair_net,
                                            );
                                        match chunked_transfer::encrypt_sealed_metadata(
                                            &sealed_meta,
                                            &pct.x25519_pk,
                                            pct.kyber_pk.as_deref(),
                                        ) {
                                            Ok((enc_meta, env_bytes)) => {
                                                chunk_payload.sealed_metadata = Some(enc_meta);
                                                chunk_payload.sealed_metadata_key_envelope =
                                                    Some(env_bytes);
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    peer = %pct.peer_id,
                                                    %e,
                                                    "Failed to seal metadata for chunk[0]"
                                                );
                                            }
                                        }
                                    }

                                    let chunk_bytes = bincode::serialize(&chunk_payload)
                                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                                    let chunk_request = chunked_transfer::wrap_chunk_request(
                                        &keypair_net,
                                        MessageKind::ChunkData,
                                        chunk_bytes,
                                        0,
                                    )?;
                                    let req_id = network
                                        .swarm
                                        .behaviour_mut()
                                        .messaging
                                        .send_request(&pct.peer_id, chunk_request);
                                    Ok(req_id)
                                })();

                                match ok {
                                    Ok(req_id) => {
                                        pct.inflight_request = Some(req_id);
                                        // Rate-limited progress: update every ~2% or first/last chunk.
                                        let print_interval =
                                            std::cmp::max(1, pct.session.total_chunks / 50);
                                        if (i + 1) == 1
                                            || (i + 1) % print_interval == 0
                                            || (i + 1) == pct.session.total_chunks
                                        {
                                            let total_mb =
                                                pct.session.total_size as f64 / (1024.0 * 1024.0);
                                            let sent_mb = ((i + 1) as f64
                                                * pct.chunk_size as f64)
                                                / (1024.0 * 1024.0);
                                            let pct_done = ((i + 1) as f64
                                                / pct.session.total_chunks as f64
                                                * 100.0) as u32;
                                            print_async_progress_notice(format!(
                                                "   {} [{}/{}] {:.1}/{:.1} MB ({}%)",
                                                "Sending:".yellow(),
                                                i + 1,
                                                pct.session.total_chunks,
                                                sent_mb,
                                                total_mb,
                                                pct_done,
                                            ));
                                            emit_transfer_progress_event(
                                                "outgoing_progress",
                                                "out",
                                                Some(&pct.peer_did),
                                                Some(&pct.peer_name),
                                                Some(&pct.session.session_id),
                                                Some(&pct.path),
                                                i + 1,
                                                pct.session.total_chunks,
                                                ((i + 1) as u64)
                                                    .saturating_mul(pct.chunk_size as u64),
                                                pct.session.total_size,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        println!(
                                            "\n   {} chunk {}: {}",
                                            "Send failed:".red().bold(),
                                            i,
                                            e
                                        );
                                        pct.chunk_source.secure_cleanup();
                                        keep_transfer = false;
                                    }
                                }
                            } else {
                                // All chunks sent → send TransferComplete + clean up.
                                let complete_payload =
                                    chunked_transfer::build_complete_payload(&pct.session);
                                if let Ok(complete_bytes) = bincode::serialize(&complete_payload) {
                                    if let Ok(complete_request) =
                                        chunked_transfer::wrap_chunk_request(
                                            &keypair_net,
                                            MessageKind::TransferComplete,
                                            complete_bytes,
                                            pct.ttl,
                                        )
                                    {
                                        network
                                            .swarm
                                            .behaviour_mut()
                                            .messaging
                                            .send_request(&pct.peer_id, complete_request);
                                    }
                                }

                                println!(
                                    "\n   {} {} ({:.1} MB, {} chunks) -> {} [E2EE + Merkle + signed]",
                                    "Sent:".green().bold(),
                                    pct.path,
                                    pct.packed_mb,
                                    pct.session.total_chunks,
                                    pct.peer_name.cyan(),
                                );

                                {
                                    let mut a = audit_net.lock().await;
                                    a.record(
                                        "CHUNKED_FILE_SEND",
                                        &config_net.agent.did,
                                        &format!(
                                            "path={} to={} size={} chunks={}",
                                            pct.path,
                                            pct.peer_did,
                                            pct.packed_size,
                                            pct.session.total_chunks
                                        ),
                                    );
                                }

                                emit_transfer_event(
                                    "outgoing_completed",
                                    "out",
                                    Some(&pct.peer_did),
                                    Some(&pct.peer_name),
                                    Some(&pct.session.session_id),
                                    Some(&pct.path),
                                    Some("chunked_transfer_sent"),
                                );

                                // Securely clear transfer staging data.
                                pct.chunk_source.secure_cleanup();
                                // Secure wipe saved session file (contains transfer metadata)
                                // only when disk-backed resume mode is allowed.
                                if !no_resume_session_persistence {
                                    let session_dir = runtime_temp_path("qypha-sessions");
                                    let session_file =
                                        session_dir.join(format!("{}.session.json", pct.session.session_id));
                                    secure_wipe_file(&session_file);
                                }
                                keep_transfer = false;
                            }
                        }
                    } // else peer_alive

                    if keep_transfer {
                        pending_chunk_transfers.insert(transfer_key, pct);
                    }
                }

                // ── Cover traffic emitter (indistinguishable from real traffic) ──
                _ = cover_ticker.tick(), if cover_active => {
                    // MILITARY REQUIREMENT: Cover packets MUST be structurally identical
                    // to real Heartbeat messages — same signature length (64 bytes),
                    // same payload format, same metadata fields.
                    // An observer monitoring the wire CANNOT distinguish cover from real.
                    let cover_data = crate::shadow::generate_cover_packet();
                    let nonce = crate::crypto::next_request_nonce();

                    // Sign canonical data: msg_type || payload || nonce || timestamp
                    // Must match verification in message handler.
                    let cover_msg_type_bytes = serde_json::to_vec(&MessageKind::Heartbeat).unwrap_or_default();
                    let mut cover_signed = Vec::with_capacity(cover_msg_type_bytes.len() + cover_data.len() + 16);
                    cover_signed.extend_from_slice(&cover_msg_type_bytes);
                    cover_signed.extend_from_slice(&cover_data);
                    cover_signed.extend_from_slice(&nonce.to_le_bytes());
                    cover_signed.extend_from_slice(&nonce.to_le_bytes());
                    let cover_sig = signing::sign_data(&sign_key, &cover_signed);

                    let cover_request = AgentRequest {
                        message_id: uuid::Uuid::new_v4().to_string(),
                        sender_did: config_net.agent.did.clone(),
                        sender_name: config_net.agent.name.clone(),
                        sender_role: "agent".to_string(),
                        msg_type: MessageKind::Heartbeat,
                        payload: cover_data,
                        signature: cover_sig,
                        nonce,
                        timestamp: nonce,
                        ttl_ms: 0,
                    };
                    for entry in peers_net.iter() {
                        // Only send cover traffic to peers that completed handshake
                        // (have verifying_key). Sending to peers still in handshake
                        // floods Yamux sub-streams and causes "max sub-streams reached" loop.
                        if entry.value().verifying_key.is_none() {
                            continue;
                        }
                        let pid = entry.value().peer_id;
                        network.swarm.behaviour_mut().messaging
                            .send_request(&pid, cover_request.clone());
                    }
                    tracing::trace!(
                        peer_count = peers_net.len(),
                        "Cover traffic emitted to all peers"
                    );

                    // Random next interval: 15-30s with 1s granularity.
                    // Each emission independently picks a new wait time —
                    // no repeating pattern for timing analysis to detect.
                    let next_ms = if cover_active { 15_000 + (rand::random::<u64>() % 16) * 1_000 } else { 3600_000 };
                    cover_ticker = tokio::time::interval(
                        tokio::time::Duration::from_millis(next_ms)
                    );
                    // CRITICAL: Skip the immediate first tick of the new interval.
                    // Without this, every cover emission creates a new interval that
                    // fires instantly → infinite loop flooding peers with cover traffic.
                    cover_ticker.reset();
                }

                // ── Signal handler: emergency Ghost cleanup on Ctrl-C/SIGTERM ──
                _ = tokio::signal::ctrl_c() => {
                    if GHOST_MODE_ACTIVE.load(Ordering::SeqCst) {
                        eprintln!("\n   \x1b[31m\x1b[1mGHOST: Signal caught — emergency cleanup...\x1b[0m");
                        emergency_ghost_cleanup();
                        break;
                    }
                    if shutdown_notice_deadline.is_none() {
                        let notice_count = queue_shutdown_disconnect_notices(
                            &mut network,
                            &peers_net,
                            &direct_peer_dids_net,
                            &pending_chunk_transfers,
                            &sign_key,
                            &config_net,
                        );
                        shutdown_notice_deadline = Some(
                            tokio::time::Instant::now()
                                + tokio::time::Duration::from_millis(
                                    shutdown_notice_grace_ms(
                                        &config_net.network.transport_mode,
                                        !pending_chunk_transfers.is_empty(),
                                    ),
                                ),
                        );
                        if notice_count == 0 {
                            break;
                        }
                    }
                }

                // ── REPL commands ──────────────────────────────────────────
                Some(cmd) = cmd_rx.recv() => {
                    if let NetworkCommand::Shutdown(done) = cmd {
                        shutdown_done = Some(done);
                        if shutdown_notice_deadline.is_none() {
                            let notice_count = queue_shutdown_disconnect_notices(
                                &mut network,
                                &peers_net,
                                &direct_peer_dids_net,
                                &pending_chunk_transfers,
                                &sign_key,
                                &config_net,
                            );
                            shutdown_notice_deadline = Some(
                                tokio::time::Instant::now()
                                    + tokio::time::Duration::from_millis(
                                        shutdown_notice_grace_ms(
                                            &config_net.network.transport_mode,
                                            !pending_chunk_transfers.is_empty(),
                                        ),
                                    ),
                            );
                            if notice_count == 0 {
                                break;
                            }
                        }
                        continue;
                    }
                    if shutdown_notice_deadline.is_some() {
                        continue;
                    }
                    handle_libp2p_command(
                        cmd,
                        Libp2pCommandHandlerState {
                            network: &mut network,
                            handshake_sent: &mut handshake_sent,
                            pending_chunk_transfers: &mut pending_chunk_transfers,
                            pending_disconnect_notices: &mut pending_disconnect_notices,
                            pending_tor_reconnects: &mut pending_tor_reconnects,
                            pending_tor_dial_seeds: &mut pending_tor_dial_seeds,
                            pending_tor_direct_contact_requests:
                                &mut pending_tor_direct_contact_requests,
                            pending_user_chat_requests: &mut pending_user_chat_requests,
                        },
                        Libp2pCommandHandlerShared {
                            agent_data_dir: &agent_data_dir,
                            cmd_tx_net: &cmd_tx_net,
                            receive_dir_config_net: &receive_dir_config_net,
                            peers_net: &peers_net,
                            config_net: &config_net,
                            sign_key: &sign_key,
                            keypair_net: &keypair_net,
                            audit_net: &audit_net,
                            rbac_net: &rbac_net,
                            peer_store_net: &peer_store_net,
                            used_invites_net: &used_invites_net,
                            used_invites_path_net: &used_invites_path_net,
                            used_invites_persist_key_net: &used_invites_persist_key_net,
                            group_mailboxes_net: &group_mailboxes_net,
                            handshake_request_gate_net: &handshake_request_gate,
                            mailbox_transport_net: &mailbox_transport_net,
                            contact_mailbox_transport_net: &contact_mailbox_transport_net,
                            contact_bundle_transport_net: &contact_bundle_transport_net,
                            group_invite_bundle_transport_net: &group_invite_bundle_transport_net,
                            public_group_invite_bundle_service_net: &public_group_invite_bundle_service_net,
                            direct_peer_dids_net: &direct_peer_dids_net,
                            invite_proof_net: &invite_proof_net,
                            manual_disconnect_dids_net: &manual_disconnect_dids_net,
                            ip_hidden_net: &ip_hidden_net,
                            ratchet_mgr_net: &ratchet_mgr_net,
                            pending_hybrid_ratchet_inits_net:
                                &pending_hybrid_ratchet_inits_net,
                            ratchet_init_pub_hex_net: &ratchet_init_pub_hex_net,
                            pending_contact_requests_net: &pending_contact_requests_net,
                            log_mode_net: &log_mode_net,
                            our_peer_id,
                            no_resume_session_persistence,
                            no_persistent_artifact_store,
                            ram_only_chunk_staging,
                        },
                    )
                    .await;
                }

                _ = async {
                    if let Some(deadline) = shutdown_notice_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    break;
                }
            }
        }

        drop(network);
        if let Some(done) = shutdown_done.take() {
            let _ = done.send(());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        has_live_authenticated_tor_peer, repair_invalid_tor_reconnect_seed,
        should_suspend_remote_offline_tor_reconnect, shutdown_notice_grace_ms,
        take_expired_disconnect_notice_peers, tor_reconnect_seed_targets_local_identity,
        tor_transfer_can_stream_chunks, yield_before_processing_ready_tor_transfer,
        LIBP2P_SHUTDOWN_NOTICE_GRACE_MS, LIBP2P_TOR_SHUTDOWN_NOTICE_GRACE_MS,
        LIBP2P_TOR_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS,
    };
    use crate::agent::daemon::{
        ActiveIncomingIrohTransfer, ChunkSource, PeerInfo, PendingChunkTransfer,
        PendingDisconnectNotice, PendingTorReconnect, DEFAULT_AGENT_ROLE,
    };
    use crate::artifact::chunked_transfer;
    use crate::config::{AppConfig, TransportMode};
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_bundle::ContactBundleGetResponse;
    use crate::network::contact_bundle_transport::ContactBundleTransport;
    use crate::network::did_profile::{DidContactService, DidProfile};
    use crate::network::peer_store::{KnownPeer, PeerStore};
    use dashmap::DashMap;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn tor_transfer_shutdown_notice_grace_is_extended() {
        assert_eq!(
            shutdown_notice_grace_ms(&TransportMode::Tor, true),
            LIBP2P_TOR_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS
        );
        assert_eq!(
            shutdown_notice_grace_ms(&TransportMode::Tor, false),
            LIBP2P_TOR_SHUTDOWN_NOTICE_GRACE_MS
        );
        assert_eq!(
            shutdown_notice_grace_ms(&TransportMode::Internet, true),
            LIBP2P_SHUTDOWN_NOTICE_GRACE_MS
        );
    }

    #[tokio::test]
    async fn ready_tor_transfer_yield_is_not_immediately_ready() {
        use std::future::Future;
        use std::task::{Context, Poll};

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(yield_before_processing_ready_tor_transfer());

        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Pending
        ));

        future.await;
    }

    #[test]
    fn remote_offline_tor_reconnect_remains_enabled_without_transfer_context() {
        let transfers = DashMap::new();
        let pending = HashMap::new();
        assert!(!should_suspend_remote_offline_tor_reconnect(
            true,
            &pending,
            &transfers,
            "did:nxf:peer"
        ));
        assert!(!should_suspend_remote_offline_tor_reconnect(
            false,
            &pending,
            &transfers,
            "did:nxf:peer"
        ));
    }

    #[test]
    fn remote_offline_tor_reconnect_stays_enabled_with_paused_transfer_sender() {
        let transfers = DashMap::new();
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
        let mut pending = HashMap::new();
        let peer_id = libp2p::PeerId::random();
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
        transfers.insert(
            "sess-1".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-1".to_string(),
                sender_did: "did:nxf:peer".to_string(),
                sender_name: "peer".to_string(),
                total_chunks: 83,
                received_chunks: 6,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: true,
            },
        );

        assert!(!should_suspend_remote_offline_tor_reconnect(
            true,
            &pending,
            &transfers,
            "did:nxf:peer"
        ));
        assert!(!should_suspend_remote_offline_tor_reconnect(
            true,
            &pending,
            &transfers,
            "did:nxf:other"
        ));
    }

    #[test]
    fn tor_transfer_waiting_for_approval_never_streams_chunks() {
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
        let mut pending = PendingChunkTransfer {
            peer_id,
            peer_name: "peer".to_string(),
            peer_did: "did:nxf:peer".to_string(),
            session,
            chunk_source: ChunkSource::InMemory(chunks),
            next_chunk: 11,
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
            awaiting_receiver_accept: true,
            awaiting_started_at: tokio::time::Instant::now(),
            needs_reinit: true,
        };

        assert!(!tor_transfer_can_stream_chunks(&pending));
        pending.awaiting_receiver_accept = false;
        assert!(tor_transfer_can_stream_chunks(&pending));
    }

    #[test]
    fn expired_disconnect_notice_peers_are_drained_by_deadline() {
        let overdue_peer = libp2p::PeerId::random();
        let future_peer = libp2p::PeerId::random();
        let now = tokio::time::Instant::now();
        let request_id_one =
            unsafe { std::mem::transmute::<u64, libp2p::request_response::OutboundRequestId>(1) };
        let request_id_two =
            unsafe { std::mem::transmute::<u64, libp2p::request_response::OutboundRequestId>(2) };
        let mut pending = HashMap::new();
        pending.insert(
            request_id_one,
            PendingDisconnectNotice {
                peer_id: overdue_peer,
                deadline: now - tokio::time::Duration::from_millis(1),
            },
        );
        pending.insert(
            request_id_two,
            PendingDisconnectNotice {
                peer_id: future_peer,
                deadline: now + tokio::time::Duration::from_secs(10),
            },
        );

        let expired = take_expired_disconnect_notice_peers(&mut pending, now);
        assert_eq!(expired, vec![overdue_peer]);
        assert_eq!(pending.len(), 1);
        assert!(pending.values().any(|entry| entry.peer_id == future_peer));
    }

    #[test]
    fn live_authenticated_tor_peer_check_ignores_stale_reconnect_placeholder() {
        let peers = DashMap::new();
        let live_peer_id = libp2p::PeerId::random();
        let stale_placeholder_id = libp2p::PeerId::random();
        let did = "did:nxf:tor-peer";

        peers.insert(
            stale_placeholder_id.to_string(),
            PeerInfo {
                peer_id: stale_placeholder_id,
                did: did.to_string(),
                name: "tor-peer".to_string(),
                role: "unknown".to_string(),
                onion_address: Some("torpeeraddress123.onion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        assert!(!has_live_authenticated_tor_peer(&peers, did, |_| false));

        peers.insert(
            live_peer_id.to_string(),
            PeerInfo {
                peer_id: live_peer_id,
                did: did.to_string(),
                name: "tor-peer".to_string(),
                role: "agent".to_string(),
                onion_address: Some("torpeeraddress123.onion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([4u8; 32]),
            },
        );

        assert!(has_live_authenticated_tor_peer(&peers, did, |peer| {
            peer.peer_id == live_peer_id
        }));
    }

    fn sample_tor_config(local_did: &str, bundle_endpoint: &str) -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": "tester",
                "role": "agent",
                "did": local_did,
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false,
                "transport_mode": "tor",
                "tor": {},
                "iroh": {},
                "mailbox": {
                    "pool_endpoints": [bundle_endpoint],
                }
            },
            "security": {
                "require_mtls": false,
                "max_message_size_bytes": 1048576,
                "nonce_window_size": 64,
                "shadow_mode_enabled": false,
                "log_mode": "safe",
            }
        }))
        .expect("test config")
    }

    async fn spawn_contact_bundle_server(profile: Option<DidProfile>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bundle listener");
        let address = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept bundle request");
            let mut buffer = Vec::new();
            let mut temp = [0u8; 2048];
            let header_end = loop {
                let read = socket.read(&mut temp).await.expect("read request");
                assert!(read > 0, "bundle request ended before headers");
                buffer.extend_from_slice(&temp[..read]);
                if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let header_text =
                std::str::from_utf8(&buffer[..header_end]).expect("utf8 request headers");
            let content_length = header_text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while buffer.len() < header_end + content_length {
                let read = socket.read(&mut temp).await.expect("read request body");
                assert!(read > 0, "bundle request ended before body");
                buffer.extend_from_slice(&temp[..read]);
            }

            let request: crate::network::contact_bundle::ContactBundleGetRequest =
                serde_json::from_slice(&buffer[header_end..header_end + content_length])
                    .expect("bundle request json");
            let response = match profile {
                Some(profile) => {
                    ContactBundleGetResponse::with_profile(request.contact_did, profile)
                }
                None => ContactBundleGetResponse::empty(request.contact_did),
            };
            let body = serde_json::to_vec(&response).expect("bundle response json");
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket
                .write_all(http.as_bytes())
                .await
                .expect("write response headers");
            socket.write_all(&body).await.expect("write response body");
            socket.flush().await.expect("flush response");
        });

        format!("http://127.0.0.1:{}", address.port())
    }

    #[test]
    fn tor_reconnect_seed_detects_local_identity_routes() {
        let our_peer_id = libp2p::PeerId::random();
        let pending = PendingTorReconnect {
            did: "did:nxf:remote".to_string(),
            name: "remote".to_string(),
            peer_id: our_peer_id.to_string(),
            onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx".to_string(),
            onion_port: 9090,
            next_attempt_at: tokio::time::Instant::now(),
            attempts: 0,
            inflight: false,
        };
        assert!(tor_reconnect_seed_targets_local_identity(
            &pending,
            "did:nxf:local",
            Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            our_peer_id,
        ));

        let pending = PendingTorReconnect {
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ.onion"
                .to_string(),
            ..pending
        };
        assert!(tor_reconnect_seed_targets_local_identity(
            &pending,
            "did:nxf:local",
            Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            our_peer_id,
        ));
    }

    #[tokio::test]
    async fn invalid_tor_reconnect_seed_refreshes_from_contact_bundle() {
        let temp = tempdir().expect("temp dir");
        let local = AgentKeyPair::generate("local", "agent");
        let remote = AgentKeyPair::generate("remote", "agent");
        let remote_onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx".to_string();
        let local_onion = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
        let remote_profile = DidProfile::generate(
            &remote,
            vec![DidContactService::TorDirect {
                onion_address: remote_onion.clone(),
                port: 9444,
            }],
            None,
        );
        let bundle_endpoint = spawn_contact_bundle_server(Some(remote_profile)).await;
        let config = sample_tor_config(&local.did, &bundle_endpoint);
        let transport = Arc::new(ContactBundleTransport::new(
            temp.path().join("bundle-client"),
        ));
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let our_peer_id = libp2p::PeerId::random();

        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: remote.did.clone(),
                name: "remote".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                peer_id: our_peer_id.to_string(),
                onion_address: Some(local_onion.clone()),
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

        let mut pending = HashMap::from([(
            remote.did.clone(),
            PendingTorReconnect {
                did: remote.did.clone(),
                name: "remote".to_string(),
                peer_id: our_peer_id.to_string(),
                onion_address: local_onion.clone(),
                onion_port: 9090,
                next_attempt_at: tokio::time::Instant::now(),
                attempts: 0,
                inflight: false,
            },
        )]);

        assert!(
            repair_invalid_tor_reconnect_seed(
                &mut pending,
                &peer_store,
                &transport,
                temp.path(),
                &config,
                &remote.did,
                &local.did,
                Some(&local_onion),
                our_peer_id,
            )
            .await
        );

        let repaired = pending.get(&remote.did).expect("pending reconnect");
        assert_eq!(repaired.onion_address, remote_onion);
        assert_eq!(repaired.onion_port, 9444);
        assert_ne!(repaired.peer_id, our_peer_id.to_string());

        let store = peer_store.lock().await;
        let stored = store.get(&remote.did).expect("stored peer");
        assert_eq!(stored.onion_address.as_deref(), Some(remote_onion.as_str()));
        assert_eq!(stored.onion_port, 9444);
        assert_ne!(stored.peer_id, our_peer_id.to_string());
    }

    #[tokio::test]
    async fn invalid_tor_reconnect_seed_defers_when_bundle_lookup_fails() {
        let temp = tempdir().expect("temp dir");
        let local = AgentKeyPair::generate("local", "agent");
        let remote = AgentKeyPair::generate("remote", "agent");
        let local_onion = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
        let bundle_endpoint = spawn_contact_bundle_server(None).await;
        let config = sample_tor_config(&local.did, &bundle_endpoint);
        let transport = Arc::new(ContactBundleTransport::new(
            temp.path().join("bundle-client"),
        ));
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let our_peer_id = libp2p::PeerId::random();
        let before = tokio::time::Instant::now();

        let mut pending = HashMap::from([(
            remote.did.clone(),
            PendingTorReconnect {
                did: remote.did.clone(),
                name: "remote".to_string(),
                peer_id: our_peer_id.to_string(),
                onion_address: local_onion.clone(),
                onion_port: 9090,
                next_attempt_at: before,
                attempts: 0,
                inflight: true,
            },
        )]);

        assert!(
            !repair_invalid_tor_reconnect_seed(
                &mut pending,
                &peer_store,
                &transport,
                temp.path(),
                &config,
                &remote.did,
                &local.did,
                Some(&local_onion),
                our_peer_id,
            )
            .await
        );

        let deferred = pending.get(&remote.did).expect("deferred reconnect");
        assert!(!deferred.inflight);
        assert_eq!(deferred.attempts, 1);
        assert!(deferred.next_attempt_at > before);
        assert_eq!(deferred.onion_address, local_onion);
    }
}

use super::handshake_request_gate::HandshakeRequestGate;
use super::incoming_connect_gate::IncomingConnectGate;
use super::iroh_command_handlers::{
    handle_iroh_command, IrohCommandHandlerShared, IrohCommandHandlerState,
};
use super::iroh_event_handlers::{
    handle_iroh_event, IrohEventHandlerOutcome, IrohEventHandlerShared, IrohEventHandlerState,
};
use super::paths::{
    emit_transfer_event_with_group, emit_transfer_event_with_handoff_and_group,
    emit_transfer_progress_event_with_group,
};
use super::*;
use crate::agent::daemon::transfer_shared::build_fast_transfer_open_request;
use anyhow::{bail, Context};
use sha2::Digest;

pub(crate) struct IrohRuntimeContext {
    pub(crate) agent_data_dir: std::path::PathBuf,
    pub(crate) peers: Arc<DashMap<String, PeerInfo>>,
    pub(crate) initial_iroh_reconnects: Vec<KnownPeer>,
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
    pub(crate) ratchet_mgr: Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) pending_hybrid_ratchet_inits: Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_pub_hex: String,
    pub(crate) transfer_start_approvals:
        Arc<tokio::sync::Mutex<HashMap<String, TransferStartApproval>>>,
    pub(crate) pending_contact_requests: Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) incoming_connect_gate: Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) iroh_peer_liveness: Arc<DashMap<String, IrohPeerLiveness>>,
    pub(crate) iroh_handshake_sync: Arc<DashMap<String, IrohHandshakeSyncState>>,
    pub(crate) iroh_authenticated_sessions: Arc<IrohAuthenticatedSessionMap>,
    pub(crate) active_incoming_iroh_transfers: Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) active_chat_target_did: Arc<Mutex<Option<String>>>,
    pub(crate) receive_dir_config: Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    pub(crate) log_mode: LogMode,
    pub(crate) no_persistent_artifact_store: bool,
}

struct PendingFastGroupIrohTransfer {
    runtime_transfer_key: String,
    transfer_id: String,
    group_id: String,
    group_name: Option<String>,
    sender_member_id: String,
    recipient_member_id: String,
    recipient_name: String,
    session: chunked_transfer::TransferSession,
    chunk_source: ChunkSource,
    init_sent: bool,
    next_chunk: usize,
    x25519_pk: [u8; 32],
    kyber_pk: Vec<u8>,
    ttl: u64,
}

struct ActiveFastGroupIrohDownload {
    runtime_transfer_key: String,
    transfer_id: String,
    group_id: String,
    group_name: Option<String>,
    sender_member_id: String,
    sender_name: String,
    sender_verifying_key_hex: String,
    mailbox_transfer_id: String,
    recv: Option<ChunkedReceiveSession>,
}

const IROH_SHUTDOWN_NOTICE_TIMEOUT_MS: u64 = 1_500;
const IROH_SHUTDOWN_NOTICE_GRACE_MS: u64 = 350;
const IROH_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS: u64 = 3_000;
const IROH_TRANSFER_REQUEST_POLL_SLICE_MS: u64 = 50;
const IROH_TRANSFER_REQUEST_TIMEOUT_SECS: u64 = 20;
const IROH_TRANSFER_CONTROL_PLANE_PARK_MS: u64 = 250;

fn iroh_shutdown_notice_grace_ms(has_pending_transfers: bool) -> u64 {
    if has_pending_transfers {
        IROH_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS
    } else {
        IROH_SHUTDOWN_NOTICE_GRACE_MS
    }
}

fn iroh_shutdown_has_transfer_context(
    pending_iroh_chunk_transfers: &HashMap<String, PendingIrohChunkTransfer>,
    active_incoming_iroh_transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
) -> bool {
    !pending_iroh_chunk_transfers.is_empty() || !active_incoming_iroh_transfers.is_empty()
}

fn collect_iroh_shutdown_notice_peer_ids(
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
    pending_iroh_chunk_transfers: &HashMap<String, PendingIrohChunkTransfer>,
    active_incoming_iroh_transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
) -> Vec<libp2p::PeerId> {
    let mut peer_ids = Vec::new();
    let mut seen = HashSet::new();

    for peer in super::selectors::sorted_direct_peer_list(peers, direct_peer_dids) {
        if seen.insert(peer.peer_id) {
            peer_ids.push(peer.peer_id);
        }
    }

    for transfer in pending_iroh_chunk_transfers.values() {
        let live_peer_id = peers
            .iter()
            .find(|entry| entry.value().did == transfer.peer_did)
            .map(|entry| entry.value().peer_id);
        let shutdown_peer_id = live_peer_id.unwrap_or(transfer.peer_id);
        if seen.insert(shutdown_peer_id) {
            peer_ids.push(shutdown_peer_id);
        }
    }

    let sender_dids: std::collections::BTreeSet<String> = active_incoming_iroh_transfers
        .iter()
        .filter_map(|entry| {
            let sender_did = entry.sender_did.trim();
            if sender_did.is_empty() {
                None
            } else {
                Some(sender_did.to_string())
            }
        })
        .collect();

    for sender_did in sender_dids {
        if let Some(peer_id) = peers
            .iter()
            .find(|entry| entry.value().did == sender_did)
            .map(|entry| entry.value().peer_id)
        {
            if seen.insert(peer_id) {
                peer_ids.push(peer_id);
            }
        }
    }

    peer_ids
}

fn fast_group_runtime_transfer_key(ticket_id: &str) -> String {
    format!("fast-group-ticket:{ticket_id}")
}

fn next_pending_fast_group_transfer_key(
    pending_fast_group_iroh_transfers: &HashMap<String, PendingFastGroupIrohTransfer>,
    last_served_key: Option<&str>,
) -> Option<String> {
    let mut keys: Vec<&String> = pending_fast_group_iroh_transfers.keys().collect();
    keys.sort();
    let first = keys.first()?;

    if let Some(last_served_key) = last_served_key {
        if let Some(last_index) = keys.iter().position(|key| key.as_str() == last_served_key) {
            let next_index = (last_index + 1) % keys.len();
            return Some(keys[next_index].clone());
        }
    }

    Some((*first).clone())
}

async fn send_iroh_shutdown_disconnect_notices(
    iroh_network: &IrohTransport,
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
    pending_iroh_chunk_transfers: &HashMap<String, PendingIrohChunkTransfer>,
    active_incoming_iroh_transfers: &DashMap<String, ActiveIncomingIrohTransfer>,
    sign_key: &ed25519_dalek::SigningKey,
    config: &AppConfig,
) -> usize {
    let peer_ids = collect_iroh_shutdown_notice_peer_ids(
        peers,
        direct_peer_dids,
        pending_iroh_chunk_transfers,
        active_incoming_iroh_transfers,
    );
    if peer_ids.is_empty() {
        return 0;
    }

    let notice =
        build_disconnect_notice_request(sign_key, config, DisconnectNoticeKind::AgentOffline);
    for peer_id in &peer_ids {
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_millis(IROH_SHUTDOWN_NOTICE_TIMEOUT_MS),
            iroh_network.send_request_without_response(peer_id, &notice),
        )
        .await;
    }
    peer_ids.len()
}

async fn await_iroh_shutdown_notice_grace(notice_count: usize, has_pending_transfers: bool) {
    if notice_count == 0 {
        return;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(
        iroh_shutdown_notice_grace_ms(has_pending_transfers),
    ))
    .await;
}

async fn yield_before_processing_ready_iroh_transfer() {
    // Outgoing chunk streaming can stay perpetually ready; yield once so
    // shutdown/reconnect/control-plane work is not starved by the data pump.
    tokio::task::yield_now().await;
}

async fn send_iroh_transfer_request_interruptibly(
    iroh_network: &IrohTransport,
    peer_id: &libp2p::PeerId,
    request: &AgentRequest,
) -> Result<Option<crate::network::protocol::AgentResponse>> {
    if graceful_shutdown_requested() {
        return Ok(None);
    }

    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(IROH_TRANSFER_REQUEST_TIMEOUT_SECS);
    let send_future = iroh_network.send_request(peer_id, request);
    tokio::pin!(send_future);

    let slice = tokio::time::sleep(tokio::time::Duration::from_millis(
        IROH_TRANSFER_REQUEST_POLL_SLICE_MS,
    ));
    tokio::pin!(slice);

    loop {
        tokio::select! {
            result = &mut send_future => return result.map(Some),
            _ = &mut slice => {
                if graceful_shutdown_requested() {
                    return Ok(None);
                }
                if tokio::time::Instant::now() >= deadline {
                    bail!(
                        "iroh transfer request timed out after {} seconds",
                        IROH_TRANSFER_REQUEST_TIMEOUT_SECS
                    );
                }
                // Keep long-lived chunk sends from monopolizing the runtime if the
                // relay stalls; this gives other async work a chance to make progress.
                tokio::task::yield_now().await;
                slice.as_mut().reset(
                    tokio::time::Instant::now()
                        + tokio::time::Duration::from_millis(
                            IROH_TRANSFER_REQUEST_POLL_SLICE_MS,
                        ),
                );
            }
        }
    }
}

pub(crate) fn spawn_iroh_runtime(
    ctx: IrohRuntimeContext,
    mut iroh_network: IrohTransport,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
) {
    clear_graceful_shutdown_requested();
    let IrohRuntimeContext {
        agent_data_dir,
        peers: peers_net,
        initial_iroh_reconnects,
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
        ratchet_mgr: ratchet_mgr_net,
        pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits_net,
        ratchet_init_pub_hex: ratchet_init_pub_hex_net,
        transfer_start_approvals: transfer_start_approvals_net,
        pending_contact_requests: pending_contact_requests_net,
        incoming_connect_gate: incoming_connect_gate_net,
        iroh_peer_liveness: iroh_peer_liveness_net,
        iroh_handshake_sync: iroh_handshake_sync_net,
        iroh_authenticated_sessions: iroh_authenticated_sessions_net,
        active_incoming_iroh_transfers: active_incoming_iroh_transfers_net,
        active_chat_target_did: active_chat_target_did_net,
        receive_dir_config: receive_dir_config_net,
        log_mode: log_mode_net,
        no_persistent_artifact_store,
    } = ctx;
    let iroh_config = config_net.network.iroh.clone();
    let mut transfer_request_rx = iroh_network.take_transfer_request_rx();

    tokio::spawn(async move {
        let mut handshake_sent: IrohHandshakeTracker = HashMap::new();
        let mut pending_iroh_chunk_transfers: HashMap<String, PendingIrohChunkTransfer> =
            HashMap::new();
        let mut pending_fast_group_iroh_transfers: HashMap<String, PendingFastGroupIrohTransfer> =
            HashMap::new();
        let mut last_fast_group_transfer_key: Option<String> = None;
        let mut active_fast_group_iroh_downloads: HashMap<String, ActiveFastGroupIrohDownload> =
            HashMap::new();
        let mut pending_iroh_reconnects: HashMap<String, PendingIrohReconnect> = HashMap::new();
        let mut shutdown_done: Option<tokio::sync::oneshot::Sender<()>> = None;
        seed_initial_iroh_reconnects(&mut pending_iroh_reconnects, &initial_iroh_reconnects);
        let cover_active = config_net.security.cover_traffic.mode == "always";
        // Keep iroh sessions alive during idle periods to prevent QUIC idle timeout drops.
        let mut keepalive_ticker = tokio::time::interval(tokio::time::Duration::from_secs(10));
        keepalive_ticker.reset();
        let mut reconnect_ticker = tokio::time::interval(tokio::time::Duration::from_secs(1));
        reconnect_ticker.reset();
        let mut cover_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            config_net.security.cover_traffic.interval_secs.max(5),
        ));
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
        let mut anonymous_cover_ticker =
            tokio::time::interval(tokio::time::Duration::from_millis(250));
        anonymous_cover_ticker.reset();
        let mut fast_group_transfer_janitor = tokio::time::interval(
            tokio::time::Duration::from_secs(FAST_GROUP_TRANSFER_JANITOR_INTERVAL_SECS),
        );
        fast_group_transfer_janitor.reset();
        spawn_startup_identified_membership_announcements(
            Arc::clone(&group_mailboxes_net),
            Arc::clone(&mailbox_transport_net),
            sign_key.clone(),
        );

        loop {
            tokio::select! {
                event = iroh_network.next_event() => {
                    let outcome = handle_iroh_event(
                        event,
                        IrohEventHandlerState {
                            iroh_network: &mut iroh_network,
                            handshake_sent: &mut handshake_sent,
                            pending_iroh_reconnects: &mut pending_iroh_reconnects,
                        },
                        IrohEventHandlerShared {
                            peers_net: &peers_net,
                            config_net: &config_net,
                            keypair_net: &keypair_net,
                            ratchet_mgr_net: &ratchet_mgr_net,
                            audit_net: &audit_net,
                            peer_store_net: &peer_store_net,
                            group_mailboxes_net: &group_mailboxes_net,
                            direct_peer_dids_net: &direct_peer_dids_net,
                            invite_proof_net: &invite_proof_net,
                            incoming_connect_gate_net: &incoming_connect_gate_net,
                            manual_disconnect_dids_net: &manual_disconnect_dids_net,
                            remote_offline_dids_net: &remote_offline_dids_net,
                            pending_hybrid_ratchet_inits_net:
                                &pending_hybrid_ratchet_inits_net,
                            ratchet_init_pub_hex_net: &ratchet_init_pub_hex_net,
                            iroh_peer_liveness_net: &iroh_peer_liveness_net,
                            iroh_handshake_sync_net: &iroh_handshake_sync_net,
                            iroh_authenticated_sessions_net:
                                &iroh_authenticated_sessions_net,
                            active_incoming_iroh_transfers_net:
                                &active_incoming_iroh_transfers_net,
                            active_chat_target_did_net: &active_chat_target_did_net,
                        },
                    )
                    .await;
                    if matches!(outcome, IrohEventHandlerOutcome::Break) {
                        break;
                    }
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
                    launch_due_fast_group_transfers(
                        &group_mailboxes_net,
                        &config_net,
                        &keypair_net,
                        &mut iroh_network,
                        &mut pending_fast_group_iroh_transfers,
                        &mut active_fast_group_iroh_downloads,
                    ).await;
                }

                transfer_request = async {
                    match &mut transfer_request_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<crate::network::iroh_transport::IrohTransferIncomingRequest>>().await,
                    }
                } => {
                    handle_fast_group_transfer_request(
                        transfer_request,
                        &group_mailboxes_net,
                        &receive_dir_config_net,
                        &log_mode_net,
                        &config_net,
                        &keypair_net,
                        &mut iroh_network,
                        &peers_net,
                        &peer_store_net,
                        &manual_disconnect_dids_net,
                        &remote_offline_dids_net,
                        &mut pending_iroh_reconnects,
                        &mut pending_fast_group_iroh_transfers,
                        &mut active_fast_group_iroh_downloads,
                    ).await;
                }

                _ = anonymous_cover_ticker.tick() => {
                    emit_due_anonymous_cover_traffic_once(
                        &group_mailboxes_net,
                        &mailbox_transport_net,
                    ).await;
                }

                _ = fast_group_transfer_janitor.tick() => {
                    let mut registry = group_mailboxes_net.lock().await;
                    registry.prune_expired_fast_file_state_now();
                }

                _ = yield_before_processing_ready_iroh_transfer(), if pending_iroh_chunk_transfers.values().any(|p| {
                    iroh_transfer_ready(p, tokio::time::Instant::now())
                }) => {
                    let ready_transfer_key = pending_iroh_chunk_transfers
                        .iter()
                        .find(|(_, p)| iroh_transfer_ready(p, tokio::time::Instant::now()))
                        .map(|(k, _)| k.clone());
                    let Some(transfer_key) = ready_transfer_key else {
                        continue;
                    };

                    let Some(mut pct) = pending_iroh_chunk_transfers.remove(&transfer_key) else {
                        continue;
                    };
                    let mut keep_transfer = true;
                    let authenticated_session = has_authenticated_iroh_peer_session(
                        &iroh_network,
                        &iroh_authenticated_sessions_net,
                        &pct.peer_id,
                        &pct.peer_did,
                    )
                    .await;

                    if !authenticated_session {
                        park_iroh_transfer_until_authenticated_session(
                            &mut pct,
                            tokio::time::Instant::now(),
                        );
                        pending_iroh_chunk_transfers.insert(transfer_key, pct);
                        continue;
                    }

                    if pct.awaiting_receiver_accept {
                        if pct.needs_reinit {
                            let (mut init_payload, _) = chunked_transfer::build_sealed_init_payload(
                                &pct.session,
                                &keypair_net,
                            );
                            init_payload.resume_requested = pct.next_chunk > 0;
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
                                    match send_iroh_transfer_request_interruptibly(
                                        &iroh_network,
                                        &pct.peer_id,
                                        &init_request,
                                    )
                                    .await
                                    {
                                        Ok(Some(_)) => {
                                            pct.needs_reinit = false;
                                            pct.retry_after = None;
                                            print_async_notice(
                                                &config_net.agent.name,
                                                format!(
                                                    "   {} {} transfer init re-sent, waiting for resume/accept",
                                                    "Pending:".yellow().bold(),
                                                    pct.peer_name.cyan(),
                                                ),
                                            );
                                        }
                                        Ok(None) => {
                                            park_iroh_transfer_for_control_plane(&mut pct);
                                            pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                            continue;
                                        }
                                        Err(_) if schedule_iroh_chunk_transfer_retry(
                                            &mut pct,
                                            &peers_net,
                                            &active_chat_target_did_net,
                                            &invite_proof_net,
                                            &iroh_peer_liveness_net,
                                            &iroh_handshake_sync_net,
                                            &iroh_authenticated_sessions_net,
                                            &mut handshake_sent,
                                            &peer_store_net,
                                            &manual_disconnect_dids_net,
                                            &remote_offline_dids_net,
                                            &mut pending_iroh_reconnects,
                                            &config_net.agent.name,
                                            "re-send transfer init",
                                        )
                                        .await =>
                                        {
                                            pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                            continue;
                                        }
                                        Err(_) => {
                                            print_async_notice(
                                                &config_net.agent.name,
                                                format!(
                                                    "   {} {} transfer init could not be re-sent",
                                                    "Error:".red().bold(),
                                                    pct.peer_name.cyan(),
                                                ),
                                            );
                                            pct.chunk_source.secure_cleanup_async().await;
                                            keep_transfer = false;
                                        }
                                    }
                                }
                                None => {
                                    print_async_notice(
                                        &config_net.agent.name,
                                        format!(
                                            "   {} {} transfer init could not be rebuilt",
                                            "Error:".red().bold(),
                                            pct.peer_name.cyan(),
                                        ),
                                    );
                                    pct.chunk_source.secure_cleanup_async().await;
                                    keep_transfer = false;
                                }
                            }
                        }
                        if pct.awaiting_started_at.elapsed()
                            > tokio::time::Duration::from_secs(300)
                        {
                            print_async_notice(
                                &config_net.agent.name,
                                format!(
                                    "   {} receiver did not accept transfer {} within timeout; transfer aborted",
                                    "Timeout:".red().bold(),
                                    pct.session.session_id[..16].dimmed()
                                ),
                            );
                            pct.chunk_source.secure_cleanup_async().await;
                            keep_transfer = false;
                        }
                        if keep_transfer {
                            let approval = {
                                let mut approvals = transfer_start_approvals_net.lock().await;
                                approvals.remove(&pct.session.session_id)
                            };
                            let approved_by_expected_peer = approval
                                .as_ref()
                                .is_some_and(|approval| approval.peer_did == pct.peer_did);
                            if !approved_by_expected_peer {
                                pct.approval_poll_after = Some(
                                    tokio::time::Instant::now()
                                        + tokio::time::Duration::from_millis(200),
                                );
                            } else {
                                let resume_start = approval
                                    .as_ref()
                                    .map(|approval| {
                                        apply_transfer_resume_snapshot(
                                            &mut pct.session,
                                            &approval.received_chunks,
                                        )
                                    })
                                    .unwrap_or(0);
                                pct.next_chunk = resume_start;
                                pct.awaiting_receiver_accept = false;
                                pct.approval_poll_after = None;
                                pct.needs_reinit = false;
                                if resume_start > 0 {
                                    println!(
                                        "   {} {} resumed transfer {} from chunk {}/{}",
                                        "Resume:".green().bold(),
                                        pct.peer_name.cyan(),
                                        pct.session.session_id[..16].dimmed(),
                                        resume_start + 1,
                                        pct.session.total_chunks
                                    );
                                } else {
                                    println!(
                                        "   {} {} approved transfer {}, starting chunk stream...",
                                        "Start:".green().bold(),
                                        pct.peer_name.cyan(),
                                        pct.session.session_id[..16].dimmed()
                                    );
                                }
                            }
                        }
                    }

                    if keep_transfer && !pct.awaiting_receiver_accept {
                        if let Some(retry_after) = pct.retry_after {
                            if tokio::time::Instant::now() < retry_after {
                                pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                continue;
                            }
                            pct.retry_after = None;
                        }
                        if pct.next_chunk < pct.session.total_chunks {
                            let i = pct.next_chunk;
                            let chunk_data = match pct.chunk_source.read_chunk(&pct.session, i) {
                                Ok(data) => data,
                                Err(e) => {
                                    println!(
                                        "\n   {} chunk {}: {}",
                                        "Read failed:".red().bold(),
                                        i,
                                        e
                                    );
                                    pct.chunk_source.secure_cleanup_async().await;
                                    keep_transfer = false;
                                    Vec::new()
                                }
                            };
                            if keep_transfer {
                                if pct.merkle_proof_cache.len() != pct.session.total_chunks {
                                    match chunked_transfer::build_serialized_merkle_proof_cache(
                                        &pct.session,
                                    ) {
                                        Ok(cache) => pct.merkle_proof_cache = cache,
                                        Err(e) => {
                                            println!(
                                                "\n   {} chunk {}: {}",
                                                "Merkle prep failed:".red().bold(),
                                                i,
                                                e
                                            );
                                            pct.chunk_source.secure_cleanup_async().await;
                                            keep_transfer = false;
                                        }
                                    }
                                }
                                let encrypted = match pct.merkle_proof_cache.get(i) {
                                    Some(serialized_proof) => {
                                        match chunked_transfer::encrypt_chunk_padded_with_serialized_proof(
                                            &pct.session,
                                            i,
                                            serialized_proof,
                                            &chunk_data,
                                            &keypair_net,
                                            &pct.x25519_pk,
                                            Some(pct.kyber_pk.as_slice()),
                                        ) {
                                            Ok(v) => Some(v),
                                            Err(e) => {
                                                println!(
                                                    "\n   {} chunk {}: {}",
                                                    "Encrypt failed:".red().bold(),
                                                    i,
                                                    e
                                                );
                                                pct.chunk_source.secure_cleanup_async().await;
                                                keep_transfer = false;
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        println!(
                                            "\n   {} chunk {}: missing cached Merkle proof",
                                            "Merkle proof missing:".red().bold(),
                                            i
                                        );
                                        pct.chunk_source.secure_cleanup_async().await;
                                        keep_transfer = false;
                                        None
                                    }
                                };
                                if let Some((encrypted_chunk, padded_data, actual_size)) = encrypted {
                                    let mut chunk_payload = chunked_transfer::build_chunk_payload_padded(
                                        &encrypted_chunk,
                                        padded_data,
                                        actual_size,
                                    );
                                    if i == 0 {
                                        let (_, sealed_meta) = chunked_transfer::build_sealed_init_payload(
                                            &pct.session,
                                            &keypair_net,
                                        );
                                        if let Ok((enc_meta, env_bytes)) =
                                            chunked_transfer::encrypt_sealed_metadata(
                                                &sealed_meta,
                                                &pct.x25519_pk,
                                                Some(pct.kyber_pk.as_slice()),
                                            )
                                        {
                                            chunk_payload.sealed_metadata = Some(enc_meta);
                                            chunk_payload.sealed_metadata_key_envelope =
                                                Some(env_bytes);
                                        }
                                    }

                                    let chunk_bytes = match bincode::serialize(&chunk_payload) {
                                        Ok(b) => Some(b),
                                        Err(e) => {
                                            println!(
                                                "\n   {} chunk {}: {}",
                                                "Encode failed:".red().bold(),
                                                i,
                                                e
                                            );
                                            pct.chunk_source.secure_cleanup_async().await;
                                            keep_transfer = false;
                                            None
                                        }
                                    };
                                    if let Some(chunk_bytes) = chunk_bytes {
                                        let chunk_request = match chunked_transfer::wrap_chunk_request(
                                            &keypair_net,
                                            MessageKind::ChunkData,
                                            chunk_bytes,
                                            0,
                                        ) {
                                            Ok(r) => Some(r),
                                            Err(e) => {
                                                println!(
                                                    "\n   {} chunk {}: {}",
                                                    "Wrap failed:".red().bold(),
                                                    i,
                                                    e
                                                );
                                                pct.chunk_source.secure_cleanup_async().await;
                                                keep_transfer = false;
                                                None
                                            }
                                        };
                                        if let Some(chunk_request) = chunk_request {
                                            match send_iroh_transfer_request_interruptibly(
                                                &iroh_network,
                                                &pct.peer_id,
                                                &chunk_request,
                                            )
                                            .await
                                            {
                                                Ok(Some(_)) => {
                                                    mark_iroh_peer_active(
                                                        &iroh_peer_liveness_net,
                                                        &pct.peer_id,
                                                    );
                                                    pct.retry_after = None;
                                                    pct.reconnect_wait_secs = 0;
                                                    pct.next_chunk += 1;
                                                    let print_interval =
                                                        std::cmp::max(1, pct.session.total_chunks / 50);
                                                    if pct.next_chunk == 1
                                                        || pct.next_chunk % print_interval == 0
                                                        || pct.next_chunk == pct.session.total_chunks
                                                    {
                                                        let total_mb =
                                                            pct.session.total_size as f64 / (1024.0 * 1024.0);
                                                        let sent_mb = (pct.next_chunk as f64
                                                            * pct.chunk_size as f64)
                                                            / (1024.0 * 1024.0);
                                                        let pct_done = (pct.next_chunk as f64
                                                            / pct.session.total_chunks as f64
                                                            * 100.0) as u32;
                                                        print_async_progress_notice(format!(
                                                            "   {} [{}/{}] {:.1}/{:.1} MB ({}%)",
                                                            "Sending:".yellow(),
                                                            pct.next_chunk,
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
                                                            pct.next_chunk,
                                                            pct.session.total_chunks,
                                                            (pct.next_chunk as u64)
                                                                .saturating_mul(pct.chunk_size as u64),
                                                            pct.session.total_size,
                                                        );
                                                    }
                                                    tokio::task::yield_now().await;
                                                }
                                                Ok(None) => {
                                                    park_iroh_transfer_for_control_plane(&mut pct);
                                                    pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                                    continue;
                                                }
                                                Err(_) => {
                                                    reset_iroh_transfer_for_reapproval(&mut pct);
                                                    if schedule_iroh_chunk_transfer_retry(
                                                        &mut pct,
                                                        &peers_net,
                                                        &active_chat_target_did_net,
                                                        &invite_proof_net,
                                                        &iroh_peer_liveness_net,
                                                        &iroh_handshake_sync_net,
                                                        &iroh_authenticated_sessions_net,
                                                        &mut handshake_sent,
                                                        &peer_store_net,
                                                        &manual_disconnect_dids_net,
                                                        &remote_offline_dids_net,
                                                        &mut pending_iroh_reconnects,
                                                        &config_net.agent.name,
                                                        &format!("chunk {}", i),
                                                    )
                                                    .await
                                                    {
                                                        keep_transfer = true;
                                                    } else {
                                                        println!(
                                                            "\n   {} chunk {}",
                                                            "Send failed:".red().bold(),
                                                            i
                                                        );
                                                        pct.chunk_source.secure_cleanup_async().await;
                                                        keep_transfer = false;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            let complete_payload =
                                chunked_transfer::build_complete_payload(&pct.session);
                            if let Ok(complete_bytes) = bincode::serialize(&complete_payload) {
                                if let Ok(complete_request) = chunked_transfer::wrap_chunk_request(
                                    &keypair_net,
                                    MessageKind::TransferComplete,
                                    complete_bytes,
                                    pct.ttl,
                                ) {
                                    match send_iroh_transfer_request_interruptibly(
                                        &iroh_network,
                                        &pct.peer_id,
                                        &complete_request,
                                    )
                                    .await
                                    {
                                        Ok(Some(_)) => {
                                            mark_iroh_peer_active(
                                                &iroh_peer_liveness_net,
                                                &pct.peer_id,
                                            );
                                            pct.retry_after = None;
                                            pct.reconnect_wait_secs = 0;
                                        }
                                        Ok(None) => {
                                            park_iroh_transfer_for_control_plane(&mut pct);
                                            pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                            continue;
                                        }
                                        Err(_) if schedule_iroh_chunk_transfer_retry(
                                            &mut pct,
                                            &peers_net,
                                            &active_chat_target_did_net,
                                            &invite_proof_net,
                                            &iroh_peer_liveness_net,
                                            &iroh_handshake_sync_net,
                                            &iroh_authenticated_sessions_net,
                                            &mut handshake_sent,
                                            &peer_store_net,
                                            &manual_disconnect_dids_net,
                                            &remote_offline_dids_net,
                                            &mut pending_iroh_reconnects,
                                            &config_net.agent.name,
                                            "finalize transfer",
                                        )
                                        .await =>
                                        {
                                            pending_iroh_chunk_transfers.insert(transfer_key, pct);
                                            continue;
                                        }
                                        Err(_) => {}
                                    }
                                }
                            }
                            print_async_notice(
                                &config_net.agent.name,
                                format!(
                                    "   {} {} ({:.1} MB, {} chunks) -> {} [E2EE + Merkle + signed]",
                                    "Sent:".green().bold(),
                                    pct.path,
                                    pct.packed_mb,
                                    pct.session.total_chunks,
                                    pct.peer_name.cyan(),
                                ),
                            );
                            {
                                let mut a = audit_net.lock().await;
                                a.record(
                                    "CHUNKED_FILE_SEND",
                                    &config_net.agent.did,
                                    &format!(
                                        "path={} to={} size={} chunks={} transport=iroh",
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
                            pct.chunk_source.secure_cleanup_async().await;
                            keep_transfer = false;

                            // Large transfers can saturate the relay and starve unrelated
                            // sessions; sweep the known peer set and immediately queue
                            // reconnects for any missing direct lanes.
                            queue_post_transfer_reconnect_sweep(
                                &iroh_network,
                                &peer_store_net,
                                &peers_net,
                                &manual_disconnect_dids_net,
                                &remote_offline_dids_net,
                                &mut pending_iroh_reconnects,
                            )
                            .await;
                        }
                    }

                    if keep_transfer {
                        pending_iroh_chunk_transfers.insert(transfer_key, pct);
                    }
                }

                _ = futures::future::ready(()), if pending_fast_group_iroh_transfers.values().any(|_| true) => {
                    let ready_transfer_key = next_pending_fast_group_transfer_key(
                        &pending_fast_group_iroh_transfers,
                        last_fast_group_transfer_key.as_deref(),
                    );
                    let Some(transfer_key) = ready_transfer_key else {
                        continue;
                    };
                    last_fast_group_transfer_key = Some(transfer_key.clone());
                    let Some(mut pending) = pending_fast_group_iroh_transfers.remove(&transfer_key) else {
                        continue;
                    };
                    let keep_pending = drive_fast_group_transfer_once(
                        &config_net,
                        &keypair_net,
                        &group_mailboxes_net,
                        &mut iroh_network,
                        &peers_net,
                        &peer_store_net,
                        &manual_disconnect_dids_net,
                        &remote_offline_dids_net,
                        &mut pending_iroh_reconnects,
                        &mut active_fast_group_iroh_downloads,
                        &mut pending,
                    ).await;
                    if keep_pending {
                        pending_fast_group_iroh_transfers.insert(transfer_key, pending);
                    } else {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_staged_fast_file_transfer_inactive(&pending.transfer_id);
                        registry.prune_expired_fast_file_state_now();
                    }
                }

                _ = cover_ticker.tick(), if cover_active => {
                    let cover_data = crate::shadow::generate_cover_packet();
                    let nonce = crate::crypto::next_request_nonce();
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

                    let cover_targets: Vec<libp2p::PeerId> = peers_net
                        .iter()
                        .filter_map(|entry| {
                            if entry.value().verifying_key.is_none() {
                                None
                            } else {
                                Some(entry.value().peer_id)
                            }
                        })
                        .collect();
                    let mut stale_peers: Vec<libp2p::PeerId> = Vec::new();
                    for pid in cover_targets {
                        if iroh_peer_recently_active(
                            &iroh_peer_liveness_net,
                            &pid,
                            tokio::time::Duration::from_secs(30),
                        ) {
                            continue;
                        }
                        let send_result = tokio::time::timeout(
                            tokio::time::Duration::from_secs(8),
                            iroh_network.send_request(&pid, &cover_request),
                        )
                        .await;
                        match send_result {
                            Ok(Ok(_)) => {
                                mark_iroh_peer_active(&iroh_peer_liveness_net, &pid);
                            }
                            Ok(Err(e)) => {
                                let failures =
                                    note_iroh_keepalive_failure(&iroh_peer_liveness_net, &pid);
                                tracing::debug!(
                                    peer = %pid,
                                    %e,
                                    failures,
                                    "iroh cover heartbeat failed"
                                );
                                // Tolerate up to 18 consecutive failures (~3 min of
                                // unreachability) before attempting reconnect.  This
                                // keeps the connection alive through transient relay
                                // hiccups while still recovering from real outages.
                                if failures >= 18 {
                                    stale_peers.push(pid);
                                }
                            }
                            Err(_) => {
                                let failures =
                                    note_iroh_keepalive_failure(&iroh_peer_liveness_net, &pid);
                                tracing::warn!(
                                    peer = %pid,
                                    failures,
                                    "iroh cover heartbeat timeout"
                                );
                                if failures >= 18 {
                                    stale_peers.push(pid);
                                }
                            }
                        }
                    }
                    for pid in stale_peers {
                        let peer_info = peers_net
                            .get(&pid.to_string())
                            .map(|peer| (peer.did.clone(), peer.name.clone()));
                        let Some((did, _name)) = peer_info.filter(|(did, _)| !did.is_empty()) else {
                            continue;
                        };
                        let known = {
                            let ps = peer_store_net.lock().await;
                            ps.get(&did).cloned()
                        };
                        if let Some(kp) = known.filter(|kp| kp.iroh_endpoint_addr.is_some()) {
                            queue_iroh_reconnect(&mut pending_iroh_reconnects, &kp, true);
                        }
                    }
                }

                _ = keepalive_ticker.tick(), if !cover_active => {
                    let nonce = crate::crypto::next_request_nonce();
                    let heartbeat_data = b"KA".to_vec();
                    let heartbeat_mt_bytes =
                        serde_json::to_vec(&MessageKind::Heartbeat).unwrap_or_default();
                    let mut signed = Vec::with_capacity(heartbeat_mt_bytes.len() + heartbeat_data.len() + 16);
                    signed.extend_from_slice(&heartbeat_mt_bytes);
                    signed.extend_from_slice(&heartbeat_data);
                    signed.extend_from_slice(&nonce.to_le_bytes());
                    signed.extend_from_slice(&nonce.to_le_bytes());
                    let sig = signing::sign_data(&sign_key, &signed);

                    let request = AgentRequest {
                        message_id: uuid::Uuid::new_v4().to_string(),
                        sender_did: config_net.agent.did.clone(),
                        sender_name: config_net.agent.name.clone(),
                        sender_role: "agent".to_string(),
                        msg_type: MessageKind::Heartbeat,
                        payload: heartbeat_data,
                        signature: sig,
                        nonce,
                        timestamp: nonce,
                        ttl_ms: 0,
                    };

                    let active_transfer_peers: HashSet<libp2p::PeerId> =
                        pending_iroh_chunk_transfers
                            .values()
                            .map(|pending| pending.peer_id)
                            .collect();
                    let keepalive_targets: Vec<libp2p::PeerId> = peers_net
                        .iter()
                        .filter_map(|entry| {
                            if entry.value().verifying_key.is_none() {
                                None
                            } else {
                                Some(entry.value().peer_id)
                            }
                        })
                        .collect();
                    let mut stale_peers: Vec<libp2p::PeerId> = Vec::new();
                    for pid in keepalive_targets {
                        if active_transfer_peers.contains(&pid)
                            || iroh_peer_recently_active(
                                &iroh_peer_liveness_net,
                                &pid,
                                tokio::time::Duration::from_secs(30),
                            )
                        {
                            continue;
                        }
                        let send_result = tokio::time::timeout(
                            tokio::time::Duration::from_secs(8),
                            iroh_network.send_request(&pid, &request),
                        )
                        .await;
                        match send_result {
                            Ok(Ok(_)) => {
                                mark_iroh_peer_active(&iroh_peer_liveness_net, &pid);
                            }
                            Ok(Err(e)) => {
                                let failures =
                                    note_iroh_keepalive_failure(&iroh_peer_liveness_net, &pid);
                                tracing::debug!(
                                    peer = %pid,
                                    %e,
                                    failures,
                                    "iroh keepalive failed"
                                );
                                if failures >= 18 {
                                    stale_peers.push(pid);
                                }
                            }
                            Err(_) => {
                                let failures =
                                    note_iroh_keepalive_failure(&iroh_peer_liveness_net, &pid);
                                tracing::debug!(
                                    peer = %pid,
                                    failures,
                                    "iroh keepalive timeout"
                                );
                                if failures >= 18 {
                                    stale_peers.push(pid);
                                }
                            }
                        }
                    }
                    for pid in stale_peers {
                        let peer_info = peers_net
                            .get(&pid.to_string())
                            .map(|peer| (peer.did.clone(), peer.name.clone()));
                        let Some((did, _name)) = peer_info.filter(|(did, _)| !did.is_empty()) else {
                            continue;
                        };
                        let known = {
                            let ps = peer_store_net.lock().await;
                            ps.get(&did).cloned()
                        };
                        if let Some(kp) = known.filter(|kp| kp.iroh_endpoint_addr.is_some()) {
                            queue_iroh_reconnect(&mut pending_iroh_reconnects, &kp, true);
                        }
                    }
                }

                _ = reconnect_ticker.tick() => {
                    let due_reconnects = next_due_iroh_reconnect_dids(
                        &pending_iroh_reconnects,
                        tokio::time::Instant::now(),
                        IROH_RECONNECTS_PER_TICK_BUDGET,
                    );
                    if due_reconnects.is_empty() {
                        continue;
                    }
                    for did in due_reconnects {
                        drive_due_iroh_reconnect(
                            did,
                            &mut iroh_network,
                            &peers_net,
                            &peer_store_net,
                            &manual_disconnect_dids_net,
                            &mut pending_iroh_reconnects,
                            &mut pending_iroh_chunk_transfers,
                            &invite_proof_net,
                            &iroh_peer_liveness_net,
                            &iroh_handshake_sync_net,
                            &iroh_authenticated_sessions_net,
                            &mut handshake_sent,
                        )
                        .await;
                        tokio::task::yield_now().await;
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    if GHOST_MODE_ACTIVE.load(Ordering::SeqCst) {
                        eprintln!("\n   \x1b[31m\x1b[1mGHOST: Signal caught — emergency cleanup...\x1b[0m");
                        emergency_ghost_cleanup();
                    }
                    let has_transfer_context = iroh_shutdown_has_transfer_context(
                        &pending_iroh_chunk_transfers,
                        &active_incoming_iroh_transfers_net,
                    );
                    let notice_count = send_iroh_shutdown_disconnect_notices(
                        &iroh_network,
                        &peers_net,
                        &direct_peer_dids_net,
                        &pending_iroh_chunk_transfers,
                        &active_incoming_iroh_transfers_net,
                        &sign_key,
                        &config_net,
                    )
                    .await;
                    await_iroh_shutdown_notice_grace(
                        notice_count,
                        has_transfer_context,
                    )
                    .await;
                    iroh_network.shutdown().await;
                    break;
                }

                Some(cmd) = cmd_rx.recv() => {
                    if let NetworkCommand::Shutdown(done) = cmd {
                        let has_transfer_context = iroh_shutdown_has_transfer_context(
                            &pending_iroh_chunk_transfers,
                            &active_incoming_iroh_transfers_net,
                        );
                        let notice_count = send_iroh_shutdown_disconnect_notices(
                            &iroh_network,
                            &peers_net,
                            &direct_peer_dids_net,
                            &pending_iroh_chunk_transfers,
                            &active_incoming_iroh_transfers_net,
                            &sign_key,
                            &config_net,
                        )
                        .await;
                        await_iroh_shutdown_notice_grace(
                            notice_count,
                            has_transfer_context,
                        )
                        .await;
                        iroh_network.shutdown().await;
                        shutdown_done = Some(done);
                        break;
                    }
                    handle_iroh_command(
                        cmd,
                        IrohCommandHandlerState {
                            iroh_network: &mut iroh_network,
                            handshake_sent: &mut handshake_sent,
                            pending_iroh_chunk_transfers: &mut pending_iroh_chunk_transfers,
                            pending_iroh_reconnects: &mut pending_iroh_reconnects,
                        },
                        IrohCommandHandlerShared {
                            agent_data_dir: &agent_data_dir,
                            receive_dir_config_net: &receive_dir_config_net,
                            peers_net: &peers_net,
                            active_incoming_iroh_transfers_net:
                                &active_incoming_iroh_transfers_net,
                            active_chat_target_did_net: &active_chat_target_did_net,
                            peer_store_net: &peer_store_net,
                            config_net: &config_net,
                            sign_key: &sign_key,
                            keypair_net: &keypair_net,
                            audit_net: &audit_net,
                            rbac_net: &rbac_net,
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
                            remote_offline_dids_net: &remote_offline_dids_net,
                            ratchet_mgr_net: &ratchet_mgr_net,
                            pending_hybrid_ratchet_inits_net:
                                &pending_hybrid_ratchet_inits_net,
                            ratchet_init_pub_hex_net: &ratchet_init_pub_hex_net,
                            pending_contact_requests_net: &pending_contact_requests_net,
                            iroh_peer_liveness_net: &iroh_peer_liveness_net,
                            iroh_handshake_sync_net: &iroh_handshake_sync_net,
                            iroh_authenticated_sessions_net:
                                &iroh_authenticated_sessions_net,
                            log_mode_net: &log_mode_net,
                            iroh_config: &iroh_config,
                            no_persistent_artifact_store,
                        },
                    )
                    .await;
                }
            }
        }

        drop(transfer_request_rx);
        drop(iroh_network);
        if let Some(done) = shutdown_done.take() {
            let _ = done.send(());
        }
    });
}

const MAX_IROH_RECONNECT_ATTEMPTS: u32 = 5;
const STARTUP_IROH_RECONNECT_DELAY_SECS: u64 = 1;
const STEADY_IROH_RECONNECT_INTERVAL_SECS: u64 = 30;
const IROH_BACKGROUND_RECONNECT_CONNECT_TIMEOUT_SECS: u64 = 2;
const IROH_RECONNECTS_PER_TICK_BUDGET: usize = 2;
const MAX_IROH_TRANSFER_RECONNECT_WAIT_SECS: u64 = 15 * 60;
const IROH_TRANSFER_SESSION_POLL_INTERVAL_MS: u64 = 250;
const FAST_GROUP_TRANSFER_JANITOR_INTERVAL_SECS: u64 = 10;

async fn has_authenticated_iroh_peer_session(
    iroh_network: &IrohTransport,
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    peer_id: &libp2p::PeerId,
    _did: &str,
) -> bool {
    let Some(stable_id) = iroh_network.current_stable_id(peer_id).await else {
        return false;
    };
    is_authenticated_iroh_session(authenticated_sessions, peer_id, stable_id)
}

async fn has_live_iroh_transport_session(
    iroh_network: &IrohTransport,
    peers: &DashMap<String, PeerInfo>,
    did: &str,
) -> bool {
    let peer_ids: Vec<libp2p::PeerId> = peers
        .iter()
        .filter(|entry| entry.value().did == did)
        .map(|entry| entry.value().peer_id)
        .collect();

    for peer_id in peer_ids {
        if iroh_network.is_connected(&peer_id).await {
            return true;
        }
    }
    false
}

fn has_connected_iroh_transport_session(peers: &DashMap<String, PeerInfo>, did: &str) -> bool {
    peers.iter().any(|entry| entry.value().did == did)
}

fn iroh_transfer_ready(pending: &PendingIrohChunkTransfer, now: tokio::time::Instant) -> bool {
    if pending.awaiting_receiver_accept {
        return pending.approval_poll_after.is_none_or(|t| now >= t);
    }
    pending.retry_after.is_none_or(|t| now >= t)
}

fn park_iroh_transfer_until_authenticated_session(
    pending: &mut PendingIrohChunkTransfer,
    now: tokio::time::Instant,
) {
    let wake_at = now + tokio::time::Duration::from_millis(IROH_TRANSFER_SESSION_POLL_INTERVAL_MS);
    if pending.awaiting_receiver_accept {
        pending.approval_poll_after = Some(wake_at);
    } else {
        pending.retry_after = Some(wake_at);
    }
}

fn park_iroh_transfer_for_control_plane(pending: &mut PendingIrohChunkTransfer) {
    let wake_at = tokio::time::Instant::now()
        + tokio::time::Duration::from_millis(IROH_TRANSFER_CONTROL_PLANE_PARK_MS);
    if pending.awaiting_receiver_accept {
        pending.approval_poll_after = Some(wake_at);
    } else {
        pending.retry_after = Some(wake_at);
    }
}

fn clear_selected_runtime_chat_target(
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    peer_did: &str,
) {
    let mut cleared = false;
    if let Ok(mut target) = active_chat_target_did_net.lock() {
        if target.as_deref() == Some(peer_did) {
            *target = None;
            cleared = true;
        }
    }
    if cleared {
        set_active_prompt_target_label(None);
    }
}

fn rebind_pending_iroh_chunk_transfer_peer(
    pending_iroh_chunk_transfers: &mut HashMap<String, PendingIrohChunkTransfer>,
    peer_did: &str,
    new_peer_id: libp2p::PeerId,
    new_peer_name: &str,
) {
    let new_key = new_peer_id.to_string();
    if let Some(pct) = pending_iroh_chunk_transfers.get_mut(&new_key) {
        if pct.peer_did == peer_did {
            pct.peer_id = new_peer_id;
            pct.peer_name = new_peer_name.to_string();
            pct.retry_after = Some(tokio::time::Instant::now());
            pct.reconnect_wait_secs = 0;
        }
        return;
    }

    let old_key = pending_iroh_chunk_transfers
        .iter()
        .find(|(_, pct)| pct.peer_did == peer_did)
        .map(|(key, _)| key.clone());
    let Some(old_key) = old_key else {
        return;
    };

    if let Some(mut pct) = pending_iroh_chunk_transfers.remove(&old_key) {
        pct.peer_id = new_peer_id;
        pct.peer_name = new_peer_name.to_string();
        pct.retry_after = Some(tokio::time::Instant::now());
        pct.reconnect_wait_secs = 0;
        pending_iroh_chunk_transfers.insert(new_key, pct);
    }
}

pub(crate) fn reset_iroh_transfer_for_reapproval(pending: &mut PendingIrohChunkTransfer) {
    pending.awaiting_receiver_accept = true;
    pending.awaiting_started_at = tokio::time::Instant::now();
    pending.approval_poll_after = None;
    pending.needs_reinit = true;
}

pub(crate) fn iroh_transfer_restart_already_pending(pending: &PendingIrohChunkTransfer) -> bool {
    pending.awaiting_receiver_accept && pending.needs_reinit
}

fn apply_transfer_resume_snapshot(
    session: &mut chunked_transfer::TransferSession,
    received_chunks: &[usize],
) -> usize {
    for chunk in &mut session.chunks {
        chunk.sent = false;
        chunk.acknowledged = false;
    }
    for &index in received_chunks {
        if let Some(chunk) = session.chunks.get_mut(index) {
            chunk.sent = true;
            chunk.acknowledged = true;
        }
    }
    session
        .chunks
        .iter()
        .find(|chunk| !chunk.acknowledged)
        .map(|chunk| chunk.index)
        .unwrap_or(session.total_chunks)
}

fn next_iroh_transfer_retry_delay(waited_secs: u64) -> tokio::time::Duration {
    let secs = match waited_secs {
        0 => 1,
        1..=2 => 2,
        3..=6 => 4,
        7..=14 => 8,
        _ => 15,
    };
    tokio::time::Duration::from_secs(secs)
}

async fn schedule_iroh_chunk_transfer_retry(
    pending: &mut PendingIrohChunkTransfer,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    iroh_peer_liveness_net: &Arc<DashMap<String, IrohPeerLiveness>>,
    iroh_handshake_sync_net: &Arc<DashMap<String, IrohHandshakeSyncState>>,
    iroh_authenticated_sessions_net: &Arc<IrohAuthenticatedSessionMap>,
    handshake_sent: &mut IrohHandshakeTracker,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    remote_offline_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
    agent_name: &str,
    phase: &str,
) -> bool {
    let manually_disconnected = {
        let manual = manual_disconnect_dids_net.lock().await;
        manual.contains(&pending.peer_did)
    };
    if manually_disconnected {
        return false;
    }
    let remotely_offline = {
        let offline = remote_offline_dids_net.lock().await;
        offline.contains(&pending.peer_did)
    };

    let known_peer = {
        let ps = peer_store_net.lock().await;
        ps.get(&pending.peer_did).cloned()
    };
    let Some(kp) = known_peer.filter(|kp| kp.iroh_endpoint_addr.is_some()) else {
        return false;
    };

    let stale_peer_id = pending.peer_id;
    if remotely_offline {
        peers_net.remove(&stale_peer_id.to_string());
    } else {
        peers_net.insert(
            stale_peer_id.to_string(),
            reconnecting_iroh_placeholder(stale_peer_id, &kp),
        );
    }
    invite_proof_net.remove(&stale_peer_id.to_string());
    iroh_peer_liveness_net.remove(&stale_peer_id.to_string());
    clear_iroh_handshake_tracking(handshake_sent, &stale_peer_id);
    clear_iroh_handshake_sync(iroh_handshake_sync_net, &stale_peer_id);
    clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &stale_peer_id);
    clear_selected_runtime_chat_target(active_chat_target_did_net, &pending.peer_did);

    let first_pause_notice = pending.reconnect_wait_secs == 0;
    let backoff = next_iroh_transfer_retry_delay(pending.reconnect_wait_secs);
    pending.reconnect_wait_secs = pending
        .reconnect_wait_secs
        .saturating_add(backoff.as_secs());
    if pending.reconnect_wait_secs > MAX_IROH_TRANSFER_RECONNECT_WAIT_SECS {
        return false;
    }

    pending.retry_after = Some(tokio::time::Instant::now() + backoff);
    if first_pause_notice {
        print_async_notice(
            agent_name,
            format!(
                "   {} {} paused during {} — {}",
                "Transfer:".yellow().bold(),
                pending.peer_name.cyan(),
                phase.dimmed(),
                if remotely_offline {
                    "peer went offline".dimmed()
                } else {
                    "reconnecting".dimmed()
                },
            ),
        );
    }
    queue_iroh_reconnect(pending_iroh_reconnects, &kp, true);
    true
}

fn finalize_successful_iroh_reconnect(
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    iroh_peer_liveness_net: &Arc<DashMap<String, IrohPeerLiveness>>,
    iroh_handshake_sync_net: &Arc<DashMap<String, IrohHandshakeSyncState>>,
    iroh_authenticated_sessions_net: &Arc<IrohAuthenticatedSessionMap>,
    handshake_sent: &mut IrohHandshakeTracker,
    pending_iroh_chunk_transfers: &mut HashMap<String, PendingIrohChunkTransfer>,
    pending: &PendingIrohReconnect,
    pid: libp2p::PeerId,
    sanitized_iroh_json: &str,
) {
    let stale_peer_ids: Vec<libp2p::PeerId> = peers_net
        .iter()
        .filter(|entry| entry.value().did == pending.did && entry.value().peer_id != pid)
        .map(|entry| entry.value().peer_id)
        .collect();
    for stale_peer_id in stale_peer_ids {
        peers_net.remove(&stale_peer_id.to_string());
        invite_proof_net.remove(&stale_peer_id.to_string());
        iroh_peer_liveness_net.remove(&stale_peer_id.to_string());
        clear_iroh_handshake_tracking(handshake_sent, &stale_peer_id);
        clear_iroh_handshake_sync(iroh_handshake_sync_net, &stale_peer_id);
        clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &stale_peer_id);
    }

    rebind_pending_iroh_chunk_transfer_peer(
        pending_iroh_chunk_transfers,
        &pending.did,
        pid,
        &pending.name,
    );
    mark_iroh_peer_active(iroh_peer_liveness_net, &pid);
    peers_net.insert(
        pid.to_string(),
        PeerInfo {
            peer_id: pid,
            did: pending.did.clone(),
            name: pending.name.clone(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(sanitized_iroh_json.to_string()),
            onion_port: 9090,
            x25519_public_key: pending
                .encryption_public_key_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&b);
                        Some(out)
                    } else {
                        None
                    }
                }),
            kyber_public_key: pending
                .kyber_public_key_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok()),
            verifying_key: pending
                .verifying_key_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&b);
                        Some(out)
                    } else {
                        None
                    }
                }),
            aegis_supported: false,
            ratchet_dh_public: None,
        },
    );
    clear_iroh_handshake_tracking(handshake_sent, &pid);
    clear_iroh_handshake_sync(iroh_handshake_sync_net, &pid);
    clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &pid);
}

async fn queue_post_transfer_reconnect_sweep(
    iroh_network: &IrohTransport,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    _remote_offline_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
) {
    let reconnect_candidates: Vec<KnownPeer> = {
        let ps = peer_store_net.lock().await;
        ps.all_peers()
            .into_iter()
            .filter(|kp| kp.iroh_endpoint_addr.is_some())
            .cloned()
            .collect()
    };

    let manually_disconnected: HashSet<String> = {
        let manual = manual_disconnect_dids_net.lock().await;
        manual.clone()
    };
    for kp in reconnect_candidates {
        let already_connected =
            has_live_iroh_transport_session(iroh_network, peers_net, &kp.did).await;
        if already_connected || manually_disconnected.contains(&kp.did) {
            continue;
        }
        queue_iroh_reconnect(pending_iroh_reconnects, &kp, true);
        tracing::debug!(
            peer = %kp.name,
            did = %kp.did,
            "post-transfer reconnect sweep — queued"
        );
    }
}

async fn drive_due_iroh_reconnect(
    did: String,
    iroh_network: &mut IrohTransport,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
    pending_iroh_chunk_transfers: &mut HashMap<String, PendingIrohChunkTransfer>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    iroh_peer_liveness_net: &Arc<DashMap<String, IrohPeerLiveness>>,
    iroh_handshake_sync_net: &Arc<DashMap<String, IrohHandshakeSyncState>>,
    iroh_authenticated_sessions_net: &Arc<IrohAuthenticatedSessionMap>,
    handshake_sent: &mut IrohHandshakeTracker,
) {
    let manually_disconnected = {
        let manual = manual_disconnect_dids_net.lock().await;
        manual.contains(&did)
    };
    if manually_disconnected {
        pending_iroh_reconnects.remove(&did);
        return;
    }

    let mut pending = match pending_iroh_reconnects.remove(&did) {
        Some(p) => p,
        None => return,
    };

    let already_connected =
        has_live_iroh_transport_session(iroh_network, peers_net, &pending.did).await;
    if already_connected && !pending.force_replace {
        return;
    }

    let sanitized_iroh_json =
        match crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json(
            &pending.iroh_endpoint_addr_json,
        ) {
            Ok(sanitized) => sanitized,
            Err(e) => {
                tracing::debug!(
                    peer = %pending.name,
                    %e,
                    "iroh reconnect skipped — endpoint payload has no relay-only route"
                );
                return;
            }
        };
    let endpoint_addr = match serde_json::from_str::<iroh::EndpointAddr>(&sanitized_iroh_json) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::debug!(
                peer = %pending.name,
                %e,
                "iroh reconnect skipped — sanitized endpoint payload is invalid"
            );
            return;
        }
    };
    if endpoint_addr.addrs.is_empty() {
        tracing::debug!(
            peer = %pending.name,
            "iroh reconnect skipped — no usable relay-only path"
        );
        return;
    }

    let keep_retrying_forever = {
        let ps = peer_store_net.lock().await;
        ps.get(&pending.did)
            .is_some_and(|known| known.auto_reconnect)
    };

    pending.attempts = pending.attempts.saturating_add(1);
    if should_give_up_iroh_reconnect(pending.attempts, keep_retrying_forever) {
        tracing::debug!(
            peer = %pending.name,
            did = %pending.did,
            attempts = pending.attempts,
            "iroh reconnect gave up — peer unreachable"
        );
        return;
    }

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(IROH_BACKGROUND_RECONNECT_CONNECT_TIMEOUT_SECS),
        iroh_network.connect(endpoint_addr),
    )
    .await
    {
        Ok(Ok(crate::network::iroh_transport::IrohConnectOutcome::Established(pid))) => {
            finalize_successful_iroh_reconnect(
                peers_net,
                invite_proof_net,
                iroh_peer_liveness_net,
                iroh_handshake_sync_net,
                iroh_authenticated_sessions_net,
                handshake_sent,
                pending_iroh_chunk_transfers,
                &pending,
                pid,
                &sanitized_iroh_json,
            );
            tracing::info!(
                peer = %pending.name,
                did = %pending.did,
                "iroh transport reconnected; awaiting authenticated handshake refresh"
            );
        }
        Ok(Ok(crate::network::iroh_transport::IrohConnectOutcome::ReusedExisting(pid))) => {
            tracing::debug!(
                peer = %pending.name,
                did = %pending.did,
                peer_id = %pid,
                "iroh reconnect reused existing preferred live session"
            );
        }
        Ok(Err(e)) => {
            let backoff_secs =
                next_iroh_reconnect_delay(pending.attempts, keep_retrying_forever).as_secs();
            pending.next_attempt_at =
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(backoff_secs);
            tracing::debug!(
                peer = %pending.name,
                did = %pending.did,
                backoff_secs,
                %e,
                "iroh reconnect failed — will retry"
            );
            pending_iroh_reconnects.insert(did, pending);
        }
        Err(_) => {
            let backoff_secs =
                next_iroh_reconnect_delay(pending.attempts, keep_retrying_forever).as_secs();
            pending.next_attempt_at =
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(backoff_secs);
            tracing::debug!(
                peer = %pending.name,
                did = %pending.did,
                backoff_secs,
                timeout_secs = IROH_BACKGROUND_RECONNECT_CONNECT_TIMEOUT_SECS,
                "iroh reconnect timed out — will retry"
            );
            pending_iroh_reconnects.insert(did, pending);
        }
    }
}

fn seed_initial_iroh_reconnects(
    pending: &mut HashMap<String, PendingIrohReconnect>,
    initial: &[KnownPeer],
) {
    for known in initial {
        if known.iroh_endpoint_addr.is_some() {
            queue_iroh_reconnect(pending, known, false);
            if let Some(entry) = pending.get_mut(&known.did) {
                entry.next_attempt_at =
                    tokio::time::Instant::now() + startup_iroh_reconnect_delay();
            }
        }
    }
}

fn next_due_iroh_reconnect_dids(
    pending: &HashMap<String, PendingIrohReconnect>,
    now: tokio::time::Instant,
    limit: usize,
) -> Vec<String> {
    let mut ready: Vec<(&String, &PendingIrohReconnect)> = pending
        .iter()
        .filter(|(_, pending)| pending.next_attempt_at <= now)
        .collect();
    ready.sort_by_key(|(did, pending)| (pending.next_attempt_at, (*did).clone()));
    ready
        .into_iter()
        .take(limit)
        .map(|(did, _)| did.clone())
        .collect()
}

fn next_due_iroh_reconnect_did(
    pending: &HashMap<String, PendingIrohReconnect>,
    now: tokio::time::Instant,
) -> Option<String> {
    next_due_iroh_reconnect_dids(pending, now, 1)
        .into_iter()
        .next()
}

fn should_give_up_iroh_reconnect(attempts: u32, keep_retrying_forever: bool) -> bool {
    attempts > MAX_IROH_RECONNECT_ATTEMPTS && !keep_retrying_forever
}

fn startup_iroh_reconnect_delay() -> tokio::time::Duration {
    tokio::time::Duration::from_secs(STARTUP_IROH_RECONNECT_DELAY_SECS)
}

fn next_iroh_reconnect_delay(attempts: u32, keep_retrying_forever: bool) -> tokio::time::Duration {
    if keep_retrying_forever && attempts > MAX_IROH_RECONNECT_ATTEMPTS {
        return tokio::time::Duration::from_secs(STEADY_IROH_RECONNECT_INTERVAL_SECS);
    }

    let exp = attempts.saturating_sub(1).min(5);
    tokio::time::Duration::from_secs(2u64.pow(exp).min(STEADY_IROH_RECONNECT_INTERVAL_SECS))
}

async fn launch_due_fast_group_transfers(
    group_mailboxes_net: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    iroh_network: &mut IrohTransport,
    pending_fast_group_iroh_transfers: &mut HashMap<String, PendingFastGroupIrohTransfer>,
    active_fast_group_iroh_downloads: &mut HashMap<String, ActiveFastGroupIrohDownload>,
) {
    let now = chrono::Utc::now().timestamp() as u64;
    let launches = {
        let mut registry = group_mailboxes_net.lock().await;
        registry.due_pending_fast_file_grants(now)
    };

    for launch in launches {
        let runtime_transfer_key = fast_group_runtime_transfer_key(&launch.secret.ticket_id);
        if pending_fast_group_iroh_transfers.contains_key(&runtime_transfer_key)
            || active_fast_group_iroh_downloads.contains_key(&runtime_transfer_key)
        {
            continue;
        }

        if !launch.secret.relay_only {
            tracing::warn!(
                transfer_id = %redacted_log_marker("transfer", &launch.transfer_id),
                "Fast group transfer launch rejected because relay_only=false"
            );
            continue;
        }

        let endpoint_addr =
            match serde_json::from_str::<iroh::EndpointAddr>(&launch.secret.endpoint_addr_json) {
                Ok(endpoint_addr) => endpoint_addr,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", &launch.transfer_id),
                        group_id = %redacted_log_marker("group", &launch.group_id),
                        %error,
                        "Fast group transfer launch skipped because endpoint payload is invalid"
                    );
                    continue;
                }
            };

        if let Err(error) = iroh_network
            .connect_transfer(&runtime_transfer_key, endpoint_addr)
            .await
        {
            tracing::debug!(
                transfer_id = %redacted_log_marker("transfer", &launch.transfer_id),
                group_id = %redacted_log_marker("group", &launch.group_id),
                %error,
                "Fast group transfer connect failed; grant remains pending"
            );
            continue;
        }

        let open_request = match build_fast_transfer_open_request(
            keypair_net,
            config_net.security.message_ttl_ms.max(30_000),
            launch.transfer_id.clone(),
            launch.group_id.clone(),
            launch.secret.recipient_did.clone(),
            hex::encode(keypair_net.verifying_key.as_bytes()),
            launch.secret.ticket_id.clone(),
        ) {
            Ok(open_request) => open_request,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &launch.transfer_id),
                    group_id = %redacted_log_marker("group", &launch.group_id),
                    %error,
                    "Failed to build fast transfer open request"
                );
                iroh_network
                    .disconnect_transfer(&runtime_transfer_key)
                    .await;
                continue;
            }
        };

        if let Err(error) = iroh_network
            .send_transfer_request(&runtime_transfer_key, &open_request)
            .await
        {
            tracing::debug!(
                transfer_id = %redacted_log_marker("transfer", &launch.transfer_id),
                group_id = %redacted_log_marker("group", &launch.group_id),
                %error,
                "Fast transfer open request failed; grant remains pending"
            );
            iroh_network
                .disconnect_transfer(&runtime_transfer_key)
                .await;
            continue;
        }

        let (group_name, sender_name) = {
            let registry = group_mailboxes_net.lock().await;
            let session = registry.get_cloned(&launch.group_id);
            let sender_name = registry
                .known_member_profile(&launch.group_id, &launch.sender_member_id)
                .map(|profile| profile.display_name)
                .unwrap_or_else(|| launch.sender_member_id.clone());
            (session.and_then(|session| session.group_name), sender_name)
        };

        {
            let mut registry = group_mailboxes_net.lock().await;
            registry
                .mark_fast_file_grant_launched(&launch.transfer_id, &launch.secret.recipient_did);
        }

        active_fast_group_iroh_downloads.insert(
            runtime_transfer_key.clone(),
            ActiveFastGroupIrohDownload {
                runtime_transfer_key,
                transfer_id: launch.transfer_id.clone(),
                group_id: launch.group_id.clone(),
                group_name,
                sender_member_id: launch.sender_member_id.clone(),
                sender_name: sender_name.clone(),
                sender_verifying_key_hex: launch.sender_verifying_key_hex.clone(),
                mailbox_transfer_id: launch.secret.mailbox_transfer_id.clone(),
                recv: None,
            },
        );

        print_async_notice(
            &config_net.agent.name,
            format!(
                "   {} {} from {} over relay-only fast path",
                "Fast download:".green().bold(),
                launch.secret.transfer_id[..std::cmp::min(16, launch.secret.transfer_id.len())]
                    .dimmed(),
                sender_name.cyan(),
            ),
        );
    }
}

async fn handle_fast_group_transfer_request(
    transfer_request: Option<crate::network::iroh_transport::IrohTransferIncomingRequest>,
    group_mailboxes_net: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    receive_dir_config_net: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode_net: &LogMode,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    iroh_network: &mut IrohTransport,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    remote_offline_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
    pending_fast_group_iroh_transfers: &mut HashMap<String, PendingFastGroupIrohTransfer>,
    active_fast_group_iroh_downloads: &mut HashMap<String, ActiveFastGroupIrohDownload>,
) {
    let Some(transfer_request) = transfer_request else {
        return;
    };
    match (
        &transfer_request.transfer_id,
        transfer_request.request.msg_type.clone(),
    ) {
        (None, MessageKind::FastTransferOpen) => {
            let payload = match bincode::deserialize::<
                crate::network::protocol::FastTransferOpenPayload,
            >(&transfer_request.request.payload)
            {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(stable_id = transfer_request.stable_id, %error, "FastTransferOpen decode failed");
                    return;
                }
            };
            if let Err(error) = verify_agent_request_signature_with_verifying_key_hex(
                &transfer_request.request,
                &payload.recipient_verifying_key_hex,
                Some(payload.recipient_did.as_str()),
            ) {
                tracing::warn!(
                    stable_id = transfer_request.stable_id,
                    transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                    %error,
                    "FastTransferOpen outer signature rejected"
                );
                return;
            }
            let recipient_did =
                match verify_fast_transfer_open_payload(&payload, &transfer_request.request) {
                    Ok(recipient_did) => recipient_did,
                    Err(error) => {
                        tracing::warn!(
                            stable_id = transfer_request.stable_id,
                            transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                            %error,
                            "FastTransferOpen rejected"
                        );
                        return;
                    }
                };
            let runtime_transfer_key = fast_group_runtime_transfer_key(&payload.ticket_id);
            let now = chrono::Utc::now().timestamp() as u64;
            let (staged, secret, recipient_profile, recipient_name) = {
                let mut registry = group_mailboxes_net.lock().await;
                let Some((staged, secret)) = registry.consume_fast_transfer_open_authorization(
                    &payload.transfer_id,
                    &recipient_did,
                    now,
                ) else {
                    tracing::warn!(
                        stable_id = transfer_request.stable_id,
                        transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                        "FastTransferOpen has no matching active authorization"
                    );
                    return;
                };
                if secret.ticket_id != payload.ticket_id || secret.group_id != payload.group_id {
                    tracing::warn!(
                        stable_id = transfer_request.stable_id,
                        transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                        "FastTransferOpen ticket/group mismatch"
                    );
                    return;
                }
                let Some(recipient_profile) =
                    registry.known_member_profile(&payload.group_id, &recipient_did)
                else {
                    tracing::warn!(
                        stable_id = transfer_request.stable_id,
                        transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                        recipient = %redacted_log_marker("member", &recipient_did),
                        "FastTransferOpen recipient profile is unknown"
                    );
                    return;
                };
                let recipient_name = recipient_profile.display_name.clone();
                (staged, secret, recipient_profile, recipient_name)
            };

            let recipient_x25519 = match parse_x25519_public_key_hex_runtime(
                &recipient_profile.encryption_public_key_hex,
            ) {
                Ok(key) => key,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                        %error,
                        "FastTransferOpen recipient X25519 key invalid"
                    );
                    return;
                }
            };
            let recipient_kyber = match recipient_profile.kyber_public_key_hex.as_deref() {
                Some(kyber_hex) => match parse_kyber_public_key_hex_runtime(kyber_hex) {
                    Ok(key) => key,
                    Err(error) => {
                        tracing::warn!(
                            transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                            %error,
                            "FastTransferOpen recipient Kyber key invalid"
                        );
                        return;
                    }
                },
                None => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                        "FastTransferOpen recipient missing Kyber key"
                    );
                    return;
                }
            };

            if let Err(error) = iroh_network
                .bind_incoming_transfer_connection(
                    transfer_request.stable_id,
                    &runtime_transfer_key,
                )
                .await
            {
                tracing::warn!(
                    stable_id = transfer_request.stable_id,
                    transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                    %error,
                    "FastTransferOpen binding failed"
                );
                return;
            }

            pending_fast_group_iroh_transfers.insert(
                runtime_transfer_key.clone(),
                PendingFastGroupIrohTransfer {
                    runtime_transfer_key,
                    transfer_id: payload.transfer_id.clone(),
                    group_id: payload.group_id.clone(),
                    group_name: staged.group_name.clone(),
                    sender_member_id: staged.sender_member_id.clone(),
                    recipient_member_id: recipient_did.clone(),
                    recipient_name,
                    session: staged.fast_session.clone(),
                    chunk_source: ChunkSource::SharedTempFile(staged.packed_path.clone()),
                    init_sent: false,
                    next_chunk: 0,
                    x25519_pk: recipient_x25519,
                    kyber_pk: recipient_kyber,
                    ttl: config_net.security.message_ttl_ms.max(30_000),
                },
            );
            {
                let mut registry = group_mailboxes_net.lock().await;
                registry.mark_staged_fast_file_transfer_active(&payload.transfer_id);
            }
            tracing::info!(
                transfer_id = %redacted_log_marker("transfer", &payload.transfer_id),
                group_id = %redacted_log_marker("group", &payload.group_id),
                recipient = %redacted_log_marker("member", &recipient_did),
                "Authorized transfer-only fast group download"
            );
            let _ = secret;
        }
        (Some(transfer_id), MessageKind::ChunkTransferInit) => {
            let payload = match bincode::deserialize::<
                crate::network::protocol::ChunkTransferInitPayload,
            >(&transfer_request.request.payload)
            {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        %error,
                        "Fast transfer init decode failed"
                    );
                    return;
                }
            };
            let Some(download) = active_fast_group_iroh_downloads.get_mut(transfer_id) else {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer init received for unknown download"
                );
                return;
            };
            if let Err(error) = verify_agent_request_signature_with_verifying_key_hex(
                &transfer_request.request,
                &payload.sender_verifying_key_hex,
                Some(download.sender_member_id.as_str()),
            ) {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    %error,
                    "Fast transfer init outer signature rejected"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }
            let sender_did = match derive_did_from_verifying_key_hex_runtime(
                &payload.sender_verifying_key_hex,
            ) {
                Ok(sender_did) => sender_did,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        %error,
                        "Fast transfer init sender DID derivation failed"
                    );
                    active_fast_group_iroh_downloads.remove(transfer_id);
                    iroh_network.disconnect_transfer(transfer_id).await;
                    return;
                }
            };
            if sender_did != download.sender_member_id
                || transfer_request.request.sender_did != download.sender_member_id
                || payload.session_id != download.transfer_id
            {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer init sender/session mismatch"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }

            let recv = match ChunkedReceiveSession::new(
                payload,
                download.sender_member_id.clone(),
                download.sender_name.clone(),
            ) {
                Ok(recv) => recv,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        %error,
                        "Fast transfer receive session creation failed"
                    );
                    active_fast_group_iroh_downloads.remove(transfer_id);
                    iroh_network.disconnect_transfer(transfer_id).await;
                    return;
                }
            };
            {
                let mut registry = group_mailboxes_net.lock().await;
                let _ =
                    registry.remove_chunk_download_by_transfer_id(&download.mailbox_transfer_id);
            }
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {} from {}",
                    "Fast transfer started:".green().bold(),
                    download.transfer_id[..std::cmp::min(16, download.transfer_id.len())].dimmed(),
                    download.sender_name.cyan(),
                ),
            );
            download.recv = Some(recv);
        }
        (Some(transfer_id), MessageKind::ChunkData) => {
            let payload = match bincode::deserialize::<crate::network::protocol::ChunkDataPayload>(
                &transfer_request.request.payload,
            ) {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        %error,
                        "Fast transfer chunk decode failed"
                    );
                    return;
                }
            };
            let Some(download) = active_fast_group_iroh_downloads.get_mut(transfer_id) else {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer chunk received for unknown download"
                );
                return;
            };
            if transfer_request.request.sender_did != download.sender_member_id {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer chunk sender DID mismatch"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }
            if let Err(error) = verify_agent_request_signature_with_verifying_key_hex(
                &transfer_request.request,
                &download.sender_verifying_key_hex,
                Some(download.sender_member_id.as_str()),
            ) {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    %error,
                    "Fast transfer chunk outer signature rejected"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }

            let actual_data = if payload.actual_encrypted_size > 0 {
                chunked_transfer::strip_padding(
                    &payload.encrypted_data,
                    payload.actual_encrypted_size,
                )
                .to_vec()
            } else {
                payload.encrypted_data.clone()
            };
            let encrypted_chunk = chunked_transfer::EncryptedChunk {
                session_id: payload.session_id.clone(),
                chunk_index: payload.chunk_index,
                total_chunks: payload.total_chunks,
                encrypted_data: actual_data,
                key_envelope: payload.key_envelope.clone(),
                signature: payload.signature.clone(),
                merkle_proof: payload.merkle_proof.clone(),
                chunk_sha256: payload.chunk_sha256,
            };

            let Some(recv) = download.recv.as_mut() else {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer chunk arrived before init"
                );
                return;
            };

            if payload.chunk_index == 0 {
                if let (Some(sealed_data), Some(sealed_env)) = (
                    payload.sealed_metadata.as_deref(),
                    payload.sealed_metadata_key_envelope.as_deref(),
                ) {
                    match chunked_transfer::decrypt_sealed_metadata(
                        sealed_data,
                        sealed_env,
                        keypair_net,
                    ) {
                        Ok(meta) => recv.apply_sealed_metadata(meta),
                        Err(error) => {
                            tracing::warn!(
                                transfer_id = %redacted_log_marker("transfer", transfer_id),
                                %error,
                                "Fast transfer sealed metadata decrypt failed"
                            );
                        }
                    }
                }
            }

            let decrypted = match chunked_transfer::receive_chunk(
                keypair_net,
                &encrypted_chunk,
                &recv.init.merkle_root,
                &recv.init.sender_verifying_key_hex,
            ) {
                Ok(decrypted) => decrypted,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        chunk = payload.chunk_index,
                        %error,
                        "Fast transfer chunk verify failed"
                    );
                    active_fast_group_iroh_downloads.remove(transfer_id);
                    iroh_network.disconnect_transfer(transfer_id).await;
                    return;
                }
            };

            if let Err(error) = recv.store_chunk(payload.chunk_index, decrypted) {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    chunk = payload.chunk_index,
                    %error,
                    "Fast transfer chunk store failed"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }

            let total = recv.init.total_chunks;
            let print_interval = std::cmp::max(1, total / 50);
            if recv.received_count == 1
                || recv.received_count % print_interval == 0
                || recv.received_count == total
            {
                let filename = if recv.init.filename.trim().is_empty() {
                    None
                } else {
                    Some(recv.init.filename.as_str())
                };
                let transferred_bytes = std::cmp::min(
                    recv.received_count as u64 * recv.init.chunk_size as u64,
                    recv.init.total_size,
                );
                let received_mb =
                    (recv.received_count as f64 * recv.init.chunk_size as f64) / (1024.0 * 1024.0);
                let total_mb = recv.init.total_size as f64 / (1024.0 * 1024.0);
                let pct_done = (recv.received_count as f64 / total as f64 * 100.0) as u32;
                emit_transfer_progress_event_with_group(
                    "incoming_progress",
                    "group_mailbox",
                    Some(&download.sender_member_id),
                    Some(&download.sender_name),
                    Some(&download.transfer_id),
                    filename,
                    recv.received_count,
                    total,
                    transferred_bytes,
                    recv.init.total_size,
                    Some(&download.group_id),
                    download.group_name.as_deref(),
                );
                print_async_progress_notice(format!(
                    "   {} [{}/{}] {:.1}/{:.1} MB ({}%)",
                    "Fast receiving:".yellow(),
                    recv.received_count,
                    total,
                    received_mb,
                    total_mb,
                    pct_done,
                ));
            }

            if recv.is_complete() {
                finalize_active_fast_group_download(
                    transfer_id,
                    active_fast_group_iroh_downloads,
                    group_mailboxes_net,
                    receive_dir_config_net,
                    log_mode_net,
                    config_net,
                    iroh_network,
                    peers_net,
                    peer_store_net,
                    manual_disconnect_dids_net,
                    remote_offline_dids_net,
                    pending_iroh_reconnects,
                )
                .await;
            }
        }
        (Some(transfer_id), MessageKind::TransferComplete) => {
            let payload = match bincode::deserialize::<
                crate::network::protocol::TransferCompletePayload,
            >(&transfer_request.request.payload)
            {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", transfer_id),
                        %error,
                        "Fast transfer complete decode failed"
                    );
                    return;
                }
            };
            let Some(download) = active_fast_group_iroh_downloads.get_mut(transfer_id) else {
                return;
            };
            if transfer_request.request.sender_did != download.sender_member_id
                || payload.session_id != download.transfer_id
            {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", transfer_id),
                    "Fast transfer complete sender/session mismatch"
                );
                active_fast_group_iroh_downloads.remove(transfer_id);
                iroh_network.disconnect_transfer(transfer_id).await;
                return;
            }
            if let Some(recv) = download.recv.as_mut() {
                recv.transfer_complete_received = true;
                if recv.is_complete() {
                    finalize_active_fast_group_download(
                        transfer_id,
                        active_fast_group_iroh_downloads,
                        group_mailboxes_net,
                        receive_dir_config_net,
                        log_mode_net,
                        config_net,
                        iroh_network,
                        peers_net,
                        peer_store_net,
                        manual_disconnect_dids_net,
                        remote_offline_dids_net,
                        pending_iroh_reconnects,
                    )
                    .await;
                }
            }
        }
        _ => {}
    }
}

async fn drive_fast_group_transfer_once(
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    group_mailboxes_net: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    iroh_network: &mut IrohTransport,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    remote_offline_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
    active_fast_group_iroh_downloads: &mut HashMap<String, ActiveFastGroupIrohDownload>,
    pending: &mut PendingFastGroupIrohTransfer,
) -> bool {
    if !pending.init_sent {
        let (init_payload, _) =
            chunked_transfer::build_sealed_init_payload(&pending.session, keypair_net);
        let init_bytes = match bincode::serialize(&init_payload) {
            Ok(init_bytes) => init_bytes,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                    %error,
                    "Fast transfer init encode failed"
                );
                return false;
            }
        };
        let init_request = match chunked_transfer::wrap_chunk_request(
            keypair_net,
            MessageKind::ChunkTransferInit,
            init_bytes,
            pending.ttl,
        ) {
            Ok(init_request) => init_request,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                    %error,
                    "Fast transfer init request build failed"
                );
                return false;
            }
        };
        if let Err(error) = iroh_network
            .send_transfer_request(&pending.runtime_transfer_key, &init_request)
            .await
        {
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {} fast relay path interrupted before init completed; receiver must /accept again",
                    "Fast transfer paused:".yellow().bold(),
                    pending.recipient_name.cyan(),
                ),
            );
            tracing::debug!(
                transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                group_id = %redacted_log_marker("group", &pending.group_id),
                %error,
                "Fast transfer init send failed"
            );
            iroh_network
                .disconnect_transfer(&pending.runtime_transfer_key)
                .await;
            queue_post_transfer_reconnect_sweep(
                iroh_network,
                peer_store_net,
                peers_net,
                manual_disconnect_dids_net,
                remote_offline_dids_net,
                pending_iroh_reconnects,
            )
            .await;
            return false;
        }
        pending.init_sent = true;
        print_async_notice(
            &config_net.agent.name,
            format!(
                "   {} {} -> {} [{}]",
                "Fast transfer init:".green().bold(),
                pending
                    .group_name
                    .clone()
                    .unwrap_or_else(|| pending.group_id.clone())
                    .cyan(),
                pending.recipient_name.cyan(),
                pending.transfer_id[..std::cmp::min(16, pending.transfer_id.len())].dimmed(),
            ),
        );
        return true;
    }

    if pending.next_chunk < pending.session.total_chunks {
        let chunk_index = pending.next_chunk;
        let chunk_data = match pending
            .chunk_source
            .read_chunk(&pending.session, chunk_index)
        {
            Ok(chunk_data) => chunk_data,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                    chunk = chunk_index,
                    %error,
                    "Fast transfer chunk read failed"
                );
                return false;
            }
        };
        let (encrypted_chunk, padded_data, actual_size) =
            match chunked_transfer::encrypt_chunk_padded(
                &pending.session,
                chunk_index,
                &chunk_data,
                keypair_net,
                &pending.x25519_pk,
                Some(pending.kyber_pk.as_slice()),
            ) {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                        chunk = chunk_index,
                        %error,
                        "Fast transfer chunk encrypt failed"
                    );
                    return false;
                }
            };
        let mut chunk_payload = chunked_transfer::build_chunk_payload_padded(
            &encrypted_chunk,
            padded_data,
            actual_size,
        );
        if chunk_index == 0 {
            let (_, sealed_meta) =
                chunked_transfer::build_sealed_init_payload(&pending.session, keypair_net);
            if let Ok((enc_meta, env_bytes)) = chunked_transfer::encrypt_sealed_metadata(
                &sealed_meta,
                &pending.x25519_pk,
                Some(pending.kyber_pk.as_slice()),
            ) {
                chunk_payload.sealed_metadata = Some(enc_meta);
                chunk_payload.sealed_metadata_key_envelope = Some(env_bytes);
            }
        }
        let chunk_bytes = match bincode::serialize(&chunk_payload) {
            Ok(chunk_bytes) => chunk_bytes,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                    chunk = chunk_index,
                    %error,
                    "Fast transfer chunk encode failed"
                );
                return false;
            }
        };
        let chunk_request = match chunked_transfer::wrap_chunk_request(
            keypair_net,
            MessageKind::ChunkData,
            chunk_bytes,
            0,
        ) {
            Ok(chunk_request) => chunk_request,
            Err(error) => {
                tracing::warn!(
                    transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                    chunk = chunk_index,
                    %error,
                    "Fast transfer chunk request build failed"
                );
                return false;
            }
        };
        if let Err(error) = iroh_network
            .send_transfer_request(&pending.runtime_transfer_key, &chunk_request)
            .await
        {
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {} fast relay path interrupted during chunk {} — receiver must /accept again",
                    "Fast transfer paused:".yellow().bold(),
                    pending.recipient_name.cyan(),
                    chunk_index,
                ),
            );
            tracing::debug!(
                transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                chunk = chunk_index,
                %error,
                "Fast transfer chunk send failed"
            );
            iroh_network
                .disconnect_transfer(&pending.runtime_transfer_key)
                .await;
            active_fast_group_iroh_downloads.remove(&pending.runtime_transfer_key);
            queue_post_transfer_reconnect_sweep(
                iroh_network,
                peer_store_net,
                peers_net,
                manual_disconnect_dids_net,
                remote_offline_dids_net,
                pending_iroh_reconnects,
            )
            .await;
            return false;
        }
        pending.next_chunk += 1;
        let print_interval = std::cmp::max(1, pending.session.total_chunks / 50);
        if pending.next_chunk == 1
            || pending.next_chunk % print_interval == 0
            || pending.next_chunk == pending.session.total_chunks
        {
            let total_mb = pending.session.total_size as f64 / (1024.0 * 1024.0);
            let sent_mb =
                (pending.next_chunk as f64 * pending.session.chunk_size as f64) / (1024.0 * 1024.0);
            let pct_done =
                (pending.next_chunk as f64 / pending.session.total_chunks as f64 * 100.0) as u32;
            print_async_progress_notice(format!(
                "   {} [{}/{}] {:.1}/{:.1} MB ({}%)",
                "Fast sending:".yellow(),
                pending.next_chunk,
                pending.session.total_chunks,
                sent_mb,
                total_mb,
                pct_done,
            ));
        }
        return true;
    }

    let complete_payload = chunked_transfer::build_complete_payload(&pending.session);
    let complete_bytes = match bincode::serialize(&complete_payload) {
        Ok(complete_bytes) => complete_bytes,
        Err(error) => {
            tracing::warn!(
                transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                %error,
                "Fast transfer complete encode failed"
            );
            return false;
        }
    };
    let complete_request = match chunked_transfer::wrap_chunk_request(
        keypair_net,
        MessageKind::TransferComplete,
        complete_bytes,
        pending.ttl,
    ) {
        Ok(complete_request) => complete_request,
        Err(error) => {
            tracing::warn!(
                transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
                %error,
                "Fast transfer complete request build failed"
            );
            return false;
        }
    };
    if let Err(error) = iroh_network
        .send_transfer_request(&pending.runtime_transfer_key, &complete_request)
        .await
    {
        print_async_notice(
            &config_net.agent.name,
            format!(
                "   {} {} fast relay path interrupted before completion — receiver must /accept again",
                "Fast transfer paused:".yellow().bold(),
                pending.recipient_name.cyan(),
            ),
        );
        tracing::debug!(
            transfer_id = %redacted_log_marker("transfer", &pending.transfer_id),
            %error,
            "Fast transfer complete send failed"
        );
        iroh_network
            .disconnect_transfer(&pending.runtime_transfer_key)
            .await;
        active_fast_group_iroh_downloads.remove(&pending.runtime_transfer_key);
        queue_post_transfer_reconnect_sweep(
            iroh_network,
            peer_store_net,
            peers_net,
            manual_disconnect_dids_net,
            remote_offline_dids_net,
            pending_iroh_reconnects,
        )
        .await;
        return false;
    }

    {
        let mut registry = group_mailboxes_net.lock().await;
        let _ = registry.clear_fast_file_grant_for_recipient(
            &pending.transfer_id,
            &pending.recipient_member_id,
        );
    }
    iroh_network
        .disconnect_transfer(&pending.runtime_transfer_key)
        .await;
    print_async_notice(
        &config_net.agent.name,
        format!(
            "   {} {} -> {} [{}]",
            "Fast transfer complete:".green().bold(),
            pending
                .group_name
                .clone()
                .unwrap_or_else(|| pending.group_id.clone())
                .cyan(),
            pending.recipient_name.cyan(),
            pending.transfer_id[..std::cmp::min(16, pending.transfer_id.len())].dimmed(),
        ),
    );
    pending.chunk_source.secure_cleanup_async().await;
    queue_post_transfer_reconnect_sweep(
        iroh_network,
        peer_store_net,
        peers_net,
        manual_disconnect_dids_net,
        remote_offline_dids_net,
        pending_iroh_reconnects,
    )
    .await;
    false
}

fn parse_x25519_public_key_hex_runtime(public_key_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(public_key_hex).context("invalid X25519 public key hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 public key must be 32 bytes"))
}

fn parse_kyber_public_key_hex_runtime(public_key_hex: &str) -> Result<Vec<u8>> {
    hex::decode(public_key_hex).context("invalid Kyber public key hex")
}

fn derive_did_from_verifying_key_hex_runtime(verifying_key_hex: &str) -> Result<String> {
    let verifying_key_bytes = hex::decode(verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key must be 32 bytes"))?;
    Ok(format!(
        "did:nxf:{}",
        hex::encode(sha2::Sha256::digest(verifying_key_bytes))
    ))
}

fn verify_agent_request_signature_with_verifying_key_hex(
    request: &AgentRequest,
    verifying_key_hex: &str,
    expected_did: Option<&str>,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let actual_did = derive_did_from_verifying_key_hex_runtime(verifying_key_hex)?;
    if let Some(expected_did) = expected_did {
        if actual_did != expected_did {
            bail!("agent request DID/verifying key mismatch");
        }
    }
    if request.sender_did != actual_did {
        bail!("agent request sender DID does not match verifying key");
    }

    let verifying_key_bytes = hex::decode(verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&verifying_key_bytes).context("invalid Ed25519 verifying key")?;

    let msg_type_bytes = serde_json::to_vec(&request.msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(msg_type_bytes.len() + request.payload.len() + 16);
    signed_data.extend_from_slice(&msg_type_bytes);
    signed_data.extend_from_slice(&request.payload);
    signed_data.extend_from_slice(&request.nonce.to_le_bytes());
    signed_data.extend_from_slice(&request.timestamp.to_le_bytes());

    let signature = Signature::from_slice(&request.signature)
        .map_err(|_| anyhow::anyhow!("invalid signature bytes"))?;
    verifying_key
        .verify_strict(&signed_data, &signature)
        .map_err(|_| anyhow::anyhow!("agent request signature invalid"))?;
    Ok(())
}

fn verify_fast_transfer_open_payload(
    payload: &crate::network::protocol::FastTransferOpenPayload,
    request: &AgentRequest,
) -> Result<String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let recipient_did =
        derive_did_from_verifying_key_hex_runtime(&payload.recipient_verifying_key_hex)?;
    if recipient_did != payload.recipient_did {
        bail!("FastTransferOpen DID/verifying key mismatch");
    }
    if request.sender_did != recipient_did {
        bail!("FastTransferOpen request sender DID mismatch");
    }

    let verifying_key_bytes = hex::decode(&payload.recipient_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("FastTransferOpen verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("invalid FastTransferOpen Ed25519 verifying key")?;
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("invalid FastTransferOpen signature"))?;
    verifying_key
        .verify_strict(
            &crate::agent::daemon::transfer_shared::fast_transfer_open_signing_data(payload),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("FastTransferOpen signature invalid"))?;
    Ok(recipient_did)
}

async fn finalize_active_fast_group_download(
    runtime_transfer_key: &str,
    active_fast_group_iroh_downloads: &mut HashMap<String, ActiveFastGroupIrohDownload>,
    group_mailboxes_net: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    receive_dir_config_net: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode_net: &LogMode,
    config_net: &AppConfig,
    iroh_network: &mut IrohTransport,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    remote_offline_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
) {
    let Some(mut download) = active_fast_group_iroh_downloads.remove(runtime_transfer_key) else {
        return;
    };
    debug_assert_eq!(download.runtime_transfer_key, runtime_transfer_key);
    let Some(recv) = download.recv.take() else {
        iroh_network.disconnect_transfer(runtime_transfer_key).await;
        queue_post_transfer_reconnect_sweep(
            iroh_network,
            peer_store_net,
            peers_net,
            manual_disconnect_dids_net,
            remote_offline_dids_net,
            pending_iroh_reconnects,
        )
        .await;
        return;
    };

    let sender_selector = download.sender_member_id.clone();
    let receive_cfg = receive_dir_config_net.lock().await.clone();
    let (target_dir, handoff) = match prepare_group_receive_target(
        log_mode_net,
        &receive_cfg,
        &sender_selector,
        &download.mailbox_transfer_id,
    ) {
        Ok(target) => target,
        Err(error) => {
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} fast transfer receive dir setup failed: {}",
                    "Error:".red().bold(),
                    error
                ),
            );
            iroh_network.disconnect_transfer(runtime_transfer_key).await;
            queue_post_transfer_reconnect_sweep(
                iroh_network,
                peer_store_net,
                peers_net,
                manual_disconnect_dids_net,
                remote_offline_dids_net,
                pending_iroh_reconnects,
            )
            .await;
            secure_wipe_dir_async(recv.temp_dir.clone()).await;
            return;
        }
    };

    let finalize_result = tokio::task::spawn_blocking({
        let recv = recv.clone();
        let target_dir = target_dir.clone();
        move || recv.finalize(&target_dir)
    })
    .await;

    iroh_network.disconnect_transfer(runtime_transfer_key).await;
    queue_post_transfer_reconnect_sweep(
        iroh_network,
        peer_store_net,
        peers_net,
        manual_disconnect_dids_net,
        remote_offline_dids_net,
        pending_iroh_reconnects,
    )
    .await;

    match finalize_result {
        Ok(Ok(manifest)) => {
            let manifest_label = manifest
                .files
                .first()
                .map(|entry| entry.path.clone())
                .unwrap_or_else(|| manifest.sha256.clone());
            {
                let mut registry = group_mailboxes_net.lock().await;
                let _ =
                    registry.remove_chunk_download_by_transfer_id(&download.mailbox_transfer_id);
                registry.clear_fast_file_grants_for_transfer(&download.transfer_id);
                registry.drop_fast_file_offer(&download.transfer_id);
            }
            let size_mb = manifest.total_size as f64 / (1024.0 * 1024.0);
            if let Some((handoff_id, handoff_dir)) = handoff {
                print_async_notice(
                    &config_net.agent.name,
                    format!(
                        "   {} {} ({:.1} MB) -> {}",
                        "Fast transfer staged for secure handoff:".green().bold(),
                        manifest.sha256[..16].dimmed(),
                        size_mb,
                        handoff_dir.display(),
                    ),
                );
                emit_transfer_event_with_handoff_and_group(
                    "incoming_staged",
                    "group_mailbox",
                    Some(&download.sender_member_id),
                    Some(&download.sender_name),
                    Some(&download.transfer_id),
                    Some(&manifest_label),
                    Some("group_fast_transfer_complete"),
                    Some(&handoff_id),
                    Some(&handoff_dir),
                    Some(&download.group_id),
                    download.group_name.as_deref(),
                );
            } else {
                print_async_notice(
                    &config_net.agent.name,
                    format!(
                        "   {} {} ({:.1} MB) -> {}",
                        "Fast transfer complete:".green().bold(),
                        manifest.sha256[..16].dimmed(),
                        size_mb,
                        target_dir.display(),
                    ),
                );
                emit_transfer_event_with_group(
                    "incoming_completed",
                    "group_mailbox",
                    Some(&download.sender_member_id),
                    Some(&download.sender_name),
                    Some(&download.transfer_id),
                    Some(&manifest_label),
                    Some("group_fast_transfer_complete"),
                    Some(&download.group_id),
                    download.group_name.as_deref(),
                );
            }
        }
        Ok(Err(error)) => {
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {}",
                    "Fast transfer finalize FAILED:".red().bold(),
                    error
                ),
            );
            emit_transfer_event(
                "incoming_failed",
                "in",
                Some(&download.sender_member_id),
                Some(&download.sender_name),
                Some(&download.transfer_id),
                None,
                Some(&format!("{}", error)),
            );
            secure_wipe_dir_async(recv.temp_dir.clone()).await;
        }
        Err(error) => {
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {}",
                    "Fast transfer finalize task failed:".red().bold(),
                    error
                ),
            );
            secure_wipe_dir_async(recv.temp_dir.clone()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_relay_only_iroh_endpoint_json(seed: u8) -> String {
        crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(seed)
    }

    fn known_peer_with_iroh_endpoint(did: &str, name: &str) -> KnownPeer {
        KnownPeer {
            did: did.to_string(),
            name: name.to_string(),
            role: "peer".to_string(),
            peer_id: "peer-id".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(91)),
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: true,
        }
    }

    fn sample_transfer_session(recipient_did: &str) -> chunked_transfer::TransferSession {
        chunked_transfer::TransferSession {
            session_id: "sess_test".to_string(),
            resume_token: "resume_test".to_string(),
            artifact_id: "artifact_test".to_string(),
            sender_did: "did:nxf:sender".to_string(),
            recipient_did: recipient_did.to_string(),
            filename: "payload.bin".to_string(),
            classification: "confidential".to_string(),
            total_size: 1024,
            chunk_size: 512,
            total_chunks: 2,
            merkle_root: [0u8; 32],
            plaintext_sha256: "00".repeat(32),
            chunks: vec![],
            chain_hash: "11".repeat(32),
            created_at: 0,
            status: chunked_transfer::TransferStatus::Preparing,
        }
    }

    fn sample_pending_iroh_chunk_transfer(
        peer_id: libp2p::PeerId,
        peer_did: &str,
        peer_name: &str,
    ) -> PendingIrohChunkTransfer {
        PendingIrohChunkTransfer {
            peer_id,
            peer_name: peer_name.to_string(),
            peer_did: peer_did.to_string(),
            session: sample_transfer_session(peer_did),
            merkle_proof_cache: vec![vec![]; 2],
            chunk_source: ChunkSource::InMemory(vec![vec![0u8; 8]]),
            next_chunk: 1,
            chunk_size: 8,
            x25519_pk: [7u8; 32],
            kyber_pk: vec![9u8; 32],
            ttl: 30_000,
            path: "/tmp/payload.bin".to_string(),
            packed_mb: 1.0,
            packed_size: 1024,
            awaiting_receiver_accept: false,
            awaiting_started_at: tokio::time::Instant::now(),
            approval_poll_after: None,
            retry_after: None,
            reconnect_wait_secs: 0,
            needs_reinit: false,
        }
    }

    fn sample_active_incoming_iroh_transfer(
        session_id: &str,
        sender_did: &str,
        sender_name: &str,
    ) -> ActiveIncomingIrohTransfer {
        ActiveIncomingIrohTransfer {
            session_id: session_id.to_string(),
            sender_did: sender_did.to_string(),
            sender_name: sender_name.to_string(),
            total_chunks: 8,
            received_chunks: 3,
            last_progress_at: tokio::time::Instant::now(),
            pause_notified: false,
        }
    }

    #[tokio::test]
    async fn ready_iroh_transfer_yield_is_not_immediately_ready() {
        use std::future::Future;
        use std::task::{Context, Poll};

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(yield_before_processing_ready_iroh_transfer());

        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Pending
        ));

        future.await;
    }

    #[test]
    fn fast_group_runtime_keys_isolate_parallel_recipient_downloads() {
        let logical_transfer_id = "sess_shared".to_string();
        let ticket_a = fast_group_runtime_transfer_key("ticket-a");
        let ticket_b = fast_group_runtime_transfer_key("ticket-b");

        assert_ne!(ticket_a, ticket_b);

        let mut downloads = HashMap::new();
        downloads.insert(
            ticket_a.clone(),
            ActiveFastGroupIrohDownload {
                runtime_transfer_key: ticket_a.clone(),
                transfer_id: logical_transfer_id.clone(),
                group_id: "grp_1".to_string(),
                group_name: Some("group1".to_string()),
                sender_member_id: "did:nxf:sender".to_string(),
                sender_name: "agent3".to_string(),
                sender_verifying_key_hex: "00".repeat(32),
                mailbox_transfer_id: "mailbox_a".to_string(),
                recv: None,
            },
        );
        downloads.insert(
            ticket_b.clone(),
            ActiveFastGroupIrohDownload {
                runtime_transfer_key: ticket_b.clone(),
                transfer_id: logical_transfer_id,
                group_id: "grp_1".to_string(),
                group_name: Some("group1".to_string()),
                sender_member_id: "did:nxf:sender".to_string(),
                sender_name: "agent3".to_string(),
                sender_verifying_key_hex: "11".repeat(32),
                mailbox_transfer_id: "mailbox_b".to_string(),
                recv: None,
            },
        );

        assert_eq!(downloads.len(), 2);
        assert_eq!(
            downloads
                .values()
                .filter(|download| download.transfer_id == "sess_shared")
                .count(),
            2
        );
    }

    #[test]
    fn fast_group_scheduler_round_robins_pending_recipients() {
        let mut pending = HashMap::new();
        pending.insert(
            "fast-group-ticket:ticket-a".to_string(),
            PendingFastGroupIrohTransfer {
                runtime_transfer_key: "fast-group-ticket:ticket-a".to_string(),
                transfer_id: "sess_shared".to_string(),
                group_id: "grp_1".to_string(),
                group_name: Some("ops".to_string()),
                sender_member_id: "did:nxf:sender".to_string(),
                recipient_member_id: "did:nxf:member-a".to_string(),
                recipient_name: "agent2".to_string(),
                session: sample_transfer_session("did:nxf:member-a"),
                chunk_source: ChunkSource::InMemory(vec![vec![0u8; 8]]),
                init_sent: true,
                next_chunk: 0,
                x25519_pk: [7u8; 32],
                kyber_pk: vec![9u8; 32],
                ttl: 30_000,
            },
        );
        pending.insert(
            "fast-group-ticket:ticket-b".to_string(),
            PendingFastGroupIrohTransfer {
                runtime_transfer_key: "fast-group-ticket:ticket-b".to_string(),
                transfer_id: "sess_shared".to_string(),
                group_id: "grp_1".to_string(),
                group_name: Some("ops".to_string()),
                sender_member_id: "did:nxf:sender".to_string(),
                recipient_member_id: "did:nxf:member-b".to_string(),
                recipient_name: "agent3".to_string(),
                session: sample_transfer_session("did:nxf:member-b"),
                chunk_source: ChunkSource::InMemory(vec![vec![0u8; 8]]),
                init_sent: true,
                next_chunk: 0,
                x25519_pk: [8u8; 32],
                kyber_pk: vec![10u8; 32],
                ttl: 30_000,
            },
        );

        assert_eq!(
            next_pending_fast_group_transfer_key(&pending, None),
            Some("fast-group-ticket:ticket-a".to_string())
        );
        assert_eq!(
            next_pending_fast_group_transfer_key(&pending, Some("fast-group-ticket:ticket-a"),),
            Some("fast-group-ticket:ticket-b".to_string())
        );
        assert_eq!(
            next_pending_fast_group_transfer_key(&pending, Some("fast-group-ticket:ticket-b"),),
            Some("fast-group-ticket:ticket-a".to_string())
        );
    }

    #[test]
    fn shutdown_transfer_context_includes_active_incoming_iroh_transfer() {
        let pending_outgoing = HashMap::new();
        let active_incoming = DashMap::new();
        active_incoming.insert(
            "sess_test".to_string(),
            sample_active_incoming_iroh_transfer("sess_test", "did:nxf:sender", "sender"),
        );

        assert!(iroh_shutdown_has_transfer_context(
            &pending_outgoing,
            &active_incoming,
        ));
    }

    #[test]
    fn shutdown_disconnect_notices_include_active_incoming_sender_peer() {
        let peer_id = libp2p::PeerId::random();
        let peers = DashMap::new();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: "did:nxf:sender".to_string(),
                name: "sender".to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(97)),
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([4u8; 32]),
            },
        );
        let direct_peer_dids = DashMap::new();
        let pending_outgoing = HashMap::new();
        let active_incoming = DashMap::new();
        active_incoming.insert(
            "sess_incoming".to_string(),
            sample_active_incoming_iroh_transfer("sess_incoming", "did:nxf:sender", "sender"),
        );

        let peer_ids = collect_iroh_shutdown_notice_peer_ids(
            &peers,
            &direct_peer_dids,
            &pending_outgoing,
            &active_incoming,
        );

        assert_eq!(peer_ids, vec![peer_id]);
    }

    #[test]
    fn seeds_startup_reconnects_for_known_iroh_peers() {
        let mut pending = HashMap::new();
        let known = known_peer_with_iroh_endpoint("did:nxf:test", "agent2");
        let expected_endpoint_json =
            crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json(
                known.iroh_endpoint_addr.as_deref().unwrap(),
            )
            .unwrap();
        let before = tokio::time::Instant::now();

        seed_initial_iroh_reconnects(&mut pending, &[known]);

        let queued = pending
            .get("did:nxf:test")
            .expect("expected startup reconnect to be queued");
        assert_eq!(queued.name, "agent2");
        assert_eq!(queued.iroh_endpoint_addr_json, expected_endpoint_json);
        assert_eq!(queued.attempts, 0);
        assert!(!queued.force_replace);
        assert!(queued.next_attempt_at >= before + startup_iroh_reconnect_delay());
    }

    #[test]
    fn next_due_reconnect_returns_only_one_ready_peer() {
        let now = tokio::time::Instant::now();
        let mut pending = HashMap::new();

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:later", "agent2"),
            true,
        );
        let later = pending.get_mut("did:nxf:later").unwrap();
        later.next_attempt_at = now + tokio::time::Duration::from_secs(10);

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:first", "agent1"),
            true,
        );
        let first = pending.get_mut("did:nxf:first").unwrap();
        first.next_attempt_at = now - tokio::time::Duration::from_secs(1);

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:second", "agent3"),
            true,
        );
        let second = pending.get_mut("did:nxf:second").unwrap();
        second.next_attempt_at = now - tokio::time::Duration::from_millis(100);

        assert_eq!(
            next_due_iroh_reconnect_did(&pending, now),
            Some("did:nxf:first".to_string())
        );
    }

    #[test]
    fn due_reconnect_batch_returns_multiple_ready_peers() {
        let now = tokio::time::Instant::now();
        let mut pending = HashMap::new();

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:later", "agent-later"),
            true,
        );
        pending.get_mut("did:nxf:later").unwrap().next_attempt_at =
            now + tokio::time::Duration::from_secs(5);

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:first", "agent-first"),
            true,
        );
        pending.get_mut("did:nxf:first").unwrap().next_attempt_at =
            now - tokio::time::Duration::from_secs(2);

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:second", "agent-second"),
            true,
        );
        pending.get_mut("did:nxf:second").unwrap().next_attempt_at =
            now - tokio::time::Duration::from_millis(100);

        queue_iroh_reconnect(
            &mut pending,
            &known_peer_with_iroh_endpoint("did:nxf:third", "agent-third"),
            true,
        );
        pending.get_mut("did:nxf:third").unwrap().next_attempt_at =
            now - tokio::time::Duration::from_secs(1);

        assert_eq!(
            next_due_iroh_reconnect_dids(&pending, now, 2),
            vec!["did:nxf:first".to_string(), "did:nxf:third".to_string()]
        );
    }

    #[test]
    fn known_auto_reconnect_peers_do_not_give_up_after_retry_limit() {
        assert!(!should_give_up_iroh_reconnect(
            MAX_IROH_RECONNECT_ATTEMPTS + 1,
            true,
        ));
        assert!(should_give_up_iroh_reconnect(
            MAX_IROH_RECONNECT_ATTEMPTS + 1,
            false,
        ));
    }

    #[test]
    fn known_auto_reconnect_peers_switch_to_steady_background_cadence() {
        assert_eq!(
            next_iroh_reconnect_delay(MAX_IROH_RECONNECT_ATTEMPTS + 1, true),
            tokio::time::Duration::from_secs(STEADY_IROH_RECONNECT_INTERVAL_SECS),
        );
        assert_eq!(
            next_iroh_reconnect_delay(1, true),
            tokio::time::Duration::from_secs(1),
        );
        assert_eq!(
            next_iroh_reconnect_delay(5, true),
            tokio::time::Duration::from_secs(16),
        );
    }

    #[test]
    fn transfer_retry_backoff_recovers_quickly_from_small_disconnects() {
        assert_eq!(
            next_iroh_transfer_retry_delay(0),
            tokio::time::Duration::from_secs(1),
        );
        assert_eq!(
            next_iroh_transfer_retry_delay(2),
            tokio::time::Duration::from_secs(2),
        );
        assert_eq!(
            next_iroh_transfer_retry_delay(6),
            tokio::time::Duration::from_secs(4),
        );
        assert_eq!(
            next_iroh_transfer_retry_delay(14),
            tokio::time::Duration::from_secs(8),
        );
    }

    #[test]
    fn unauthenticated_transfer_is_parked_instead_of_busy_spinning() {
        let now = tokio::time::Instant::now();
        let peer_id = libp2p::PeerId::random();
        let mut pending = sample_pending_iroh_chunk_transfer(peer_id, "did:nxf:test", "agent2");

        park_iroh_transfer_until_authenticated_session(&mut pending, now);
        assert!(pending.retry_after.is_some_and(|wake_at| wake_at > now));

        pending.awaiting_receiver_accept = true;
        pending.retry_after = None;
        pending.approval_poll_after = None;
        park_iroh_transfer_until_authenticated_session(&mut pending, now);
        assert!(pending
            .approval_poll_after
            .is_some_and(|wake_at| wake_at > now));
    }

    #[test]
    fn live_iroh_session_requires_matching_authenticated_stable_id() {
        let authenticated_sessions = IrohAuthenticatedSessionMap::new();
        let live_peer_id = libp2p::PeerId::random();
        let stale_peer_id = libp2p::PeerId::random();

        note_iroh_authenticated_session(&authenticated_sessions, &stale_peer_id, 7);

        assert!(!is_authenticated_iroh_session(
            &authenticated_sessions,
            &live_peer_id,
            7,
        ));
        assert!(!is_authenticated_iroh_session(
            &authenticated_sessions,
            &stale_peer_id,
            8,
        ));
        assert!(is_authenticated_iroh_session(
            &authenticated_sessions,
            &stale_peer_id,
            7,
        ));
    }

    #[test]
    fn connected_iroh_session_counts_placeholder_without_authentication() {
        let peers = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: "did:nxf:test".to_string(),
                name: "agent".to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(92)),
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        assert!(has_connected_iroh_transport_session(&peers, "did:nxf:test"));
        let authenticated_sessions = IrohAuthenticatedSessionMap::new();
        assert!(!is_authenticated_iroh_session(
            &authenticated_sessions,
            &peer_id,
            1,
        ));
    }

    #[test]
    fn reconnect_rebind_updates_pending_transfer_peer_id() {
        let old_peer_id = libp2p::PeerId::random();
        let new_peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            old_peer_id.to_string(),
            sample_pending_iroh_chunk_transfer(old_peer_id, "did:nxf:test", "agent2"),
        );

        rebind_pending_iroh_chunk_transfer_peer(
            &mut pending,
            "did:nxf:test",
            new_peer_id,
            "agent2",
        );

        assert!(!pending.contains_key(&old_peer_id.to_string()));
        let rebound = pending
            .get(&new_peer_id.to_string())
            .expect("expected rebound pending transfer");
        assert_eq!(rebound.peer_id, new_peer_id);
        assert_eq!(rebound.peer_name, "agent2");
        assert!(rebound.retry_after.is_some());
    }

    #[test]
    fn successful_reconnect_defers_handshake_until_live_event_path() {
        let peers = Arc::new(DashMap::new());
        let invite_proofs = Arc::new(DashMap::new());
        let liveness = Arc::new(DashMap::new());
        let handshake_sync = Arc::new(DashMap::new());
        let authenticated_sessions = Arc::new(IrohAuthenticatedSessionMap::new());
        let mut handshake_sent = IrohHandshakeTracker::new();
        let old_peer_id = libp2p::PeerId::random();
        let new_peer_id = libp2p::PeerId::random();
        let endpoint_json = sample_relay_only_iroh_endpoint_json(96);
        let pending = PendingIrohReconnect {
            did: "did:nxf:test".to_string(),
            name: "agent".to_string(),
            iroh_endpoint_addr_json: endpoint_json.clone(),
            encryption_public_key_hex: Some(hex::encode([7u8; 32])),
            verifying_key_hex: Some(hex::encode([9u8; 32])),
            kyber_public_key_hex: Some(hex::encode([8u8; 32])),
            next_attempt_at: tokio::time::Instant::now(),
            attempts: 1,
            force_replace: false,
        };

        peers.insert(
            old_peer_id.to_string(),
            PeerInfo {
                peer_id: old_peer_id,
                did: pending.did.clone(),
                name: "stale".to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(97)),
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([4u8; 32]),
            },
        );
        invite_proofs.insert(old_peer_id.to_string(), "old-proof".to_string());
        invite_proofs.insert(new_peer_id.to_string(), "new-proof".to_string());
        mark_iroh_peer_active(&liveness, &new_peer_id);
        note_iroh_handshake_message_sent(&handshake_sync, &new_peer_id, "hs_old");
        note_iroh_authenticated_session(&authenticated_sessions, &new_peer_id, 77);
        record_iroh_handshake_sent(&mut handshake_sent, &liveness, &new_peer_id);

        let mut pending_transfers = HashMap::new();
        pending_transfers.insert(
            old_peer_id.to_string(),
            sample_pending_iroh_chunk_transfer(old_peer_id, &pending.did, &pending.name),
        );

        finalize_successful_iroh_reconnect(
            &peers,
            &invite_proofs,
            &liveness,
            &handshake_sync,
            &authenticated_sessions,
            &mut handshake_sent,
            &mut pending_transfers,
            &pending,
            new_peer_id,
            &endpoint_json,
        );

        assert!(!peers.contains_key(&old_peer_id.to_string()));
        assert!(!invite_proofs.contains_key(&old_peer_id.to_string()));
        assert!(handshake_sync.get(&new_peer_id.to_string()).is_none());
        assert!(!authenticated_sessions.contains_key(&new_peer_id.to_string()));
        assert!(!handshake_sent.contains_key(&new_peer_id));

        let live = peers
            .get(&new_peer_id.to_string())
            .expect("expected live reconnect slot");
        assert_eq!(live.did, pending.did);
        assert_eq!(live.name, pending.name);
        assert_eq!(
            live.iroh_endpoint_addr.as_deref(),
            Some(endpoint_json.as_str())
        );
        assert_eq!(live.x25519_public_key, Some([7u8; 32]));
        assert_eq!(
            live.kyber_public_key.as_deref(),
            Some(vec![8u8; 32].as_slice())
        );
        assert_eq!(live.verifying_key, Some([9u8; 32]));

        let rebound = pending_transfers
            .get(&new_peer_id.to_string())
            .expect("expected rebound pending transfer");
        assert_eq!(rebound.peer_id, new_peer_id);
        assert!(should_send_iroh_handshake_for_live_session(
            &handshake_sent,
            &liveness,
            &new_peer_id,
        ));
    }

    #[tokio::test]
    async fn scheduling_transfer_retry_demotes_stale_peer_session() {
        let peer_did = "did:nxf:test";
        let peer_name = "agent2";
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: peer_did.to_string(),
                name: peer_name.to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(93)),
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: Some([5u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([3u8; 32]),
            },
        );
        let active_target = Arc::new(Mutex::new(Some(peer_did.to_string())));
        set_active_prompt_target_label(Some(peer_name.to_string()));

        let invite_proofs = Arc::new(DashMap::new());
        invite_proofs.insert(peer_id.to_string(), "invite-proof".to_string());
        let liveness = Arc::new(DashMap::new());
        mark_iroh_peer_active(&liveness, &peer_id);
        let handshake_sync = Arc::new(DashMap::new());
        let authenticated_sessions = Arc::new(IrohAuthenticatedSessionMap::new());
        note_iroh_handshake_message_sent(&handshake_sync, &peer_id, "hs_1");
        let mut handshake_sent = IrohHandshakeTracker::new();
        record_iroh_handshake_sent(&mut handshake_sent, &liveness, &peer_id);
        note_iroh_authenticated_session(&authenticated_sessions, &peer_id, 99);

        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(known_peer_with_iroh_endpoint(peer_did, peer_name));
        }
        let manual_disconnects = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let remote_offline = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let mut pending_reconnects = HashMap::new();
        let mut pending = sample_pending_iroh_chunk_transfer(peer_id, peer_did, peer_name);

        let scheduled = schedule_iroh_chunk_transfer_retry(
            &mut pending,
            &peers,
            &active_target,
            &invite_proofs,
            &liveness,
            &handshake_sync,
            &authenticated_sessions,
            &mut handshake_sent,
            &peer_store,
            &manual_disconnects,
            &remote_offline,
            &mut pending_reconnects,
            "agent1",
            "chunk 1",
        )
        .await;

        assert!(scheduled);
        let placeholder = peers
            .get(&peer_id.to_string())
            .expect("expected reconnecting placeholder");
        assert!(placeholder.verifying_key.is_none());
        assert_eq!(placeholder.did, peer_did);
        assert!(active_target
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
        assert!(invite_proofs.get(&peer_id.to_string()).is_none());
        assert!(liveness.get(&peer_id.to_string()).is_none());
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
        assert!(!authenticated_sessions.contains_key(&peer_id.to_string()));
        assert!(pending_reconnects.contains_key(peer_did));
        set_active_prompt_target_label(None);
    }

    #[tokio::test]
    async fn post_transfer_reconnect_sweep_skips_manual_disconnects_and_queues_unreachable_peers() {
        let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(4);
        let (priority_incoming_tx, _priority_incoming_rx) = tokio::sync::mpsc::channel(4);
        let mut iroh_config = crate::config::IrohConfig::default();
        iroh_config.direct_enabled = true;
        iroh_config.relay_enabled = false;
        let iroh_network = IrohTransport::new(
            0,
            &iroh_config,
            [7u8; 32],
            incoming_tx,
            priority_incoming_tx,
        )
        .await
        .expect("local iroh transport");

        let peers = Arc::new(DashMap::new());
        let connected_peer_id = libp2p::PeerId::random();
        peers.insert(
            connected_peer_id.to_string(),
            PeerInfo {
                peer_id: connected_peer_id,
                did: "did:nxf:connected".to_string(),
                name: "connected".to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(94)),
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(known_peer_with_iroh_endpoint(
                "did:nxf:connected",
                "connected",
            ));
            store.upsert(known_peer_with_iroh_endpoint("did:nxf:missing", "missing"));
            store.upsert(known_peer_with_iroh_endpoint("did:nxf:manual", "manual"));
            store.upsert(known_peer_with_iroh_endpoint("did:nxf:offline", "offline"));
        }

        let manual_disconnects = Arc::new(tokio::sync::Mutex::new(HashSet::from([
            "did:nxf:manual".to_string(),
        ])));
        let remote_offline = Arc::new(tokio::sync::Mutex::new(HashSet::from([
            "did:nxf:offline".to_string()
        ])));
        let mut pending = HashMap::new();

        queue_post_transfer_reconnect_sweep(
            &iroh_network,
            &peer_store,
            &peers,
            &manual_disconnects,
            &remote_offline,
            &mut pending,
        )
        .await;

        assert!(pending.contains_key("did:nxf:missing"));
        assert!(pending.contains_key("did:nxf:connected"));
        assert!(!pending.contains_key("did:nxf:manual"));
        assert!(pending.contains_key("did:nxf:offline"));
        assert!(pending
            .get("did:nxf:missing")
            .is_some_and(|entry| entry.force_replace));
    }

    #[tokio::test]
    async fn transfer_request_short_circuits_when_graceful_shutdown_is_requested() {
        clear_graceful_shutdown_requested();
        let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(4);
        let (priority_incoming_tx, _priority_incoming_rx) = tokio::sync::mpsc::channel(4);
        let mut iroh_config = crate::config::IrohConfig::default();
        iroh_config.direct_enabled = true;
        iroh_config.relay_enabled = false;
        let mut iroh_network = IrohTransport::new(
            0,
            &iroh_config,
            [13u8; 32],
            incoming_tx,
            priority_incoming_tx,
        )
        .await
        .expect("local iroh transport");

        let request = AgentRequest {
            message_id: "msg_shutdown_short_circuit".to_string(),
            sender_did: "did:nxf:test".to_string(),
            sender_name: "tester".to_string(),
            sender_role: "peer".to_string(),
            msg_type: MessageKind::Heartbeat,
            payload: b"KA".to_vec(),
            signature: vec![],
            nonce: 1,
            timestamp: 1,
            ttl_ms: 0,
        };

        mark_graceful_shutdown_requested();
        let result = send_iroh_transfer_request_interruptibly(
            &iroh_network,
            &libp2p::PeerId::random(),
            &request,
        )
        .await
        .expect("shutdown should short-circuit");
        assert!(result.is_none());

        clear_graceful_shutdown_requested();
        iroh_network.shutdown().await;
    }

    #[tokio::test]
    async fn remote_offline_retry_keeps_pending_transfer_and_reconnect() {
        let peer_did = "did:nxf:offline";
        let peer_name = "offline-peer";
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: peer_did.to_string(),
                name: peer_name.to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(96)),
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: Some([5u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([3u8; 32]),
            },
        );
        let active_target = Arc::new(Mutex::new(Some(peer_did.to_string())));
        set_active_prompt_target_label(Some(peer_name.to_string()));

        let invite_proofs = Arc::new(DashMap::new());
        invite_proofs.insert(peer_id.to_string(), "invite-proof".to_string());
        let liveness = Arc::new(DashMap::new());
        mark_iroh_peer_active(&liveness, &peer_id);
        let handshake_sync = Arc::new(DashMap::new());
        let authenticated_sessions = Arc::new(IrohAuthenticatedSessionMap::new());
        note_iroh_handshake_message_sent(&handshake_sync, &peer_id, "hs_1");
        let mut handshake_sent = IrohHandshakeTracker::new();
        record_iroh_handshake_sent(&mut handshake_sent, &liveness, &peer_id);
        note_iroh_authenticated_session(&authenticated_sessions, &peer_id, 42);

        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(known_peer_with_iroh_endpoint(peer_did, peer_name));
        }
        let manual_disconnects = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let remote_offline = Arc::new(tokio::sync::Mutex::new(HashSet::from([
            peer_did.to_string()
        ])));
        let mut pending_reconnects = HashMap::new();
        let mut pending = sample_pending_iroh_chunk_transfer(peer_id, peer_did, peer_name);

        let scheduled = schedule_iroh_chunk_transfer_retry(
            &mut pending,
            &peers,
            &active_target,
            &invite_proofs,
            &liveness,
            &handshake_sync,
            &authenticated_sessions,
            &mut handshake_sent,
            &peer_store,
            &manual_disconnects,
            &remote_offline,
            &mut pending_reconnects,
            "agent1",
            "chunk 1",
        )
        .await;

        assert!(scheduled);
        assert!(peers.get(&peer_id.to_string()).is_none());
        assert!(active_target
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
        assert!(invite_proofs.get(&peer_id.to_string()).is_none());
        assert!(liveness.get(&peer_id.to_string()).is_none());
        assert!(!peer_acked_current_iroh_handshake(
            &handshake_sync,
            &peer_id
        ));
        assert!(!authenticated_sessions.contains_key(&peer_id.to_string()));
        assert!(pending_reconnects.contains_key(peer_did));
        assert!(pending.retry_after.is_some());
        set_active_prompt_target_label(None);
    }

    #[tokio::test]
    async fn reconnecting_placeholder_is_not_treated_as_live_transport_session() {
        let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(4);
        let (priority_incoming_tx, _priority_incoming_rx) = tokio::sync::mpsc::channel(4);
        let mut iroh_config = crate::config::IrohConfig::default();
        iroh_config.direct_enabled = true;
        iroh_config.relay_enabled = false;
        let iroh_network = IrohTransport::new(
            0,
            &iroh_config,
            [9u8; 32],
            incoming_tx,
            priority_incoming_tx,
        )
        .await
        .expect("local iroh transport");

        let peers = DashMap::new();
        let placeholder_peer_id = libp2p::PeerId::random();
        peers.insert(
            placeholder_peer_id.to_string(),
            PeerInfo {
                peer_id: placeholder_peer_id,
                did: "did:nxf:test".to_string(),
                name: "agent".to_string(),
                role: "unknown".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(95)),
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: None,
                aegis_supported: false,
                ratchet_dh_public: None,
            },
        );

        assert!(!has_live_iroh_transport_session(&iroh_network, &peers, "did:nxf:test").await);
    }

    #[test]
    fn reset_transfer_for_reapproval_rewinds_pending_stream() {
        let peer_id = libp2p::PeerId::random();
        let mut pending = sample_pending_iroh_chunk_transfer(peer_id, "did:nxf:test", "agent2");
        pending.next_chunk = 5;
        pending.awaiting_receiver_accept = false;
        pending.approval_poll_after = Some(tokio::time::Instant::now());
        pending.needs_reinit = false;

        reset_iroh_transfer_for_reapproval(&mut pending);

        assert_eq!(pending.next_chunk, 5);
        assert!(pending.awaiting_receiver_accept);
        assert!(pending.approval_poll_after.is_none());
        assert!(pending.needs_reinit);
        assert!(iroh_transfer_restart_already_pending(&pending));
    }

    #[test]
    fn apply_resume_snapshot_starts_from_first_missing_chunk() {
        let mut session = sample_transfer_session("did:nxf:receiver");
        session.chunks = vec![
            chunked_transfer::ChunkState {
                index: 0,
                offset: 0,
                size: 4,
                sha256: [0u8; 32],
                encrypted: false,
                sent: false,
                acknowledged: false,
            },
            chunked_transfer::ChunkState {
                index: 1,
                offset: 4,
                size: 4,
                sha256: [1u8; 32],
                encrypted: false,
                sent: false,
                acknowledged: false,
            },
            chunked_transfer::ChunkState {
                index: 2,
                offset: 8,
                size: 4,
                sha256: [2u8; 32],
                encrypted: false,
                sent: false,
                acknowledged: false,
            },
        ];
        session.total_chunks = 3;

        let next_chunk = apply_transfer_resume_snapshot(&mut session, &[0, 2]);

        assert_eq!(next_chunk, 1);
        assert!(session.chunks[0].acknowledged);
        assert!(!session.chunks[1].acknowledged);
        assert!(session.chunks[2].acknowledged);
    }

    #[test]
    fn shutdown_notice_targets_include_transfer_only_peer() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            peer_id.to_string(),
            sample_pending_iroh_chunk_transfer(peer_id, "did:nxf:sender", "sender"),
        );

        let mut seen = HashSet::new();
        let mut peer_ids = Vec::new();
        for peer in super::super::selectors::sorted_direct_peer_list(&peers, &direct_peer_dids) {
            if seen.insert(peer.peer_id) {
                peer_ids.push(peer.peer_id);
            }
        }
        for transfer in pending.values() {
            if seen.insert(transfer.peer_id) {
                peer_ids.push(transfer.peer_id);
            }
        }

        assert_eq!(peer_ids, vec![peer_id]);
    }

    #[test]
    fn shutdown_notice_targets_prefer_live_peer_id_for_pending_transfer_did() {
        let stale_peer_id = libp2p::PeerId::random();
        let live_peer_id = libp2p::PeerId::random();
        let peers = DashMap::new();
        peers.insert(
            live_peer_id.to_string(),
            PeerInfo {
                peer_id: live_peer_id,
                did: "did:nxf:sender".to_string(),
                name: "sender".to_string(),
                role: "peer".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(sample_relay_only_iroh_endpoint_json(98)),
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([4u8; 32]),
            },
        );
        let direct_peer_dids = DashMap::new();
        let active_incoming = DashMap::new();
        let mut pending = HashMap::new();
        pending.insert(
            stale_peer_id.to_string(),
            sample_pending_iroh_chunk_transfer(stale_peer_id, "did:nxf:sender", "sender"),
        );

        let peer_ids = collect_iroh_shutdown_notice_peer_ids(
            &peers,
            &direct_peer_dids,
            &pending,
            &active_incoming,
        );

        assert_eq!(peer_ids, vec![live_peer_id]);
    }

    #[test]
    fn iroh_transfer_shutdown_notice_grace_is_extended() {
        assert_eq!(
            iroh_shutdown_notice_grace_ms(true),
            IROH_TRANSFER_SHUTDOWN_NOTICE_GRACE_MS
        );
        assert_eq!(
            iroh_shutdown_notice_grace_ms(false),
            IROH_SHUTDOWN_NOTICE_GRACE_MS
        );
    }
}

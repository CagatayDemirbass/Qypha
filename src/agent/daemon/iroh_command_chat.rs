use super::iroh_command_handlers::{IrohCommandHandlerShared, IrohCommandHandlerState};
use super::*;

struct IrohTransportHandle<'a>(&'a mut IrohTransport);

const IROH_CHAT_SEND_TIMEOUT_SECS: u64 = 3;
const DIRECT_CHAT_REESTABLISH_WAIT_MS: u64 = 1_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnsureIrohDirectChatOutcome {
    Ready,
    Reestablishing,
    StaleTransport,
}

impl std::ops::Deref for IrohTransportHandle<'_> {
    type Target = IrohTransport;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for IrohTransportHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

async fn send_iroh_request_with_timeout(
    iroh_network: &IrohTransport,
    peer_id: &libp2p::PeerId,
    request: &crate::network::protocol::AgentRequest,
) -> anyhow::Result<crate::network::protocol::AgentResponse> {
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(IROH_CHAT_SEND_TIMEOUT_SECS),
        iroh_network.send_request(peer_id, request),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => anyhow::bail!("iroh send timed out after {}s", IROH_CHAT_SEND_TIMEOUT_SECS),
    }
}

fn clear_selected_iroh_chat_target(
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    peer_did: &str,
) -> bool {
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
    cleared
}

fn demote_stale_iroh_chat_peer(
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    peer_id: &libp2p::PeerId,
    peer_did: &str,
    reconnect_peer: Option<&KnownPeer>,
) {
    let peer_key = peer_id.to_string();
    let reconnectable = reconnect_peer.filter(|known| known.iroh_endpoint_addr.is_some());
    if let Some(known) = reconnectable {
        peers_net.insert(
            peer_key,
            reconnecting_iroh_placeholder(peer_id.to_owned(), known),
        );
    } else {
        peers_net.remove(&peer_key);
        clear_selected_iroh_chat_target(active_chat_target_did_net, peer_did);
    }
}

fn should_clear_selected_target_for_stale_iroh_chat_recovery(
    has_active_incoming_transfer: bool,
) -> bool {
    has_active_incoming_transfer
}

async fn recover_stale_iroh_chat_peer(
    pending_iroh_reconnects: &mut HashMap<String, PendingIrohReconnect>,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    active_incoming_iroh_transfers_net: &Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    iroh_peer_liveness_net: &Arc<DashMap<String, IrohPeerLiveness>>,
    iroh_handshake_sync_net: &Arc<DashMap<String, IrohHandshakeSyncState>>,
    iroh_authenticated_sessions_net: &Arc<IrohAuthenticatedSessionMap>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    handshake_sent: &mut IrohHandshakeTracker,
    config_net: &AppConfig,
    peer_id: &libp2p::PeerId,
    peer_did: &str,
    peer_name: &str,
) {
    let reconnect_peer = if peer_did.trim().is_empty() {
        None
    } else {
        let persisted = {
            let ps = peer_store_net.lock().await;
            ps.get(peer_did).cloned()
        };
        persisted.or_else(|| {
            peers_net
                .get(&peer_id.to_string())
                .and_then(|entry| known_peer_from_authenticated_live_iroh_peer(entry.value()))
        })
    };
    let has_active_incoming_transfer =
        has_active_incoming_iroh_transfer_for_sender(active_incoming_iroh_transfers_net, peer_did);

    invite_proof_net.remove(&peer_id.to_string());
    iroh_peer_liveness_net.remove(&peer_id.to_string());
    clear_iroh_handshake_tracking(handshake_sent, peer_id);
    clear_iroh_handshake_sync(iroh_handshake_sync_net, peer_id);
    clear_iroh_authenticated_session(iroh_authenticated_sessions_net, peer_id);
    demote_stale_iroh_chat_peer(
        peers_net,
        active_chat_target_did_net,
        peer_id,
        peer_did,
        reconnect_peer.as_ref(),
    );
    if should_clear_selected_target_for_stale_iroh_chat_recovery(has_active_incoming_transfer) {
        clear_selected_iroh_chat_target(active_chat_target_did_net, peer_did);
    }

    if let Some(known) = reconnect_peer
        .as_ref()
        .filter(|known| known.iroh_endpoint_addr.is_some())
    {
        let queued_reconnect = queue_iroh_reconnect(pending_iroh_reconnects, known, true);
        if queued_reconnect {
            emit_headless_direct_peer_event(
                "reconnecting",
                &known.did,
                &known.name,
                Some(&peer_id.to_string()),
                "reconnecting",
                Some("send_failure"),
            );
            print_async_notice(
                &config_net.agent.name,
                format!(
                    "   {} {}",
                    "Reconnecting:".yellow().bold(),
                    peer_name.cyan(),
                ),
            );
        }
    } else {
        emit_headless_direct_peer_event(
            "disconnected",
            peer_did,
            peer_name,
            Some(&peer_id.to_string()),
            "offline",
            Some("send_failure"),
        );
        print_async_notice(
            &config_net.agent.name,
            format!(
                "   {} {}",
                "Peer offline:".yellow().bold(),
                peer_name.cyan(),
            ),
        );
    }
}

async fn ensure_iroh_direct_chat_ready(
    iroh_network: &IrohTransport,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    pending_hybrid_ratchet_inits_net: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    ratchet_mgr_net: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    iroh_handshake_sync_net: &Arc<DashMap<String, IrohHandshakeSyncState>>,
    ratchet_init_pub_hex_net: &str,
    peer_id: &libp2p::PeerId,
    peer_did: &str,
    peer_name: &str,
) -> EnsureIrohDirectChatOutcome {
    let readiness = direct_chat_readiness(peers_net, ratchet_mgr_net, peer_did).await;
    if readiness == DirectChatReadiness::Ready {
        return EnsureIrohDirectChatOutcome::Ready;
    }

    let ack_handshake_message_id = if matches!(readiness, DirectChatReadiness::AwaitingRatchetSend)
    {
        latest_inbound_iroh_handshake_message_id(iroh_handshake_sync_net, peer_id)
    } else {
        None
    };

    let (invite_code, invite_bound_override) = stored_invite_binding_parts(
        invite_proof_net
            .get(&peer_id.to_string())
            .map(|entry| entry.value().clone()),
    );
    match send_handshake_iroh(
        iroh_network,
        peers_net,
        pending_hybrid_ratchet_inits_net,
        config_net,
        keypair_net,
        peer_id,
        Some(peer_did),
        ratchet_init_pub_hex_net,
        invite_code,
        invite_bound_override,
        ack_handshake_message_id,
        false,
    )
    .await
    {
        IrohHandshakeSendOutcome::Sent(message_id) => {
            note_iroh_handshake_message_sent(iroh_handshake_sync_net, peer_id, &message_id);
        }
        IrohHandshakeSendOutcome::Failed => {
            return EnsureIrohDirectChatOutcome::StaleTransport;
        }
        IrohHandshakeSendOutcome::Suppressed => {}
    }

    if wait_for_direct_chat_ready(
        peers_net,
        ratchet_mgr_net,
        peer_did,
        tokio::time::Duration::from_millis(DIRECT_CHAT_REESTABLISH_WAIT_MS),
    )
    .await
        == DirectChatReadiness::Ready
    {
        return EnsureIrohDirectChatOutcome::Ready;
    }

    println!(
        "   {} with {} — try again in a moment",
        "E2EE session re-establishing".yellow().bold(),
        peer_name.cyan()
    );
    EnsureIrohDirectChatOutcome::Reestablishing
}

#[allow(unused_variables)]
pub(crate) async fn handle_iroh_chat_command(
    cmd: NetworkCommand,
    state: &mut IrohCommandHandlerState<'_>,
    shared: &IrohCommandHandlerShared<'_>,
) {
    let mut iroh_network = IrohTransportHandle(state.iroh_network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_iroh_chunk_transfers = &mut *state.pending_iroh_chunk_transfers;
    let pending_iroh_reconnects = &mut *state.pending_iroh_reconnects;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let sign_key = shared.sign_key;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let rbac_net = shared.rbac_net;
    let used_invites_net = shared.used_invites_net;
    let used_invites_path_net = shared.used_invites_path_net;
    let group_mailboxes_net = shared.group_mailboxes_net;
    let mailbox_transport_net = shared.mailbox_transport_net;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let peer_store_net = shared.peer_store_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let iroh_peer_liveness_net = shared.iroh_peer_liveness_net;
    let iroh_handshake_sync_net = shared.iroh_handshake_sync_net;
    let iroh_authenticated_sessions_net = shared.iroh_authenticated_sessions_net;
    let active_incoming_iroh_transfers_net = shared.active_incoming_iroh_transfers_net;
    let active_chat_target_did_net = shared.active_chat_target_did_net;
    let iroh_config = shared.iroh_config;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    match cmd {
        NetworkCommand::SendRatchetBootstrap { peer_id, peer_did } => {
            if !peer_acked_current_iroh_handshake(iroh_handshake_sync_net, &peer_id) {
                tracing::debug!(
                    peer = %peer_did,
                    "Deferring ratchet bootstrap until remote handshake acknowledgment arrives"
                );
                return;
            }
            let payload = encrypt_ratchet_payload(
                ratchet_mgr_net,
                &peer_did,
                RATCHET_BOOTSTRAP_MARKER,
                false,
            )
            .await
            .ok();
            if let Some(payload) = payload {
                let request = build_signed_chat_request(config_net, sign_key, payload);
                let _ = send_iroh_request_with_timeout(&iroh_network, &peer_id, &request).await;
            }
        }
        NetworkCommand::EnsurePeerHandshake {
            peer_id,
            ack_handshake_message_id,
            trusted_known_peer_bootstrap,
        } => {
            let should_send_ack_response = ack_handshake_message_id.is_some();
            if should_send_ack_response
                || should_send_iroh_handshake_for_live_session(
                    handshake_sent,
                    iroh_peer_liveness_net,
                    &peer_id,
                )
            {
                let (invite_code, invite_bound_override) = stored_invite_binding_parts(
                    invite_proof_net
                        .get(&peer_id.to_string())
                        .map(|entry| entry.value().clone()),
                );
                if let IrohHandshakeSendOutcome::Sent(message_id) = send_handshake_iroh(
                    &iroh_network,
                    peers_net,
                    pending_hybrid_ratchet_inits_net,
                    &config_net,
                    &keypair_net,
                    &peer_id,
                    None,
                    &ratchet_init_pub_hex_net,
                    invite_code,
                    invite_bound_override,
                    ack_handshake_message_id,
                    trusted_known_peer_bootstrap,
                )
                .await
                {
                    invite_proof_net.remove(&peer_id.to_string());
                    record_iroh_handshake_sent(handshake_sent, iroh_peer_liveness_net, &peer_id);
                    note_iroh_handshake_message_sent(
                        iroh_handshake_sync_net,
                        &peer_id,
                        &message_id,
                    );
                }
            }
        }
        NetworkCommand::SendChatToPeer {
            peer_id,
            peer_did,
            peer_name,
            message,
        } => {
            let allowed = {
                let r = rbac_net.read().await;
                r.can_send_to(&config_net.agent.did, &peer_did)
            };
            if !allowed {
                println!(
                    "   {} {} blocked by RBAC policy",
                    "Policy:".yellow().bold(),
                    peer_name.cyan()
                );
                return;
            }
            // Large incoming transfers can go quiet during relay churn or short
            // network hiccups. Treat the peer as stale only when the transport
            // is actually disconnected or an outbound request fails.
            if !iroh_network.is_connected(&peer_id).await {
                recover_stale_iroh_chat_peer(
                    pending_iroh_reconnects,
                    peers_net,
                    active_incoming_iroh_transfers_net,
                    active_chat_target_did_net,
                    invite_proof_net,
                    iroh_peer_liveness_net,
                    iroh_handshake_sync_net,
                    iroh_authenticated_sessions_net,
                    peer_store_net,
                    handshake_sent,
                    config_net,
                    &peer_id,
                    &peer_did,
                    &peer_name,
                )
                .await;
                return;
            }
            match ensure_iroh_direct_chat_ready(
                &iroh_network,
                peers_net,
                config_net,
                keypair_net,
                pending_hybrid_ratchet_inits_net,
                ratchet_mgr_net,
                invite_proof_net,
                iroh_handshake_sync_net,
                ratchet_init_pub_hex_net,
                &peer_id,
                &peer_did,
                &peer_name,
            )
            .await
            {
                EnsureIrohDirectChatOutcome::Ready => {}
                EnsureIrohDirectChatOutcome::Reestablishing => return,
                EnsureIrohDirectChatOutcome::StaleTransport => {
                    iroh_network.reset_for_reconnect(&peer_id).await;
                    recover_stale_iroh_chat_peer(
                        pending_iroh_reconnects,
                        peers_net,
                        active_incoming_iroh_transfers_net,
                        active_chat_target_did_net,
                        invite_proof_net,
                        iroh_peer_liveness_net,
                        iroh_handshake_sync_net,
                        iroh_authenticated_sessions_net,
                        peer_store_net,
                        handshake_sent,
                        config_net,
                        &peer_id,
                        &peer_did,
                        &peer_name,
                    )
                    .await;
                    return;
                }
            }
            let payload =
                match encrypt_ratchet_payload(ratchet_mgr_net, &peer_did, message.as_bytes(), true)
                    .await
                {
                    Ok(payload) => payload,
                    Err(
                        RatchetPayloadError::MissingSession
                        | RatchetPayloadError::SessionNotSendReady,
                    ) => {
                        println!(
                            "   {} with {} — try again in a moment",
                            "E2EE session re-establishing".yellow().bold(),
                            peer_name.cyan()
                        );
                        return;
                    }
                    Err(_) => return,
                };
            let request = build_signed_chat_request(config_net, sign_key, payload);
            if send_iroh_request_with_timeout(&iroh_network, &peer_id, &request)
                .await
                .is_ok()
            {
                emit_headless_direct_message_event("outgoing", &peer_did, &peer_name, &message);
                println!(
                    "   {} sent to {} [direct E2EE]",
                    "Sent".green(),
                    peer_name.cyan()
                );
            } else {
                iroh_network.reset_for_reconnect(&peer_id).await;
                recover_stale_iroh_chat_peer(
                    pending_iroh_reconnects,
                    peers_net,
                    active_incoming_iroh_transfers_net,
                    active_chat_target_did_net,
                    invite_proof_net,
                    iroh_peer_liveness_net,
                    iroh_handshake_sync_net,
                    iroh_authenticated_sessions_net,
                    peer_store_net,
                    handshake_sent,
                    config_net,
                    &peer_id,
                    &peer_did,
                    &peer_name,
                )
                .await;
            }
        }
        NetworkCommand::SendChatToGroup { group_id, message } => {
            let session = {
                let registry = group_mailboxes_net.lock().await;
                registry.get_cloned(&group_id)
            };
            let Some(session) = session else {
                println!(
                    "   {} mailbox group {} is not joined. Use /groups to inspect active mailbox groups.",
                    "Error:".red().bold(),
                    group_id.cyan()
                );
                return;
            };
            let mailbox_message = match build_chat_message(
                &session,
                keypair_net,
                &message,
                config_net.security.message_ttl_ms,
            ) {
                Ok(mailbox_message) => mailbox_message,
                Err(e) => {
                    println!("   {} {}", "Group mailbox chat rejected:".red(), e);
                    return;
                }
            };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(_receipt) => {
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
                    }
                    let sender_label = if session.anonymous_group {
                        "you".to_string()
                    } else {
                        local_member_profile(&session)
                            .ok()
                            .map(|profile| {
                                display_group_member_label(
                                    Some(profile.display_name.as_str()),
                                    &profile.member_id,
                                )
                            })
                            .unwrap_or_else(|| {
                                display_group_member_label(
                                    Some(config_net.agent.name.as_str()),
                                    &config_net.agent.did,
                                )
                            })
                    };
                    println!(
                        "   {} {} {}",
                        format!("[{}]", describe_group(&session)).cyan().bold(),
                        sender_label.dimmed(),
                        message
                    );
                    let mut a = audit_net.lock().await;
                    a.record(
                        "GROUP_MAILBOX_CHAT_SEND",
                        &config_net.agent.did,
                        &format!("group_id={} transport=tor_mailbox", session.group_id),
                    );
                }
                Err(e) => {
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.note_mailbox_transport_failure(
                            &session.group_id,
                            session.mailbox_descriptor.poll_interval_ms,
                            chrono::Utc::now().timestamp_millis().max(0) as u64,
                        );
                    }
                    if mailbox_transport_error_is_unreachable(&e) {
                        println!(
                            "   {} {}",
                            "Mailbox:".yellow().bold(),
                            format!(
                                "{} host is not active right now; keep retry running in background and try again when it comes back",
                                describe_group(&session)
                            )
                            .dimmed()
                        );
                    } else {
                        println!("   {} {}", "Mailbox send failed:".red().bold(), e);
                    }
                }
            }
        }
        NetworkCommand::SendChat { message } => {
            let targets: Vec<(libp2p::PeerId, PeerInfo)> =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net)
                    .into_iter()
                    .map(|peer| (peer.peer_id, peer))
                    .collect();
            if targets.is_empty() {
                println!("   {}", "No direct peers connected yet.".red());
                return;
            }
            let mut sent_count = 0;
            for (pid, peer_info) in &targets {
                let allowed = {
                    let r = rbac_net.read().await;
                    r.can_send_to(&config_net.agent.did, &peer_info.did)
                };
                if !allowed {
                    continue;
                }
                if !iroh_network.is_connected(pid).await {
                    recover_stale_iroh_chat_peer(
                        pending_iroh_reconnects,
                        peers_net,
                        active_incoming_iroh_transfers_net,
                        active_chat_target_did_net,
                        invite_proof_net,
                        iroh_peer_liveness_net,
                        iroh_handshake_sync_net,
                        iroh_authenticated_sessions_net,
                        peer_store_net,
                        handshake_sent,
                        config_net,
                        pid,
                        &peer_info.did,
                        &peer_info.name,
                    )
                    .await;
                    continue;
                }
                match ensure_iroh_direct_chat_ready(
                    &iroh_network,
                    peers_net,
                    config_net,
                    keypair_net,
                    pending_hybrid_ratchet_inits_net,
                    ratchet_mgr_net,
                    invite_proof_net,
                    iroh_handshake_sync_net,
                    ratchet_init_pub_hex_net,
                    pid,
                    &peer_info.did,
                    &peer_info.name,
                )
                .await
                {
                    EnsureIrohDirectChatOutcome::Ready => {}
                    EnsureIrohDirectChatOutcome::Reestablishing => continue,
                    EnsureIrohDirectChatOutcome::StaleTransport => {
                        iroh_network.reset_for_reconnect(pid).await;
                        recover_stale_iroh_chat_peer(
                            pending_iroh_reconnects,
                            peers_net,
                            active_incoming_iroh_transfers_net,
                            active_chat_target_did_net,
                            invite_proof_net,
                            iroh_peer_liveness_net,
                            iroh_handshake_sync_net,
                            iroh_authenticated_sessions_net,
                            peer_store_net,
                            handshake_sent,
                            config_net,
                            pid,
                            &peer_info.did,
                            &peer_info.name,
                        )
                        .await;
                        continue;
                    }
                }
                let payload = match encrypt_ratchet_payload(
                    ratchet_mgr_net,
                    &peer_info.did,
                    message.as_bytes(),
                    true,
                )
                .await
                {
                    Ok(payload) => payload,
                    Err(
                        RatchetPayloadError::MissingSession
                        | RatchetPayloadError::SessionNotSendReady,
                    ) => continue,
                    Err(_) => continue,
                };
                let request = build_signed_chat_request(config_net, sign_key, payload);
                if send_iroh_request_with_timeout(&iroh_network, pid, &request)
                    .await
                    .is_ok()
                {
                    sent_count += 1;
                } else {
                    iroh_network.reset_for_reconnect(pid).await;
                    recover_stale_iroh_chat_peer(
                        pending_iroh_reconnects,
                        peers_net,
                        active_incoming_iroh_transfers_net,
                        active_chat_target_did_net,
                        invite_proof_net,
                        iroh_peer_liveness_net,
                        iroh_handshake_sync_net,
                        iroh_authenticated_sessions_net,
                        peer_store_net,
                        handshake_sent,
                        config_net,
                        pid,
                        &peer_info.did,
                        &peer_info.name,
                    )
                    .await;
                }
            }
            println!(
                "   {} sent to {} peer(s) [E2EE ratcheted, TTL={}ms]",
                "Sent".green(),
                sent_count.to_string().cyan(),
                config_net.security.message_ttl_ms
            );
            {
                let mut a = audit_net.lock().await;
                a.record(
                    "MSG_SEND",
                    &config_net.agent.did,
                    &format!("peers={} ratchet=true transport=iroh", sent_count),
                );
            }
        }
        _ => unreachable!("unexpected command routed to handle_iroh_chat_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer(peer_id: libp2p::PeerId, did: &str, name: &str) -> PeerInfo {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(61);
        PeerInfo {
            peer_id,
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            x25519_public_key: Some([9u8; 32]),
            kyber_public_key: Some(vec![7u8; 32]),
            verifying_key: Some([5u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([3u8; 32]),
        }
    }

    fn sample_known_peer(peer_id: &libp2p::PeerId, did: &str, name: &str) -> KnownPeer {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(62);
        KnownPeer {
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([9u8; 32])),
            verifying_key_hex: Some(hex::encode([8u8; 32])),
            kyber_public_key_hex: Some(hex::encode(vec![7u8; 32])),
            last_seen: 0,
            auto_reconnect: true,
        }
    }

    #[test]
    fn demote_stale_iroh_chat_peer_replaces_live_peer_and_preserves_active_target() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let active_target = Arc::new(Mutex::new(Some("did:nxf:agent2".to_string())));
        peers.insert(
            peer_id.to_string(),
            sample_peer(peer_id, "did:nxf:agent2", "agent2"),
        );
        set_active_prompt_target_label(Some("agent2".to_string()));

        let known = sample_known_peer(&peer_id, "did:nxf:agent2", "agent2");
        demote_stale_iroh_chat_peer(
            &peers,
            &active_target,
            &peer_id,
            "did:nxf:agent2",
            Some(&known),
        );

        let stored = peers
            .get(&peer_id.to_string())
            .expect("expected reconnecting placeholder");
        assert_eq!(stored.did, "did:nxf:agent2");
        assert!(stored.verifying_key.is_none());
        assert_eq!(
            *active_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            Some("did:nxf:agent2".to_string())
        );
        set_active_prompt_target_label(None);
    }

    #[test]
    fn demote_stale_iroh_chat_peer_removes_unknown_peer() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let active_target = Arc::new(Mutex::new(Some("did:nxf:agent2".to_string())));
        peers.insert(
            peer_id.to_string(),
            sample_peer(peer_id, "did:nxf:agent2", "agent2"),
        );

        demote_stale_iroh_chat_peer(&peers, &active_target, &peer_id, "did:nxf:agent2", None);

        assert!(peers.get(&peer_id.to_string()).is_none());
        assert_eq!(
            *active_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            None
        );
        set_active_prompt_target_label(None);
    }

    #[test]
    fn stale_iroh_chat_recovery_clears_target_for_active_incoming_transfer() {
        assert!(should_clear_selected_target_for_stale_iroh_chat_recovery(
            true
        ));
        assert!(!should_clear_selected_target_for_stale_iroh_chat_recovery(
            false
        ));
    }
}

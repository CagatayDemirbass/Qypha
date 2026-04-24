use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
use super::*;

struct Libp2pNetworkHandle<'a>(&'a mut NetworkNode);

const DIRECT_CHAT_REESTABLISH_WAIT_MS: u64 = 1_500;
const TOR_DIRECT_CHAT_BOOTSTRAP_WAIT_MS: u64 = 5_000;

fn is_expected_tor_ratchet_bootstrap_wait(error: &str) -> bool {
    error.contains("No sending chain key") && error.contains("waiting for first message from peer")
}

fn should_refresh_libp2p_direct_chat_handshake(
    transport_mode: &TransportMode,
    readiness: DirectChatReadiness,
) -> bool {
    !matches!(transport_mode, TransportMode::Tor)
        || !matches!(readiness, DirectChatReadiness::AwaitingRatchetSend)
}

fn libp2p_direct_chat_wait_timeout(
    transport_mode: &TransportMode,
    readiness: DirectChatReadiness,
) -> tokio::time::Duration {
    if matches!(transport_mode, TransportMode::Tor)
        && matches!(readiness, DirectChatReadiness::AwaitingRatchetSend)
    {
        // Tor invite/bootstrap flows can briefly reach "verified + session exists"
        // before the initiator's first ratchet message arrives and unlocks the
        // responder send chain. Avoid re-handshaking that in-flight state.
        tokio::time::Duration::from_millis(TOR_DIRECT_CHAT_BOOTSTRAP_WAIT_MS)
    } else {
        tokio::time::Duration::from_millis(DIRECT_CHAT_REESTABLISH_WAIT_MS)
    }
}

impl std::ops::Deref for Libp2pNetworkHandle<'_> {
    type Target = NetworkNode;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for Libp2pNetworkHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

async fn ensure_libp2p_direct_chat_ready(
    network: &mut NetworkNode,
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    pending_hybrid_ratchet_inits_net: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    ratchet_mgr_net: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    ratchet_init_pub_hex_net: &str,
    peer_id: &libp2p::PeerId,
    peer_did: &str,
    peer_name: &str,
) -> bool {
    let readiness = direct_chat_readiness(peers_net, ratchet_mgr_net, peer_did).await;
    if readiness == DirectChatReadiness::Ready {
        return true;
    }

    if should_refresh_libp2p_direct_chat_handshake(&config_net.network.transport_mode, readiness) {
        let (invite_code, invite_bound_override) = stored_invite_binding_parts(
            invite_proof_net
                .get(&peer_id.to_string())
                .map(|entry| entry.value().clone()),
        );
        send_handshake(
            network,
            peers_net,
            pending_hybrid_ratchet_inits_net,
            config_net,
            keypair_net,
            peer_id,
            Some(peer_did),
            ratchet_init_pub_hex_net,
            invite_code,
            invite_bound_override,
            false,
        );
    }

    if wait_for_direct_chat_ready(
        peers_net,
        ratchet_mgr_net,
        peer_did,
        libp2p_direct_chat_wait_timeout(&config_net.network.transport_mode, readiness),
    )
    .await
        == DirectChatReadiness::Ready
    {
        return true;
    }

    println!(
        "   {} with {} — try again in a moment",
        "E2EE session re-establishing".yellow().bold(),
        peer_name.cyan()
    );
    false
}

#[allow(unused_variables)]
pub(crate) async fn handle_libp2p_chat_command(
    cmd: NetworkCommand,
    state: &mut Libp2pCommandHandlerState<'_>,
    shared: &Libp2pCommandHandlerShared<'_>,
) {
    let mut network = Libp2pNetworkHandle(state.network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_chunk_transfers = &mut *state.pending_chunk_transfers;
    let pending_tor_reconnects = &mut *state.pending_tor_reconnects;
    let pending_user_chat_requests = &mut *state.pending_user_chat_requests;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let sign_key = shared.sign_key;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let rbac_net = shared.rbac_net;
    let peer_store_net = shared.peer_store_net;
    let used_invites_net = shared.used_invites_net;
    let used_invites_path_net = shared.used_invites_path_net;
    let group_mailboxes_net = shared.group_mailboxes_net;
    let mailbox_transport_net = shared.mailbox_transport_net;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let ip_hidden_net = shared.ip_hidden_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let log_mode_net = shared.log_mode_net;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    let ram_only_chunk_staging = shared.ram_only_chunk_staging;
    match cmd {
        NetworkCommand::SendRatchetBootstrap { peer_id, peer_did } => {
            let visible_peer_did = crate::agent::contact_identity::displayed_did(&peer_did);
            let payload = match encrypt_ratchet_payload(
                ratchet_mgr_net,
                &peer_did,
                RATCHET_BOOTSTRAP_MARKER,
                false,
            )
            .await
            {
                Ok(payload) => Some(payload),
                Err(RatchetPayloadError::Encrypt(e)) => {
                    if matches!(config_net.network.transport_mode, TransportMode::Tor)
                        && is_expected_tor_ratchet_bootstrap_wait(&e)
                    {
                        tracing::debug!(
                            peer = %visible_peer_did,
                            %e,
                            "Ratchet bootstrap deferred until peer sends first message"
                        );
                    } else {
                        tracing::warn!(
                            peer = %visible_peer_did,
                            %e,
                            "Ratchet bootstrap encrypt failed"
                        );
                    }
                    None
                }
                Err(RatchetPayloadError::Serialize(e)) => {
                    tracing::error!(
                        peer = %visible_peer_did,
                        %e,
                        "Ratchet bootstrap serialize failed"
                    );
                    None
                }
                Err(
                    RatchetPayloadError::MissingSession | RatchetPayloadError::SessionNotSendReady,
                ) => None,
            };

            if let Some(payload) = payload {
                let request = build_signed_chat_request(config_net, sign_key, payload);
                network
                    .swarm
                    .behaviour_mut()
                    .messaging
                    .send_request(&peer_id, request);
                tracing::debug!(peer = %visible_peer_did, "Ratchet bootstrap sent");
            }
        }
        NetworkCommand::EnsurePeerHandshake {
            peer_id,
            ack_handshake_message_id: _,
            trusted_known_peer_bootstrap,
        } => {
            let consumed_binding = invite_proof_net
                .remove(&peer_id.to_string())
                .map(|(_, code)| code);
            let (invite_code, invite_bound_override) =
                stored_invite_binding_parts(consumed_binding.clone());
            if !handshake_sent.contains(&peer_id) || invite_bound_override {
                let handshake_sent_now = send_handshake(
                    &mut network,
                    peers_net,
                    pending_hybrid_ratchet_inits_net,
                    &config_net,
                    &keypair_net,
                    &peer_id,
                    None,
                    &ratchet_init_pub_hex_net,
                    invite_code,
                    invite_bound_override,
                    trusted_known_peer_bootstrap,
                );
                advance_libp2p_invite_binding_after_handshake_send(
                    invite_proof_net,
                    &peer_id,
                    consumed_binding,
                    handshake_sent_now,
                );
                if handshake_sent_now {
                    handshake_sent.insert(peer_id);
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
            if matches!(config_net.network.transport_mode, TransportMode::Tor)
                && !network.swarm.is_connected(&peer_id)
            {
                let reconnecting_known_peer = {
                    let ps = peer_store_net.lock().await;
                    ps.get(&peer_did)
                        .cloned()
                        .filter(|known| known.onion_address.is_some())
                };
                if let Some(known) = reconnecting_known_peer.as_ref() {
                    peers_net.insert(
                        peer_id.to_string(),
                        reconnecting_iroh_placeholder(peer_id, known),
                    );
                    if should_locally_initiate_tor_reconnect(&config_net.agent.did, &known.did) {
                        queue_tor_reconnect(pending_tor_reconnects, known, true);
                    }
                }
                println!(
                    "   {} with {} — try again in a moment",
                    "Peer reconnecting".yellow().bold(),
                    peer_name.cyan()
                );
                return;
            }
            if !ensure_libp2p_direct_chat_ready(
                &mut network,
                peers_net,
                config_net,
                keypair_net,
                pending_hybrid_ratchet_inits_net,
                ratchet_mgr_net,
                invite_proof_net,
                ratchet_init_pub_hex_net,
                &peer_id,
                &peer_did,
                &peer_name,
            )
            .await
            {
                return;
            }
            let payload = match encrypt_ratchet_payload(
                ratchet_mgr_net,
                &peer_did,
                message.as_bytes(),
                true,
            )
            .await
            {
                Ok(payload) => payload,
                Err(
                    RatchetPayloadError::MissingSession | RatchetPayloadError::SessionNotSendReady,
                ) => {
                    println!(
                        "   {} with {} — try again in a moment",
                        "E2EE session re-establishing".yellow().bold(),
                        peer_name.cyan()
                    );
                    return;
                }
                Err(RatchetPayloadError::Encrypt(e)) => {
                    tracing::error!(peer = %peer_did, %e, "Ratchet encrypt failed — message NOT sent");
                    println!(
                        "   {} encrypt failed for {} — message dropped",
                        "E2EE ERROR:".red().bold(),
                        peer_name.cyan()
                    );
                    return;
                }
                Err(RatchetPayloadError::Serialize(e)) => {
                    tracing::error!(peer = %peer_did, %e, "Ratchet serialize failed — message NOT sent");
                    return;
                }
            };
            let request = build_signed_chat_request(config_net, sign_key, payload);
            let request_id = network
                .swarm
                .behaviour_mut()
                .messaging
                .send_request(&peer_id, request);
            pending_user_chat_requests.insert(
                request_id,
                PendingLibp2pUserChatRequest {
                    peer_did: peer_did.clone(),
                    peer_name: peer_name.clone(),
                },
            );
            emit_headless_direct_message_event("outgoing", &peer_did, &peer_name, &message);
            println!(
                "   {} sent to {} [direct E2EE]",
                "Sent".green(),
                peer_name.cyan()
            );
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

        // ── /send: broadcast chat ──────────────────────────
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
                    println!(
                        "   {} {} blocked by RBAC policy",
                        "Policy:".yellow().bold(),
                        peer_info.name.cyan()
                    );
                    continue;
                }
                if !ensure_libp2p_direct_chat_ready(
                    &mut network,
                    peers_net,
                    config_net,
                    keypair_net,
                    pending_hybrid_ratchet_inits_net,
                    ratchet_mgr_net,
                    invite_proof_net,
                    ratchet_init_pub_hex_net,
                    pid,
                    &peer_info.did,
                    &peer_info.name,
                )
                .await
                {
                    continue;
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
                    ) => {
                        tracing::warn!(peer = %peer_info.did, "Ratchet session not ready — message NOT sent (handshake refresh in progress)");
                        println!(
                            "   {} with {} — try again in a moment",
                            "E2EE session re-establishing".yellow().bold(),
                            peer_info.name.cyan()
                        );
                        continue;
                    }
                    Err(RatchetPayloadError::Encrypt(e)) => {
                        tracing::error!(peer = %peer_info.did, %e, "Ratchet encrypt failed — message NOT sent (no plaintext fallback)");
                        println!(
                            "   {} encrypt failed for {} — message dropped (security: no plaintext fallback)",
                            "E2EE ERROR:".red().bold(),
                            peer_info.name.cyan()
                        );
                        continue;
                    }
                    Err(RatchetPayloadError::Serialize(e)) => {
                        tracing::error!(peer = %peer_info.did, %e, "Ratchet serialize failed — message NOT sent");
                        continue;
                    }
                };

                let request = build_signed_chat_request(config_net, sign_key, payload);

                let request_id = network
                    .swarm
                    .behaviour_mut()
                    .messaging
                    .send_request(pid, request);
                pending_user_chat_requests.insert(
                    request_id,
                    PendingLibp2pUserChatRequest {
                        peer_did: peer_info.did.clone(),
                        peer_name: peer_info.name.clone(),
                    },
                );
                sent_count += 1;
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
                    &format!("peers={} ratchet=true", sent_count),
                );
            }
        }

        // ── /transfer: E2EE file send (auto-detect chunked) ─
        _ => unreachable!("unexpected command routed to handle_libp2p_chat_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_awaiting_ratchet_send_skips_handshake_refresh_and_waits_longer() {
        assert!(!should_refresh_libp2p_direct_chat_handshake(
            &TransportMode::Tor,
            DirectChatReadiness::AwaitingRatchetSend,
        ));
        assert_eq!(
            libp2p_direct_chat_wait_timeout(
                &TransportMode::Tor,
                DirectChatReadiness::AwaitingRatchetSend,
            ),
            tokio::time::Duration::from_millis(TOR_DIRECT_CHAT_BOOTSTRAP_WAIT_MS),
        );
    }

    #[test]
    fn tor_missing_session_keeps_proactive_handshake_refresh() {
        assert!(should_refresh_libp2p_direct_chat_handshake(
            &TransportMode::Tor,
            DirectChatReadiness::MissingSession,
        ));
        assert_eq!(
            libp2p_direct_chat_wait_timeout(
                &TransportMode::Tor,
                DirectChatReadiness::MissingSession
            ),
            tokio::time::Duration::from_millis(DIRECT_CHAT_REESTABLISH_WAIT_MS),
        );
    }

    #[test]
    fn non_tor_awaiting_ratchet_send_keeps_existing_refresh_behavior() {
        assert!(should_refresh_libp2p_direct_chat_handshake(
            &TransportMode::Tcp,
            DirectChatReadiness::AwaitingRatchetSend,
        ));
        assert_eq!(
            libp2p_direct_chat_wait_timeout(
                &TransportMode::Tcp,
                DirectChatReadiness::AwaitingRatchetSend,
            ),
            tokio::time::Duration::from_millis(DIRECT_CHAT_REESTABLISH_WAIT_MS),
        );
    }
}

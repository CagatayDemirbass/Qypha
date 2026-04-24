use super::iroh_event_handlers::{IrohEventHandlerShared, IrohEventHandlerState};
use super::*;

struct IrohTransportHandle<'a>(&'a mut IrohTransport);

fn should_announce_iroh_reconnect_transition(
    queued_reconnect: bool,
    removed_peer: Option<&PeerInfo>,
) -> bool {
    queued_reconnect && removed_peer.and_then(|peer| peer.verifying_key).is_some()
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

fn reconcile_iroh_peer_slot_for_connection_established(
    peers: &Arc<DashMap<String, PeerInfo>>,
    peer_id: libp2p::PeerId,
    reconnect_seed: Option<&KnownPeer>,
    requires_fresh_live_handshake: bool,
) {
    let seeded_placeholder =
        reconnect_seed.map(|known| reconnecting_iroh_placeholder(peer_id, known));
    peers
        .entry(peer_id.to_string())
        .and_modify(|peer| {
            if peer.did.is_empty() {
                if let Some(seed) = seeded_placeholder.clone() {
                    *peer = seed;
                }
            } else if requires_fresh_live_handshake {
                demote_iroh_peer_for_live_reauthentication(peer);
            }
        })
        .or_insert_with(|| {
            seeded_placeholder.unwrap_or_else(|| PeerInfo {
                peer_id,
                did: String::new(),
                name: peer_id.to_string(),
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
            })
        });
}

fn connection_established_requires_fresh_live_handshake(
    authenticated_sessions: &IrohAuthenticatedSessionMap,
    handshake_tracker: &IrohHandshakeTracker,
    liveness: &DashMap<String, IrohPeerLiveness>,
    peer_id: &libp2p::PeerId,
    stable_id: usize,
) -> bool {
    !is_authenticated_iroh_session(authenticated_sessions, peer_id, stable_id)
        && should_send_iroh_handshake_for_live_session(handshake_tracker, liveness, peer_id)
}

fn should_use_trusted_known_peer_bootstrap_for_connection_established(
    live_peer: Option<&PeerInfo>,
    requires_fresh_live_handshake: bool,
    has_existing_ratchet_session: bool,
) -> bool {
    requires_fresh_live_handshake
        && has_existing_ratchet_session
        // Trusted reconnect probes are only safe when we already authenticated this
        // peer in the current process lifetime. After a daemon restart our local
        // handshake ratchet public key rotates, so using only a persisted reconnect
        // seed here can trigger strict-mode rejects on otherwise healthy peers.
        && live_peer.is_some_and(|peer| {
            !peer.did.is_empty()
                && peer.verifying_key.is_some()
                && peer.aegis_supported
                && peer.ratchet_dh_public.is_some()
        })
}

fn should_suppress_stale_iroh_close_notice(
    removed_peer_present: bool,
    remote_offline_disconnect: bool,
) -> bool {
    !removed_peer_present && remote_offline_disconnect
}

fn should_treat_iroh_close_as_remote_offline(
    remote_offline_disconnect: bool,
    reason: Option<&str>,
) -> bool {
    remote_offline_disconnect || is_iroh_agent_shutdown_reason(reason)
}

fn should_clear_active_target_for_reconnecting_iroh_close(
    has_active_incoming_transfer: bool,
) -> bool {
    has_active_incoming_transfer
}

fn should_persist_manual_disconnect_for_iroh_close(
    locally_marked_manual_disconnect: bool,
    reason: Option<&str>,
) -> bool {
    locally_marked_manual_disconnect || is_iroh_manual_disconnect_reason(reason)
}

fn should_proactively_reject_blocked_iroh_connection(peer_id_blocked: bool) -> bool {
    peer_id_blocked
}

fn paused_incoming_transfer_status(waiting_for_reconnect: bool) -> (&'static str, &'static str) {
    if waiting_for_reconnect {
        (
            "connection lost, waiting for reconnect",
            "connection_lost_waiting_for_reconnect",
        )
    } else {
        ("sender offline", "sender_offline")
    }
}

pub(crate) fn notify_paused_incoming_iroh_transfers(
    agent_name: &str,
    transfers: &[ActiveIncomingIrohTransfer],
    waiting_for_reconnect: bool,
) {
    for transfer in transfers {
        let (status, reason) = paused_incoming_transfer_status(waiting_for_reconnect);
        print_async_notice(
            agent_name,
            format!(
                "   {} {} paused at {}/{} chunks — {}",
                "Transfer:".yellow().bold(),
                transfer.sender_name.cyan(),
                transfer.received_chunks,
                transfer.total_chunks,
                status.dimmed(),
            ),
        );
        emit_transfer_event(
            "incoming_paused",
            "in",
            Some(&transfer.sender_did),
            Some(&transfer.sender_name),
            Some(&transfer.session_id),
            None,
            Some(reason),
        );
    }
}

#[allow(unused_variables)]
pub(crate) async fn handle_iroh_connection_event(
    event: Option<IrohNetworkEvent>,
    state: &mut IrohEventHandlerState<'_>,
    shared: &IrohEventHandlerShared<'_>,
) {
    let mut iroh_network = IrohTransportHandle(state.iroh_network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_iroh_reconnects = &mut *state.pending_iroh_reconnects;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let peer_store_net = shared.peer_store_net;
    let invite_proof_net = shared.invite_proof_net;
    let incoming_connect_gate_net = shared.incoming_connect_gate_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let remote_offline_dids_net = shared.remote_offline_dids_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let iroh_peer_liveness_net = shared.iroh_peer_liveness_net;
    let iroh_handshake_sync_net = shared.iroh_handshake_sync_net;
    let iroh_authenticated_sessions_net = shared.iroh_authenticated_sessions_net;
    let active_incoming_iroh_transfers_net = shared.active_incoming_iroh_transfers_net;
    let active_chat_target_did_net = shared.active_chat_target_did_net;

    let clear_active_target = |removed_did: &str| {
        let mut cleared = false;
        if let Ok(mut target) = active_chat_target_did_net.lock() {
            if target.as_deref() == Some(removed_did) {
                *target = None;
                cleared = true;
            }
        }
        if cleared {
            set_active_prompt_target_label(None);
        }
    };

    match event {
        Some(IrohNetworkEvent::ConnectionEstablished { peer_id, stable_id }) => {
            observe_iroh_peer_connection(&iroh_peer_liveness_net, handshake_sent, &peer_id);
            let peer_id_blocked = {
                let gate = incoming_connect_gate_net.lock().await;
                gate.is_peer_id_blocked(&peer_id.to_string())
            };
            if should_proactively_reject_blocked_iroh_connection(peer_id_blocked) {
                let notice = build_disconnect_notice_request(
                    &keypair_net.signing_key,
                    &config_net,
                    DisconnectNoticeKind::ManualDisconnect,
                );
                let _ = iroh_network.send_request(&peer_id, &notice).await;
                peers_net.remove(&peer_id.to_string());
                invite_proof_net.remove(&peer_id.to_string());
                iroh_peer_liveness_net.remove(&peer_id.to_string());
                clear_iroh_handshake_tracking(handshake_sent, &peer_id);
                clear_iroh_handshake_sync(iroh_handshake_sync_net, &peer_id);
                clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &peer_id);
                iroh_network.disconnect_with_propagation(&peer_id).await;
                tracing::info!(
                    peer_id = %peer_id,
                    "iroh connection rejected using persisted manual-disconnect peer-id binding"
                );
                return;
            }
            let requires_fresh_live_handshake =
                connection_established_requires_fresh_live_handshake(
                    iroh_authenticated_sessions_net,
                    handshake_sent,
                    &iroh_peer_liveness_net,
                    &peer_id,
                    stable_id,
                );
            let reconnect_seed = {
                let ps = peer_store_net.lock().await;
                known_peer_for_live_peer_id(&ps, &peer_id)
            };
            if let Some(seed) = reconnect_seed.as_ref() {
                pending_iroh_reconnects.remove(&seed.did);
            }
            reconcile_iroh_peer_slot_for_connection_established(
                peers_net,
                peer_id,
                reconnect_seed.as_ref(),
                requires_fresh_live_handshake,
            );
            let bootstrap_peer_did = reconnect_seed
                .as_ref()
                .map(|seed| seed.did.clone())
                .or_else(|| {
                    peers_net
                        .get(&peer_id.to_string())
                        .and_then(|peer| (!peer.did.is_empty()).then(|| peer.did.clone()))
                });
            let has_existing_ratchet_session = if let Some(peer_did) = bootstrap_peer_did.as_deref()
            {
                let ratchet_mgr = shared.ratchet_mgr_net.lock().await;
                ratchet_mgr.has_session(peer_did)
            } else {
                false
            };
            let trusted_known_peer_bootstrap =
                should_use_trusted_known_peer_bootstrap_for_connection_established(
                    peers_net.get(&peer_id.to_string()).as_deref(),
                    requires_fresh_live_handshake,
                    has_existing_ratchet_session,
                );
            if should_auto_send_iroh_handshake(&peer_id, &peers_net, &invite_proof_net)
                && requires_fresh_live_handshake
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
                    None,
                    trusted_known_peer_bootstrap,
                )
                .await
                {
                    invite_proof_net.remove(&peer_id.to_string());
                    record_iroh_handshake_sent(handshake_sent, &iroh_peer_liveness_net, &peer_id);
                    note_iroh_handshake_message_sent(
                        iroh_handshake_sync_net,
                        &peer_id,
                        &message_id,
                    );
                }
            }
        }

        Some(IrohNetworkEvent::ConnectionClosed {
            peer_id,
            stable_id,
            reason,
        }) => {
            iroh_peer_liveness_net.remove(&peer_id.to_string());
            clear_iroh_authenticated_session_if_matches(
                iroh_authenticated_sessions_net,
                &peer_id,
                stable_id,
            );
            let known_peer = {
                let ps = peer_store_net.lock().await;
                known_peer_for_live_peer_id(&ps, &peer_id)
            };
            let removed_peer = peers_net
                .remove(&peer_id.to_string())
                .map(|(_, removed)| removed);
            let removed_did = removed_peer
                .as_ref()
                .map(|p| p.did.clone())
                .or_else(|| known_peer.as_ref().map(|p| p.did.clone()))
                .unwrap_or_default();
            let removed_name = removed_peer
                .as_ref()
                .map(|p| p.name.clone())
                .or_else(|| known_peer.as_ref().map(|p| p.name.clone()))
                .unwrap_or_else(|| peer_id.to_string());
            let visible_removed_did = crate::agent::contact_identity::displayed_did(&removed_did);
            invite_proof_net.remove(&peer_id.to_string());
            clear_iroh_handshake_tracking(handshake_sent, &peer_id);
            clear_iroh_handshake_sync(iroh_handshake_sync_net, &peer_id);
            let manual_disconnect = if !removed_did.is_empty() {
                let manual = manual_disconnect_dids_net.lock().await;
                manual.contains(&removed_did)
            } else {
                false
            };
            let remote_offline_disconnect = if !removed_did.is_empty() {
                let offline = remote_offline_dids_net.lock().await;
                offline.contains(&removed_did)
            } else {
                false
            };
            let remote_offline_close = should_treat_iroh_close_as_remote_offline(
                remote_offline_disconnect,
                reason.as_deref(),
            );
            let controlled_disconnect = is_iroh_controlled_disconnect_reason(reason.as_deref());
            let persist_manual_disconnect = should_persist_manual_disconnect_for_iroh_close(
                manual_disconnect,
                reason.as_deref(),
            );

            let reconnect_candidate =
                if !manual_disconnect && !controlled_disconnect && !removed_did.is_empty() {
                    let mut ps = peer_store_net.lock().await;
                    let persisted = ps.get(&removed_did).cloned();
                    let live_authenticated = removed_peer
                        .as_ref()
                        .and_then(known_peer_from_authenticated_live_iroh_peer);
                    let candidate = persisted
                        .clone()
                        .or(live_authenticated.clone())
                        .filter(|kp| kp.iroh_endpoint_addr.is_some());
                    if persisted.is_none() {
                        if let Some(candidate) = candidate.as_ref() {
                            let log_mode = LogMode::try_from_str(&config_net.logging.mode)
                                .unwrap_or(LogMode::Safe);
                            if should_persist_known_peer(&log_mode, None, true) {
                                ps.upsert(candidate.clone());
                            }
                        }
                    }
                    candidate
                } else {
                    None
                };
            let paused_incoming_transfers = if removed_did.is_empty() {
                Vec::new()
            } else {
                mark_active_incoming_iroh_transfers_paused(
                    active_incoming_iroh_transfers_net,
                    &removed_did,
                )
            };
            let has_active_incoming_transfer = !removed_did.is_empty()
                && has_active_incoming_iroh_transfer_for_sender(
                    active_incoming_iroh_transfers_net,
                    &removed_did,
                );
            let suppress_stale_close_notice = should_suppress_stale_iroh_close_notice(
                removed_peer.is_some(),
                remote_offline_disconnect,
            );

            if let Some(kp) = reconnect_candidate
                .clone()
                .filter(|_| !remote_offline_close)
            {
                peers_net.insert(
                    peer_id.to_string(),
                    reconnecting_iroh_placeholder(peer_id, &kp),
                );
                let queued_reconnect = queue_iroh_reconnect(pending_iroh_reconnects, &kp, false);
                let announce_reconnect = should_announce_iroh_reconnect_transition(
                    queued_reconnect,
                    removed_peer.as_ref(),
                );
                if queued_reconnect {
                    emit_headless_direct_peer_event(
                        "reconnecting",
                        &kp.did,
                        &kp.name,
                        Some(&peer_id.to_string()),
                        "reconnecting",
                        Some("auto_reconnect"),
                    );
                }
                if should_clear_active_target_for_reconnecting_iroh_close(
                    has_active_incoming_transfer,
                ) {
                    clear_active_target(&removed_did);
                }
                tracing::debug!(
                    peer = %removed_name,
                    did = %visible_removed_did,
                    close_reason = reason.as_deref().unwrap_or("unknown"),
                    "iroh connection closed unexpectedly — reconnecting"
                );
                if announce_reconnect {
                    print_async_notice(
                        &config_net.agent.name,
                        format!(
                            "   {} {}",
                            "Reconnecting:".yellow().bold(),
                            removed_name.cyan(),
                        ),
                    );
                }
                notify_paused_incoming_iroh_transfers(
                    &config_net.agent.name,
                    &paused_incoming_transfers,
                    true,
                );
            } else {
                if suppress_stale_close_notice {
                    tracing::debug!(
                        peer = %removed_name,
                        did = %visible_removed_did,
                        close_reason = reason.as_deref().unwrap_or("unknown"),
                        "ignoring stale iroh close after remote offline notice"
                    );
                } else if remote_offline_close && !removed_did.is_empty() {
                    if let Some(kp) = reconnect_candidate.as_ref() {
                        queue_iroh_reconnect(pending_iroh_reconnects, kp, false);
                    }
                    notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &removed_did,
                        &removed_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("agent_offline"),
                    );
                    clear_active_target(&removed_did);
                    print_async_notice(
                        &config_net.agent.name,
                        format!("   {} {}", "Offline:".yellow().bold(), removed_name.cyan(),),
                    );
                    tracing::info!(
                        peer = %removed_name,
                        did = %visible_removed_did,
                        close_reason = reason.as_deref().unwrap_or("unknown"),
                        "iroh peer closed after remote offline notice"
                    );
                } else if controlled_disconnect && !removed_did.is_empty() {
                    if persist_manual_disconnect {
                        {
                            let mut manual = manual_disconnect_dids_net.lock().await;
                            manual.insert(removed_did.clone());
                        }
                        {
                            let mut ps = peer_store_net.lock().await;
                            ps.remove(&removed_did);
                        }
                        pending_iroh_reconnects.remove(&removed_did);
                    }
                    notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    if manual_disconnect {
                        tracing::debug!(
                            peer = %removed_name,
                            did = %visible_removed_did,
                            close_reason = reason.as_deref().unwrap_or("unknown"),
                            "iroh controlled disconnect already accounted for by local/manual policy"
                        );
                    } else {
                        emit_headless_direct_peer_event(
                            "disconnected",
                            &removed_did,
                            &removed_name,
                            Some(&peer_id.to_string()),
                            "offline",
                            Some("remote_disconnect"),
                        );
                        clear_active_target(&removed_did);
                        print_async_notice(
                            &config_net.agent.name,
                            format!(
                                "   {} {}",
                                "Disconnected:".yellow().bold(),
                                format!("{} closed the session", removed_name).cyan()
                            ),
                        );
                        tracing::info!(
                            peer = %removed_name,
                            did = %visible_removed_did,
                            close_reason = reason.as_deref().unwrap_or("unknown"),
                            "iroh session closed by peer"
                        );
                    }
                } else if !manual_disconnect && !removed_did.is_empty() {
                    notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &removed_did,
                        &removed_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("connection_lost"),
                    );
                    clear_active_target(&removed_did);
                    print_async_notice(
                        &config_net.agent.name,
                        format!("   {} {}", "Offline:".yellow().bold(), removed_name.cyan(),),
                    );
                    tracing::warn!(
                        peer = %removed_name,
                        did = %visible_removed_did,
                        close_reason = reason.as_deref().unwrap_or("unknown"),
                        "iroh peer dropped without reconnect path"
                    );
                } else if controlled_disconnect && removed_did.is_empty() {
                    tracing::debug!(
                        peer = %peer_id,
                        close_reason = reason.as_deref().unwrap_or("unknown"),
                        "suppressing unidentified controlled disconnect close after local/manual policy"
                    );
                } else {
                    // Manual disconnect — show to user.
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &removed_did,
                        &removed_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("manual_disconnect"),
                    );
                    clear_active_target(&removed_did);
                    print_async_notice(
                        &config_net.agent.name,
                        format!(
                            "   {} {}{}",
                            "Disconnected:".red().bold(),
                            removed_name.cyan(),
                            if removed_did.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", visible_removed_did.dimmed())
                            }
                        ),
                    );
                }
            }
            {
                let mut a = audit_net.lock().await;
                a.record("PEER_DISCONNECT", &peer_id.to_string(), "iroh");
            }
        }

        _ => unreachable!("unexpected iroh event routed to connection handler"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verified_peer(peer_id: libp2p::PeerId) -> PeerInfo {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(81);
        PeerInfo {
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
        }
    }

    #[test]
    fn reconnect_notice_only_announces_for_authenticated_live_peer() {
        let peer_id = libp2p::PeerId::random();
        let mut authenticated = sample_verified_peer(peer_id);
        assert!(should_announce_iroh_reconnect_transition(
            true,
            Some(&authenticated)
        ));

        authenticated.verifying_key = None;
        assert!(!should_announce_iroh_reconnect_transition(
            true,
            Some(&authenticated)
        ));
        assert!(!should_announce_iroh_reconnect_transition(true, None));
        assert!(!should_announce_iroh_reconnect_transition(false, None));
    }

    #[test]
    fn duplicate_established_event_keeps_existing_verified_peer_slot() {
        let peers = Arc::new(DashMap::new());
        let peer_id = libp2p::PeerId::random();
        peers.insert(peer_id.to_string(), sample_verified_peer(peer_id));

        reconcile_iroh_peer_slot_for_connection_established(&peers, peer_id, None, false);

        let peer = peers.get(&peer_id.to_string()).expect("expected peer");
        assert!(peer.verifying_key.is_some());
        assert!(peer.aegis_supported);
        assert!(peer.ratchet_dh_public.is_some());
    }

    #[test]
    fn fresh_live_session_demotes_authenticated_peer_slot_until_handshake() {
        let peers = Arc::new(DashMap::new());
        let peer_id = libp2p::PeerId::random();
        peers.insert(peer_id.to_string(), sample_verified_peer(peer_id));

        reconcile_iroh_peer_slot_for_connection_established(&peers, peer_id, None, true);

        let peer = peers.get(&peer_id.to_string()).expect("expected peer");
        assert!(peer.verifying_key.is_none());
        assert!(!peer.aegis_supported);
        assert!(peer.ratchet_dh_public.is_none());
        assert!(peer.x25519_public_key.is_some());
        assert!(peer.kyber_public_key.is_some());
    }

    #[test]
    fn authenticated_live_session_is_not_reopened_by_late_established_event() {
        let authenticated_sessions = IrohAuthenticatedSessionMap::new();
        let liveness = DashMap::new();
        let mut handshake_tracker = IrohHandshakeTracker::new();
        let peer_id = libp2p::PeerId::random();
        let stable_id = 42usize;

        observe_iroh_peer_connection(&liveness, &mut handshake_tracker, &peer_id);
        assert!(connection_established_requires_fresh_live_handshake(
            &authenticated_sessions,
            &handshake_tracker,
            &liveness,
            &peer_id,
            stable_id,
        ));

        note_iroh_authenticated_session(&authenticated_sessions, &peer_id, stable_id);
        assert!(!connection_established_requires_fresh_live_handshake(
            &authenticated_sessions,
            &handshake_tracker,
            &liveness,
            &peer_id,
            stable_id,
        ));
    }

    #[test]
    fn persisted_reconnect_seed_does_not_enable_trusted_bootstrap_probe() {
        let peer_id = libp2p::PeerId::random();
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(84);
        let known = KnownPeer {
            did: "did:nxf:known".to_string(),
            name: "known-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([7u8; 32])),
            verifying_key_hex: Some(hex::encode([6u8; 32])),
            kyber_public_key_hex: Some(hex::encode([8u8; 32])),
            last_seen: 0,
            auto_reconnect: true,
        };

        assert!(
            !should_use_trusted_known_peer_bootstrap_for_connection_established(None, true, true)
        );
        assert!(
            !should_use_trusted_known_peer_bootstrap_for_connection_established(None, false, true,)
        );
        assert!(
            !should_use_trusted_known_peer_bootstrap_for_connection_established(None, true, false,)
        );
        assert_eq!(known.did, "did:nxf:known");
    }

    #[test]
    fn established_event_seeds_known_peer_placeholder_for_blank_live_slot() {
        let peers = Arc::new(DashMap::new());
        let peer_id = libp2p::PeerId::random();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: String::new(),
                name: peer_id.to_string(),
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
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(85);
        let known = KnownPeer {
            did: "did:nxf:known".to_string(),
            name: "known-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json.clone()),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([7u8; 32])),
            verifying_key_hex: Some(hex::encode([6u8; 32])),
            kyber_public_key_hex: Some(hex::encode([8u8; 32])),
            last_seen: 0,
            auto_reconnect: true,
        };

        reconcile_iroh_peer_slot_for_connection_established(&peers, peer_id, Some(&known), true);

        let peer = peers
            .get(&peer_id.to_string())
            .expect("expected seeded peer");
        assert_eq!(peer.did, known.did);
        assert_eq!(peer.name, known.name);
        assert_eq!(
            peer.iroh_endpoint_addr.as_deref(),
            Some(endpoint_json.as_str())
        );
        assert_eq!(peer.x25519_public_key, Some([7u8; 32]));
        assert_eq!(
            peer.kyber_public_key.as_deref(),
            Some(vec![8u8; 32].as_slice())
        );
        assert!(peer.verifying_key.is_none());
        assert!(!peer.aegis_supported);
        assert!(peer.ratchet_dh_public.is_none());
    }

    #[test]
    fn existing_known_live_slot_enables_trusted_bootstrap_probe() {
        let peer_id = libp2p::PeerId::random();
        let peer = sample_verified_peer(peer_id);

        assert!(
            should_use_trusted_known_peer_bootstrap_for_connection_established(
                Some(&peer),
                true,
                true,
            )
        );

        let mut blank = peer.clone();
        blank.did.clear();
        assert!(
            !should_use_trusted_known_peer_bootstrap_for_connection_established(
                Some(&blank),
                true,
                true,
            )
        );

        let mut missing_ratchet = peer.clone();
        missing_ratchet.ratchet_dh_public = None;
        assert!(
            !should_use_trusted_known_peer_bootstrap_for_connection_established(
                Some(&missing_ratchet),
                true,
                true,
            )
        );
    }

    #[test]
    fn stale_remote_offline_close_notice_is_suppressed() {
        assert!(should_suppress_stale_iroh_close_notice(false, true));
        assert!(!should_suppress_stale_iroh_close_notice(true, true));
        assert!(!should_suppress_stale_iroh_close_notice(false, false));
    }

    #[test]
    fn agent_shutdown_close_is_treated_as_remote_offline() {
        assert!(should_treat_iroh_close_as_remote_offline(
            false,
            Some("stream closed: qypha-agent-shutdown"),
        ));
        assert!(should_treat_iroh_close_as_remote_offline(true, None));
        assert!(!should_treat_iroh_close_as_remote_offline(
            false,
            Some("stream closed: transient-network-loss"),
        ));
    }

    #[test]
    fn reconnecting_close_clears_active_target_for_paused_incoming_transfer() {
        assert!(should_clear_active_target_for_reconnecting_iroh_close(true));
        assert!(!should_clear_active_target_for_reconnecting_iroh_close(
            false
        ));
    }

    #[test]
    fn only_explicit_manual_iroh_close_persists_disconnect_policy() {
        assert!(should_persist_manual_disconnect_for_iroh_close(
            true,
            Some("stream closed: qypha-policy-disconnect"),
        ));
        assert!(should_persist_manual_disconnect_for_iroh_close(
            false,
            Some("stream closed: qypha-manual-disconnect"),
        ));
        assert!(!should_persist_manual_disconnect_for_iroh_close(
            false,
            Some("stream closed: qypha-policy-disconnect"),
        ));
    }

    #[test]
    fn proactively_rejects_only_peer_id_blocked_connections() {
        assert!(should_proactively_reject_blocked_iroh_connection(true));
        assert!(!should_proactively_reject_blocked_iroh_connection(false));
    }

    #[test]
    fn paused_incoming_transfer_status_distinguishes_reconnect_from_offline() {
        assert_eq!(
            paused_incoming_transfer_status(true),
            (
                "connection lost, waiting for reconnect",
                "connection_lost_waiting_for_reconnect",
            )
        );
        assert_eq!(
            paused_incoming_transfer_status(false),
            ("sender offline", "sender_offline")
        );
    }
}

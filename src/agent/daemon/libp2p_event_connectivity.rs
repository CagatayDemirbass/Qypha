use super::libp2p_event_handlers::{Libp2pEventHandlerShared, Libp2pEventHandlerState};
use super::*;

struct Libp2pNetworkHandle<'a>(&'a mut NetworkNode);

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

const TOR_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS: u64 = 20;
const TOR_PASSIVE_RECONNECT_FALLBACK_DELAY_SECS: u64 = 12;
const TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_DELAY_SECS: u64 = 5;
const TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS: u64 = 10;

fn reconnecting_tor_transfer_placeholder(
    peer_id: libp2p::PeerId,
    pending_chunk_transfers: &HashMap<String, PendingChunkTransfer>,
) -> Option<PeerInfo> {
    let mut candidates = pending_chunk_transfers
        .values()
        .filter(|transfer| transfer.reconnecting && !transfer.peer_did.is_empty());
    let transfer = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }

    Some(PeerInfo {
        peer_id,
        did: transfer.peer_did.clone(),
        name: transfer.peer_name.clone(),
        role: DEFAULT_AGENT_ROLE.to_string(),
        onion_address: transfer.peer_onion.clone(),
        tcp_address: None,
        iroh_endpoint_addr: None,
        onion_port: transfer.peer_onion_port,
        x25519_public_key: Some(transfer.x25519_pk),
        kyber_public_key: transfer.kyber_pk.clone(),
        verifying_key: None,
        aegis_supported: false,
        ratchet_dh_public: None,
    })
}

fn known_peer_from_pending_tor_transfer(transfer: &PendingChunkTransfer) -> Option<KnownPeer> {
    let onion_address = transfer
        .peer_onion
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()?;

    Some(KnownPeer {
        did: transfer.peer_did.clone(),
        name: transfer.peer_name.clone(),
        role: DEFAULT_AGENT_ROLE.to_string(),
        peer_id: transfer.peer_id.to_string(),
        onion_address: Some(onion_address),
        tcp_address: None,
        iroh_endpoint_addr: None,
        onion_port: transfer.peer_onion_port,
        encryption_public_key_hex: Some(hex::encode(transfer.x25519_pk)),
        verifying_key_hex: None,
        kyber_public_key_hex: transfer.kyber_pk.as_ref().map(hex::encode),
        last_seen: 0,
        auto_reconnect: true,
    })
}

fn tor_bridge_port_from_connected_point(endpoint: &libp2p::core::ConnectedPoint) -> Option<u16> {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => {
            address.iter().find_map(|protocol| match protocol {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
        }
        _ => None,
    }
}

fn take_tor_dial_seed_for_endpoint(
    endpoint: &libp2p::core::ConnectedPoint,
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
) -> Option<KnownPeer> {
    let bridge_port = tor_bridge_port_from_connected_point(endpoint)?;
    pending_tor_dial_seeds.remove(&bridge_port)
}

fn pause_tor_transfer_for_remote_offline(
    pending_chunk_transfers: &mut HashMap<String, PendingChunkTransfer>,
    pending_tor_reconnects: &mut HashMap<String, PendingTorReconnect>,
    peer_id: &libp2p::PeerId,
) -> Option<(String, String, usize)> {
    let pct = pending_chunk_transfers.get_mut(&peer_id.to_string())?;
    if !pct.peer_did.is_empty() {
        pending_tor_reconnects.remove(&pct.peer_did);
    }
    pct.reconnecting = false;
    pct.inflight_request = None;
    pct.bridge_warming = false;
    pct.chunk_jitter_until = None;
    pct.reconnect_wait_secs = 0;
    pct.backoff_until = Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(3));
    Some((
        pct.peer_name.clone(),
        pct.peer_did.clone(),
        pct.next_chunk + 1,
    ))
}

fn clear_selected_libp2p_chat_target(
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

fn should_auto_send_handshake_on_connection_established(
    peer_id: &libp2p::PeerId,
    peers: &DashMap<String, PeerInfo>,
    invite_proofs: &DashMap<String, String>,
    handshake_sent: &HashSet<libp2p::PeerId>,
    sent_pending_tor_direct_contact_request: bool,
) -> bool {
    !sent_pending_tor_direct_contact_request
        && !handshake_sent.contains(peer_id)
        && should_auto_send_live_handshake(peer_id, peers, invite_proofs)
}

fn should_send_trusted_tor_reconnect_probe(
    transport_mode: &TransportMode,
    endpoint: &libp2p::core::ConnectedPoint,
    resolved_did: Option<&str>,
    live_peer: Option<&PeerInfo>,
    has_existing_ratchet_session: bool,
) -> bool {
    matches!(transport_mode, TransportMode::Tor)
        && matches!(endpoint, libp2p::core::ConnectedPoint::Dialer { .. })
        && resolved_did.is_some_and(|did| !did.trim().is_empty())
        && has_existing_ratchet_session
        && live_peer.is_some_and(|peer| {
            !peer.did.trim().is_empty()
                && peer.verifying_key.is_some()
                && peer.aegis_supported
                && peer.ratchet_dh_public.is_some()
        })
}

fn should_proactively_reject_blocked_libp2p_connection(peer_id_blocked: bool) -> bool {
    peer_id_blocked
}

fn resolved_tor_connection_did(
    existing_did: Option<&str>,
    reconnect_seed: Option<&KnownPeer>,
    transfer_seed: Option<&PeerInfo>,
    tor_dial_seed: Option<&KnownPeer>,
) -> Option<String> {
    existing_did
        .map(str::trim)
        .filter(|did| !did.is_empty())
        .map(str::to_string)
        .or_else(|| reconnect_seed.map(|known| known.did.clone()))
        .or_else(|| {
            transfer_seed
                .map(|peer| peer.did.trim())
                .filter(|did| !did.is_empty())
                .map(str::to_string)
        })
        .or_else(|| tor_dial_seed.map(|known| known.did.clone()))
}

fn should_proactively_reject_manual_disconnect_tor_connection(
    peer_did: Option<&str>,
    manual_disconnect_dids: &HashSet<String>,
) -> bool {
    peer_did.is_some_and(|did| manual_disconnect_dids.contains(did))
}

#[allow(unused_variables)]
pub(crate) async fn handle_libp2p_connectivity_event(
    event: libp2p::swarm::SwarmEvent<crate::network::node::AgentBehaviourEvent>,
    state: &mut Libp2pEventHandlerState<'_>,
    shared: &Libp2pEventHandlerShared<'_>,
) {
    use libp2p::request_response;
    use libp2p::swarm::SwarmEvent;

    let mut network = Libp2pNetworkHandle(state.network);
    let handshake_sent = &mut *state.handshake_sent;
    let dialing = &mut *state.dialing;
    let pending_chunk_transfers = &mut *state.pending_chunk_transfers;
    let pending_tor_reconnects = &mut *state.pending_tor_reconnects;
    let pending_tor_dial_seeds = &mut *state.pending_tor_dial_seeds;
    let pending_tor_direct_contact_requests = &mut *state.pending_tor_direct_contact_requests;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let peer_store_net = shared.peer_store_net;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let remote_offline_dids_net = shared.remote_offline_dids_net;
    let incoming_connect_gate_net = shared.incoming_connect_gate_net;
    let cmd_tx_net = shared.cmd_tx_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let msg_tx = shared.msg_tx;
    let active_recv_for_swarm = shared.active_recv_for_swarm;
    let active_incoming_iroh_transfers_net = shared.active_incoming_iroh_transfers_net;
    let active_chat_target_did_net = shared.active_chat_target_did_net;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;

    match event {
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Mdns(
            libp2p::mdns::Event::Discovered(peers),
        )) => {
            let our_port_suffix = format!("/tcp/{}", config_net.network.listen_port);
            for (peer_id, addr) in peers {
                // Skip: ourselves, already connected, already dialing,
                // or stale mDNS record pointing at our own listen port
                let addr_str = addr.to_string();
                let is_our_port = addr_str.contains(&our_port_suffix);
                if peer_id != our_peer_id
                    && !is_our_port
                    && !network.swarm.is_connected(&peer_id)
                    && !dialing.contains(&peer_id)
                {
                    dialing.insert(peer_id);
                    match network.swarm.dial(addr.clone()) {
                        Ok(()) => tracing::info!(%peer_id, %addr, "mDNS discovered, dialing..."),
                        Err(e) => {
                            dialing.remove(&peer_id);
                            tracing::error!(%peer_id, %addr, "Dial failed: {}", e);
                            println!(
                                "\n   {} {} (peer {})",
                                "Dial failed:".red().bold(),
                                e,
                                &peer_id.to_string()[..12]
                            );
                        }
                    }
                } else if is_our_port && peer_id != our_peer_id {
                    tracing::debug!(%peer_id, %addr, "Ignoring stale mDNS record (our port)");
                }
            }
        }

        // ── mDNS: peer expired → remove ghost if disconnected ──
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Mdns(
            libp2p::mdns::Event::Expired(peers),
        )) => {
            for (peer_id, _) in peers {
                if !network.swarm.is_connected(&peer_id) {
                    peers_net.remove(&peer_id.to_string());
                    handshake_sent.remove(&peer_id);
                    tracing::info!(%peer_id, "Ghost peer removed");
                }
            }
        }

        // ── Ping: keep-alive (handled silently) ──────────────
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Ping(_)) => {
            // Ping keep-alive handled by libp2p automatically
        }

        // ── Connection established → placeholder + handshake ──
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            dialing.remove(&peer_id);
            tracing::info!(%peer_id, "TCP connection established");
            if peer_id != our_peer_id {
                let peer_id_blocked = {
                    let gate = incoming_connect_gate_net.lock().await;
                    gate.is_peer_id_blocked(&peer_id.to_string())
                };
                if should_proactively_reject_blocked_libp2p_connection(peer_id_blocked) {
                    let _ = cmd_tx_net
                        .send(NetworkCommand::DisconnectPeerWithNotice {
                            peer_id,
                            notice_kind: DisconnectNoticeKind::ManualDisconnect,
                        })
                        .await;
                    tracing::info!(
                        peer_id = %peer_id,
                        "Tor connection rejected using persisted manual-disconnect peer-id binding"
                    );
                    return;
                }
                let existing_did = peers_net
                    .get(&peer_id.to_string())
                    .map(|peer| peer.did.clone())
                    .filter(|did| !did.is_empty());
                if let Some(existing_did) = existing_did.as_ref() {
                    pending_tor_reconnects.remove(existing_did);
                }
                let reconnect_seed = {
                    let ps = peer_store_net.lock().await;
                    known_peer_for_live_peer_id(&ps, &peer_id)
                };
                if let Some(seed) = reconnect_seed.as_ref() {
                    pending_tor_reconnects.remove(&seed.did);
                }
                let transfer_seed =
                    if matches!(endpoint, libp2p::core::ConnectedPoint::Dialer { .. })
                        && matches!(config_net.network.transport_mode, TransportMode::Tor)
                    {
                        reconnecting_tor_transfer_placeholder(peer_id, pending_chunk_transfers)
                    } else {
                        None
                    };
                if let Some(seed) = transfer_seed.as_ref() {
                    pending_tor_reconnects.remove(&seed.did);
                }
                let tor_dial_seed =
                    if matches!(config_net.network.transport_mode, TransportMode::Tor)
                        && matches!(endpoint, libp2p::core::ConnectedPoint::Dialer { .. })
                    {
                        take_tor_dial_seed_for_endpoint(&endpoint, pending_tor_dial_seeds)
                    } else {
                        None
                    };
                if let Some(seed) = tor_dial_seed.as_ref() {
                    pending_tor_reconnects.remove(&seed.did);
                }
                let resolved_did = resolved_tor_connection_did(
                    existing_did.as_deref(),
                    reconnect_seed.as_ref(),
                    transfer_seed.as_ref(),
                    tor_dial_seed.as_ref(),
                );
                let reject_for_manual_disconnect = {
                    let manual = manual_disconnect_dids_net.lock().await;
                    should_proactively_reject_manual_disconnect_tor_connection(
                        resolved_did.as_deref(),
                        &manual,
                    )
                };
                if reject_for_manual_disconnect {
                    if let Some(did) = resolved_did.as_ref() {
                        pending_tor_reconnects.remove(did);
                        direct_peer_dids_net.remove(did);
                    }
                    let _ = cmd_tx_net
                        .send(NetworkCommand::DisconnectPeerWithNotice {
                            peer_id,
                            notice_kind: DisconnectNoticeKind::ManualDisconnect,
                        })
                        .await;
                    tracing::info!(
                        peer_id = %peer_id,
                        did = %resolved_did.clone().unwrap_or_default(),
                        "Tor connection rejected using manual-disconnect DID tombstone"
                    );
                    return;
                }
                let seeded_placeholder = reconnect_seed
                    .as_ref()
                    .map(|known| reconnecting_iroh_placeholder(peer_id, known));
                let seeded_placeholder = seeded_placeholder.or(transfer_seed).or_else(|| {
                    tor_dial_seed
                        .as_ref()
                        .map(|known| reconnecting_iroh_placeholder(peer_id, known))
                });
                match peers_net.entry(peer_id.to_string()) {
                    dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                        if entry.get().did.is_empty() {
                            if let Some(seed) = seeded_placeholder.clone() {
                                *entry.get_mut() = seed;
                            }
                        }
                    }
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(seeded_placeholder.unwrap_or_else(|| PeerInfo {
                            peer_id,
                            did: String::new(),
                            name: peer_id.to_string(),
                            role: DEFAULT_AGENT_ROLE.to_string(),
                            onion_address: None,
                            tcp_address: None,
                            iroh_endpoint_addr: None,
                            onion_port: 9090,
                            x25519_public_key: None,
                            kyber_public_key: None,
                            verifying_key: None,
                            aegis_supported: false,
                            ratchet_dh_public: None,
                        }));
                    }
                }

                let sent_pending_tor_direct_contact_request =
                    if let Some(seed) = tor_dial_seed.as_ref() {
                        send_pending_tor_direct_contact_request_for_did(
                            &mut network,
                            pending_tor_direct_contact_requests,
                            audit_net,
                            &config_net.agent.did,
                            &peer_id,
                            &seed.did,
                        )
                        .await
                    } else {
                        false
                    };
                let live_peer_snapshot =
                    peers_net.get(&peer_id.to_string()).map(|peer| peer.clone());
                let has_existing_ratchet_session = if let Some(peer_did) = resolved_did.as_deref() {
                    let ratchet_mgr = ratchet_mgr_net.lock().await;
                    ratchet_mgr.has_session(peer_did)
                } else {
                    false
                };
                let trusted_tor_reconnect_probe = should_send_trusted_tor_reconnect_probe(
                    &config_net.network.transport_mode,
                    &endpoint,
                    resolved_did.as_deref(),
                    live_peer_snapshot.as_ref(),
                    has_existing_ratchet_session,
                );

                // Send handshake to new peer (works for all modes including Relay —
                // circuit relay is transparent at transport layer)
                if should_auto_send_handshake_on_connection_established(
                    &peer_id,
                    peers_net,
                    invite_proof_net,
                    handshake_sent,
                    sent_pending_tor_direct_contact_request,
                ) {
                    let consumed_binding = invite_proof_net
                        .remove(&peer_id.to_string())
                        .map(|(_, code)| code);
                    let (invite_code, invite_bound_override) =
                        stored_invite_binding_parts(consumed_binding.clone());
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
                        trusted_tor_reconnect_probe,
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
        }

        // ── Connection closed → auto re-dial if active transfer ──
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            if num_established > 0 {
                tracing::debug!(
                    %peer_id,
                    remaining = num_established,
                    "Connection closed but another Tor/libp2p session is still established"
                );
                return;
            }
            if matches!(config_net.network.transport_mode, TransportMode::Tor) {
                tracing::debug!(%peer_id, "Connection closed");
            } else {
                tracing::warn!(%peer_id, "Connection closed");
            }
            invite_proof_net.remove(&peer_id.to_string());

            // Check if this peer has an active chunk transfer.
            let peer_key = peer_id.to_string();
            let is_transfer_peer = pending_chunk_transfers.contains_key(&peer_key);

            if is_transfer_peer {
                // ── Active transfer: spawn non-blocking Tor re-dial ──
                // Tor circuit died (normal after ~10-25 min).
                // Spawn a background task to create new bridge + dial.
                // This avoids blocking the select! loop for 10-30s.
                // Silent reconnect — no user-visible noise.
                tracing::debug!("Tor circuit dropped — reconnecting");
                {
                    #[allow(unused_imports)]
                    use std::io::Write;
                }
                handshake_sent.remove(&peer_id);

                let mut transfer_pause_notice: Option<(String, usize)> = None;
                let known_peer = {
                    let persisted = {
                        let ps = peer_store_net.lock().await;
                        ps.all_peers()
                            .into_iter()
                            .find(|kp| kp.peer_id == peer_id.to_string())
                            .cloned()
                    };
                    if persisted.is_some() {
                        persisted
                    } else {
                        pending_chunk_transfers
                            .get(&peer_key)
                            .and_then(|pct| known_peer_from_pending_tor_transfer(&pct))
                    }
                };
                let transfer_peer_did = known_peer
                    .as_ref()
                    .map(|known| known.did.clone())
                    .or_else(|| {
                        pending_chunk_transfers
                            .get(&peer_key)
                            .map(|pct| pct.peer_did.clone())
                    })
                    .unwrap_or_default();
                let remote_offline_disconnect = if !transfer_peer_did.is_empty() {
                    let offline = remote_offline_dids_net.lock().await;
                    offline.contains(&transfer_peer_did)
                } else {
                    false
                };
                let paused_incoming_transfers = if transfer_peer_did.is_empty() {
                    Vec::new()
                } else {
                    mark_active_incoming_iroh_transfers_paused(
                        active_incoming_iroh_transfers_net,
                        &transfer_peer_did,
                    )
                };

                if remote_offline_disconnect {
                    dialing.remove(&peer_id);
                    let paused_transfer = pause_tor_transfer_for_remote_offline(
                        pending_chunk_transfers,
                        pending_tor_reconnects,
                        &peer_id,
                    );
                    let peer_name = paused_transfer
                        .as_ref()
                        .map(|(name, _, _)| name.clone())
                        .or_else(|| known_peer.as_ref().map(|known| known.name.clone()))
                        .unwrap_or_else(|| peer_id.to_string());
                    peers_net.remove(&peer_id.to_string());
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &transfer_peer_did,
                        &peer_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("agent_offline"),
                    );
                    super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    clear_selected_libp2p_chat_target(
                        active_chat_target_did_net,
                        &transfer_peer_did,
                    );
                    if let Some(kp) = known_peer.as_ref() {
                        queue_tor_reconnect_for_local_role(
                            pending_tor_reconnects,
                            kp,
                            &config_net.agent.did,
                            tokio::time::Duration::from_secs(
                                TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_DELAY_SECS,
                            ),
                            tokio::time::Duration::from_secs(
                                TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS,
                            ),
                            true,
                        );
                    }
                    if let Some((paused_peer_name, _, chunk_number)) = paused_transfer {
                        print_async_notice(
                            &config_net.agent.name,
                            format!(
                                "   {} {} paused during chunk {} — {}",
                                "Transfer:".yellow().bold(),
                                paused_peer_name.cyan(),
                                chunk_number.to_string().dimmed(),
                                "peer went offline".dimmed(),
                            ),
                        );
                    }
                } else {
                    // Mark transfer as reconnecting (prevents OutboundFailure from aborting)
                    if let Some(pct) = pending_chunk_transfers.get_mut(&peer_key) {
                        let first_reconnect_transition = !pct.reconnecting;
                        pct.reconnecting = true;
                        pct.inflight_request = None; // old request is dead
                        pct.backoff_until = Some(
                            tokio::time::Instant::now() + tokio::time::Duration::from_secs(30),
                        );
                        // wait for re-dial
                        if first_reconnect_transition {
                            transfer_pause_notice =
                                Some((pct.peer_name.clone(), pct.next_chunk + 1));
                        }
                    }

                    if let Some(kp) = known_peer.as_ref() {
                        peers_net.insert(
                            peer_id.to_string(),
                            reconnecting_iroh_placeholder(peer_id, kp),
                        );
                        queue_tor_reconnect_for_local_role(
                            pending_tor_reconnects,
                            kp,
                            &config_net.agent.did,
                            tokio::time::Duration::from_secs(
                                TOR_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS,
                            ),
                            tokio::time::Duration::from_secs(
                                TOR_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS
                                    + TOR_PASSIVE_RECONNECT_FALLBACK_DELAY_SECS,
                            ),
                            false,
                        );
                        if let Some((peer_name, chunk_number)) = transfer_pause_notice.as_ref() {
                            emit_headless_direct_peer_event(
                                "reconnecting",
                                &kp.did,
                                peer_name,
                                Some(&peer_id.to_string()),
                                "reconnecting",
                                Some("transfer_reconnect"),
                            );
                            print_async_notice(
                                &config_net.agent.name,
                                format!(
                                    "   {} {} paused during chunk {} — {}",
                                    "Transfer:".yellow().bold(),
                                    peer_name.cyan(),
                                    chunk_number.to_string().dimmed(),
                                    "reconnecting".dimmed(),
                                ),
                            );
                        }
                    }

                    if let Some(kp) = known_peer {
                        if let Some(onion_addr) = kp.onion_address.clone() {
                            if !should_locally_initiate_tor_reconnect(
                                &config_net.agent.did,
                                &kp.did,
                            ) {
                                tracing::debug!(
                                    peer = %kp.name,
                                    did = %kp.did,
                                    "Tor transfer reconnect will wait for the deterministic remote dialer"
                                );
                            } else {
                                let onion_port = kp.onion_port;
                                let peer_did = kp.did.clone();
                                if let Some(ref tor_mgr) = network.tor_manager {
                                    // Spawn re-dial as background task with retry
                                    let tor_mgr_clone = Arc::clone(tor_mgr);
                                    let redial_tx = cmd_tx_net.clone();
                                    let redial_peer_id = peer_id.clone();
                                    tokio::spawn(async move {
                                        const MAX_REDIAL_ATTEMPTS: usize = 3;
                                        for attempt in 1..=MAX_REDIAL_ATTEMPTS {
                                            tracing::info!(
                                                attempt,
                                                max = MAX_REDIAL_ATTEMPTS,
                                                "Tor re-dial attempt"
                                            );
                                            match tor_bridge::create_tor_bridge_isolated(
                                                &tor_mgr_clone,
                                                &onion_addr,
                                                onion_port,
                                                Some(&peer_did),
                                            )
                                            .await
                                            {
                                                Ok(bridge_port) => {
                                                    // Send re-dial command back to main loop
                                                    let _ = redial_tx
                                                        .send(NetworkCommand::TorRedial {
                                                            peer_id: redial_peer_id.clone(),
                                                            peer_did: peer_did.clone(),
                                                            bridge_port,
                                                        })
                                                        .await;
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::debug!(
                                                        attempt,
                                                        %e,
                                                        "Tor re-dial failed, retrying..."
                                                    );
                                                    if attempt < MAX_REDIAL_ATTEMPTS {
                                                        tokio::time::sleep(
                                                            tokio::time::Duration::from_secs(
                                                                5 * attempt as u64,
                                                            ),
                                                        )
                                                        .await;
                                                    }
                                                }
                                            }
                                        }
                                        // All attempts failed — send failure signal
                                        let _ = redial_tx
                                            .send(NetworkCommand::TorRedialFailed {
                                                peer_id: redial_peer_id,
                                                peer_did,
                                            })
                                            .await;
                                    });
                                } else {
                                    peers_net.remove(&peer_id.to_string());
                                    if let Some(pct) = pending_chunk_transfers.get_mut(&peer_key) {
                                        pct.reconnecting = false;
                                    }
                                }
                            }
                        } else {
                            tracing::debug!(peer = %peer_id, "no onion address — cannot auto-reconnect");
                            peers_net.remove(&peer_id.to_string());
                            if let Some(pct) = pending_chunk_transfers.get_mut(&peer_key) {
                                pct.reconnecting = false;
                            }
                        }
                    } else {
                        tracing::debug!(peer = %peer_id, "no onion address — cannot auto-reconnect");
                        peers_net.remove(&peer_id.to_string());
                        if let Some(pct) = pending_chunk_transfers.get_mut(&peer_key) {
                            pct.reconnecting = false;
                        }
                    }
                    if pending_chunk_transfers
                        .get(&peer_key)
                        .is_some_and(|pct| !pct.reconnecting)
                    {
                        super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                            &config_net.agent.name,
                            &paused_incoming_transfers,
                            false,
                        );
                        clear_selected_libp2p_chat_target(
                            active_chat_target_did_net,
                            &transfer_peer_did,
                        );
                    } else {
                        super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                            &config_net.agent.name,
                            &paused_incoming_transfers,
                            true,
                        );
                    }
                }
            } else {
                // No active transfer — check if this was a manual
                // disconnect or an unexpected connection drop.
                dialing.remove(&peer_id);

                let known_peer = {
                    let ps = peer_store_net.lock().await;
                    known_peer_for_live_peer_id(&ps, &peer_id)
                };
                let peer_did = peers_net
                    .get(&peer_id.to_string())
                    .map(|p| p.did.clone())
                    .or_else(|| known_peer.as_ref().map(|kp| kp.did.clone()))
                    .unwrap_or_default();
                let peer_name = peers_net
                    .get(&peer_id.to_string())
                    .map(|p| p.name.clone())
                    .or_else(|| known_peer.as_ref().map(|kp| kp.name.clone()))
                    .unwrap_or_else(|| peer_id.to_string());

                let manually_disconnected = if !peer_did.is_empty() {
                    let manual = manual_disconnect_dids_net.lock().await;
                    manual.contains(&peer_did)
                } else {
                    false
                };
                let remotely_offline = if !peer_did.is_empty() {
                    let offline = remote_offline_dids_net.lock().await;
                    offline.contains(&peer_did)
                } else {
                    false
                };
                let paused_incoming_transfers = if peer_did.is_empty() {
                    Vec::new()
                } else {
                    mark_active_incoming_iroh_transfers_paused(
                        active_incoming_iroh_transfers_net,
                        &peer_did,
                    )
                };

                if remotely_offline {
                    if let Some(kp) = known_peer.as_ref() {
                        queue_tor_reconnect_for_local_role(
                            pending_tor_reconnects,
                            kp,
                            &config_net.agent.did,
                            tokio::time::Duration::from_secs(
                                TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_DELAY_SECS,
                            ),
                            tokio::time::Duration::from_secs(
                                TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS,
                            ),
                            true,
                        );
                    }
                    peers_net.remove(&peer_id.to_string());
                    handshake_sent.remove(&peer_id);
                    super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    clear_selected_libp2p_chat_target(active_chat_target_did_net, &peer_did);
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &peer_did,
                        &peer_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("agent_offline"),
                    );
                    println!("\n   {} {}", "Offline:".yellow().bold(), peer_name.cyan());
                } else if manually_disconnected {
                    // User explicitly disconnected — clean up fully.
                    pending_tor_reconnects.remove(&peer_did);
                    peers_net.remove(&peer_id.to_string());
                    handshake_sent.remove(&peer_id);
                    super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        false,
                    );
                    clear_selected_libp2p_chat_target(active_chat_target_did_net, &peer_did);
                    emit_headless_direct_peer_event(
                        "disconnected",
                        &peer_did,
                        &peer_name,
                        Some(&peer_id.to_string()),
                        "offline",
                        Some("manual_disconnect"),
                    );
                    println!(
                        "\n   {} {}",
                        "Peer disconnected:".red().bold(),
                        peer_id.to_string().dimmed()
                    );
                } else {
                    // Unexpected drop (network hiccup, NAT rebind, etc.)
                    // Demote the live peer slot immediately so the REPL stops
                    // treating this peer as authenticated/online, then queue
                    // transport recovery in the background.
                    handshake_sent.remove(&peer_id);
                    let mut waiting_for_reconnect = false;
                    if let Some(kp) = known_peer {
                        if matches!(config_net.network.transport_mode, TransportMode::Tor)
                            && kp.onion_address.is_some()
                        {
                            peers_net.insert(
                                peer_id.to_string(),
                                reconnecting_iroh_placeholder(peer_id, &kp),
                            );
                            let queued_reconnect = queue_tor_reconnect_for_local_role(
                                pending_tor_reconnects,
                                &kp,
                                &config_net.agent.did,
                                tokio::time::Duration::ZERO,
                                tokio::time::Duration::from_secs(
                                    TOR_PASSIVE_RECONNECT_FALLBACK_DELAY_SECS,
                                ),
                                true,
                            );
                            waiting_for_reconnect = true;
                            emit_headless_direct_peer_event(
                                "reconnecting",
                                &kp.did,
                                &kp.name,
                                Some(&peer_id.to_string()),
                                "reconnecting",
                                Some("auto_reconnect"),
                            );
                            tracing::debug!(
                                peer = %kp.name,
                                did = %kp.did,
                                queued_reconnect,
                                "Tor connection dropped — queued background reconnect"
                            );
                            print_async_notice(
                                &config_net.agent.name,
                                format!(
                                    "   {} {} — {}",
                                    "Connection lost:".yellow().bold(),
                                    kp.name.cyan(),
                                    "reconnecting in background".dimmed(),
                                ),
                            );
                        } else if let Some(ref onion_addr) = kp.onion_address {
                            if let Some(ref tor_mgr) = network.tor_manager {
                                if !should_locally_initiate_tor_reconnect(
                                    &config_net.agent.did,
                                    &kp.did,
                                ) {
                                    waiting_for_reconnect = true;
                                    peers_net.insert(
                                        peer_id.to_string(),
                                        reconnecting_iroh_placeholder(peer_id, &kp),
                                    );
                                } else {
                                    waiting_for_reconnect = true;
                                    emit_headless_direct_peer_event(
                                        "reconnecting",
                                        &kp.did,
                                        &kp.name,
                                        Some(&peer_id.to_string()),
                                        "reconnecting",
                                        Some("auto_reconnect"),
                                    );
                                    let tor_mgr_clone = Arc::clone(tor_mgr);
                                    let onion = onion_addr.clone();
                                    let port = kp.onion_port;
                                    let did = kp.did.clone();
                                    let redial_tx = cmd_tx_net.clone();
                                    let redial_peer_id = peer_id;
                                    tracing::debug!("connection dropped — auto-reconnecting");
                                    tokio::spawn(async move {
                                        for attempt in 1..=3u64 {
                                            match tor_bridge::create_tor_bridge_isolated(
                                                &tor_mgr_clone,
                                                &onion,
                                                port,
                                                Some(&did),
                                            )
                                            .await
                                            {
                                                Ok(bridge_port) => {
                                                    let _ = redial_tx
                                                        .send(NetworkCommand::TorRedial {
                                                            peer_id: redial_peer_id,
                                                            peer_did: did.clone(),
                                                            bridge_port,
                                                        })
                                                        .await;
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::debug!(
                                                        attempt,
                                                        %e,
                                                        "auto-reconnect retry failed"
                                                    );
                                                    if attempt < 3 {
                                                        tokio::time::sleep(
                                                            tokio::time::Duration::from_secs(
                                                                5 * attempt,
                                                            ),
                                                        )
                                                        .await;
                                                    }
                                                }
                                            }
                                        }
                                        tracing::debug!("auto-reconnect exhausted all attempts");
                                    });
                                }
                            } else if let Some(ref addr) = kp.tcp_address {
                                waiting_for_reconnect = true;
                                emit_headless_direct_peer_event(
                                    "reconnecting",
                                    &kp.did,
                                    &kp.name,
                                    Some(&peer_id.to_string()),
                                    "reconnecting",
                                    Some("auto_reconnect"),
                                );
                                if let Ok(multiaddr) = addr.parse::<libp2p::Multiaddr>() {
                                    tracing::debug!("connection dropped — re-dialing via TCP");
                                    let _ = network.swarm.dial(multiaddr);
                                }
                            }
                        } else if let Some(ref addr) = kp.tcp_address {
                            // No onion but has TCP address — direct re-dial
                            waiting_for_reconnect = true;
                            emit_headless_direct_peer_event(
                                "reconnecting",
                                &kp.did,
                                &kp.name,
                                Some(&peer_id.to_string()),
                                "reconnecting",
                                Some("auto_reconnect"),
                            );
                            if let Ok(multiaddr) = addr.parse::<libp2p::Multiaddr>() {
                                tracing::debug!("connection dropped — re-dialing");
                                let _ = network.swarm.dial(multiaddr);
                            }
                        } else {
                            // No known address to reconnect — fall through
                            peers_net.remove(&peer_id.to_string());
                            clear_selected_libp2p_chat_target(
                                active_chat_target_did_net,
                                &peer_did,
                            );
                            emit_headless_direct_peer_event(
                                "disconnected",
                                &peer_did,
                                &kp.name,
                                Some(&peer_id.to_string()),
                                "offline",
                                Some("connection_lost"),
                            );
                            tracing::debug!(peer = %peer_id, "peer lost — no reconnect address");
                        }
                    } else {
                        // Unknown peer — clean up
                        peers_net.remove(&peer_id.to_string());
                        clear_selected_libp2p_chat_target(active_chat_target_did_net, &peer_did);
                        emit_headless_direct_peer_event(
                            "disconnected",
                            &peer_did,
                            &peer_id.to_string(),
                            Some(&peer_id.to_string()),
                            "offline",
                            Some("connection_lost"),
                        );
                    }
                    super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                        &config_net.agent.name,
                        &paused_incoming_transfers,
                        waiting_for_reconnect,
                    );
                }
            }
            {
                let mut a = audit_net.lock().await;
                a.record("PEER_DISCONNECT", &peer_id.to_string(), "");
            }
        }

        // ── Incoming message ─────────────────────────────────
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!(%address, "Listening on");
        }

        // ── Request-Response: outbound success ──
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            // If we're already connected to this peer, this is just a
            // duplicate dial (mDNS race) — log debug, don't alarm the user.
            let already_connected = peer_id
                .map(|p| network.swarm.is_connected(&p))
                .unwrap_or(false);

            if already_connected {
                tracing::debug!(?peer_id, %error, "Duplicate dial failed (already connected)");
            } else {
                tracing::error!(?peer_id, %error, "Outgoing connection failed");
                println!(
                    "\n   {} {} ({})",
                    "Connection failed:".red().bold(),
                    error,
                    peer_id
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );
                print_prompt(&config_net.agent.name);
            }
            // Clean up stale state
            if let Some(pid) = peer_id {
                dialing.remove(&pid);
                if !already_connected {
                    peers_net.remove(&pid.to_string());
                    handshake_sent.remove(&pid);
                }
            }
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            tracing::debug!(%error, "Incoming connection attempt failed");
        }
        _ => unreachable!("unexpected libp2p event routed to connectivity handler"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn sample_reconnecting_transfer(
        peer_id: libp2p::PeerId,
        peer_did: &str,
        peer_name: &str,
    ) -> PendingChunkTransfer {
        let sender = AgentKeyPair::generate("sender", "agent");
        let (session, chunks) = chunked_transfer::prepare_session(
            &sender,
            peer_did,
            "payload.bin",
            "confidential",
            b"hello world over tor transfer",
            4,
        )
        .expect("sample transfer session");
        PendingChunkTransfer {
            peer_id,
            peer_name: peer_name.to_string(),
            peer_did: peer_did.to_string(),
            session,
            chunk_source: ChunkSource::InMemory(chunks),
            next_chunk: 2,
            chunk_size: 4,
            x25519_pk: [7u8; 32],
            kyber_pk: Some(vec![8u8; 32]),
            ttl: 0,
            path: "/tmp/payload.bin".to_string(),
            packed_mb: 0.0,
            packed_size: 27,
            inflight_request: None,
            retry_count: 0,
            backoff_until: None,
            reconnect_wait_secs: 45,
            reconnecting: true,
            last_bridge_at: tokio::time::Instant::now(),
            bridge_warming: false,
            peer_onion: Some("peerexample123.onion".to_string()),
            peer_onion_port: 9090,
            chunk_jitter_until: None,
            awaiting_receiver_accept: false,
            awaiting_started_at: tokio::time::Instant::now(),
            needs_reinit: false,
        }
    }

    #[test]
    fn tor_transfer_placeholder_uses_single_reconnecting_transfer_hint() {
        let old_peer_id = libp2p::PeerId::random();
        let new_peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            old_peer_id.to_string(),
            sample_reconnecting_transfer(old_peer_id, "did:nxf:tor-peer", "tor-peer"),
        );

        let placeholder = reconnecting_tor_transfer_placeholder(new_peer_id, &pending)
            .expect("expected reconnect hint placeholder");
        assert_eq!(placeholder.peer_id, new_peer_id);
        assert_eq!(placeholder.did, "did:nxf:tor-peer");
        assert_eq!(placeholder.name, "tor-peer");
        assert_eq!(placeholder.x25519_public_key, Some([7u8; 32]));
        assert_eq!(placeholder.kyber_public_key, Some(vec![8u8; 32]));
        assert_eq!(
            placeholder.onion_address.as_deref(),
            Some("peerexample123.onion")
        );
    }

    #[test]
    fn pending_tor_direct_contact_request_suppresses_initial_auto_handshake() {
        let peer_id = libp2p::PeerId::random();
        let peers = DashMap::new();
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: "did:nxf:first-contact".to_string(),
                name: "first-contact".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                onion_address: Some("peerexample123.onion".to_string()),
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
        let invite_proofs = DashMap::new();
        let handshake_sent = HashSet::new();

        assert!(!should_auto_send_handshake_on_connection_established(
            &peer_id,
            &peers,
            &invite_proofs,
            &handshake_sent,
            true,
        ));
        assert!(should_auto_send_handshake_on_connection_established(
            &peer_id,
            &peers,
            &invite_proofs,
            &handshake_sent,
            false,
        ));
    }

    #[test]
    fn trusted_tor_reconnect_probe_requires_trusted_live_session() {
        let dialer = libp2p::core::ConnectedPoint::Dialer {
            address: "/ip4/127.0.0.1/tcp/12345".parse().expect("valid multiaddr"),
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::Reuse,
        };
        let listener = libp2p::core::ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/12346".parse().expect("valid multiaddr"),
            send_back_addr: "/ip4/127.0.0.1/tcp/12347".parse().expect("valid multiaddr"),
        };
        let trusted_peer = PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: "did:nxf:peer".to_string(),
            name: "peer".to_string(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            onion_address: Some("peer.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: Some([7u8; 32]),
            kyber_public_key: Some(vec![8u8; 32]),
            verifying_key: Some([9u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([10u8; 32]),
        };
        let mut untrusted_peer = trusted_peer.clone();
        untrusted_peer.ratchet_dh_public = None;

        assert!(should_send_trusted_tor_reconnect_probe(
            &TransportMode::Tor,
            &dialer,
            Some("did:nxf:peer"),
            Some(&trusted_peer),
            true,
        ));
        assert!(!should_send_trusted_tor_reconnect_probe(
            &TransportMode::Tor,
            &listener,
            Some("did:nxf:peer"),
            Some(&trusted_peer),
            true,
        ));
        assert!(!should_send_trusted_tor_reconnect_probe(
            &TransportMode::Tor,
            &dialer,
            None,
            Some(&trusted_peer),
            true,
        ));
        assert!(!should_send_trusted_tor_reconnect_probe(
            &TransportMode::Internet,
            &dialer,
            Some("did:nxf:peer"),
            Some(&trusted_peer),
            true,
        ));
        assert!(!should_send_trusted_tor_reconnect_probe(
            &TransportMode::Tor,
            &dialer,
            Some("did:nxf:peer"),
            Some(&untrusted_peer),
            true,
        ));
        assert!(!should_send_trusted_tor_reconnect_probe(
            &TransportMode::Tor,
            &dialer,
            Some("did:nxf:peer"),
            Some(&trusted_peer),
            false,
        ));
    }

    #[test]
    fn blocked_peer_id_binding_proactively_rejects_tor_connection() {
        assert!(should_proactively_reject_blocked_libp2p_connection(true));
        assert!(!should_proactively_reject_blocked_libp2p_connection(false));
    }

    #[test]
    fn resolved_tor_connection_did_prefers_existing_then_reconnect_then_transfer_then_dial_seed() {
        let reconnect_seed = KnownPeer {
            did: "did:nxf:reconnect".to_string(),
            name: "reconnect".to_string(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("reconnect.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: true,
        };
        let transfer_peer = PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: "did:nxf:transfer".to_string(),
            name: "transfer".to_string(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            onion_address: Some("transfer.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: None,
            verifying_key: None,
            aegis_supported: false,
            ratchet_dh_public: None,
        };
        let dial_seed = KnownPeer {
            did: "did:nxf:dial".to_string(),
            name: "dial".to_string(),
            role: DEFAULT_AGENT_ROLE.to_string(),
            peer_id: libp2p::PeerId::random().to_string(),
            onion_address: Some("dial.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: true,
        };

        assert_eq!(
            resolved_tor_connection_did(
                Some("did:nxf:existing"),
                Some(&reconnect_seed),
                Some(&transfer_peer),
                Some(&dial_seed),
            )
            .as_deref(),
            Some("did:nxf:existing")
        );
        assert_eq!(
            resolved_tor_connection_did(None, Some(&reconnect_seed), Some(&transfer_peer), None)
                .as_deref(),
            Some("did:nxf:reconnect")
        );
        assert_eq!(
            resolved_tor_connection_did(None, None, Some(&transfer_peer), Some(&dial_seed))
                .as_deref(),
            Some("did:nxf:transfer")
        );
        assert_eq!(
            resolved_tor_connection_did(None, None, None, Some(&dial_seed)).as_deref(),
            Some("did:nxf:dial")
        );
    }

    #[test]
    fn manual_disconnect_tor_connection_rejects_when_resolved_did_is_tombstoned() {
        let manual_disconnects = HashSet::from(["did:nxf:peer".to_string()]);

        assert!(should_proactively_reject_manual_disconnect_tor_connection(
            Some("did:nxf:peer"),
            &manual_disconnects,
        ));
        assert!(!should_proactively_reject_manual_disconnect_tor_connection(
            Some("did:nxf:other"),
            &manual_disconnects,
        ));
        assert!(!should_proactively_reject_manual_disconnect_tor_connection(
            None,
            &manual_disconnects,
        ));
    }

    #[test]
    fn tor_transfer_placeholder_rejects_ambiguous_reconnect_hints() {
        let first_peer_id = libp2p::PeerId::random();
        let second_peer_id = libp2p::PeerId::random();
        let new_peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            first_peer_id.to_string(),
            sample_reconnecting_transfer(first_peer_id, "did:nxf:first", "first"),
        );
        pending.insert(
            second_peer_id.to_string(),
            sample_reconnecting_transfer(second_peer_id, "did:nxf:second", "second"),
        );

        assert!(reconnecting_tor_transfer_placeholder(new_peer_id, &pending).is_none());
    }

    #[test]
    fn known_peer_from_pending_tor_transfer_preserves_reconnect_metadata() {
        let peer_id = libp2p::PeerId::random();
        let pending = sample_reconnecting_transfer(peer_id, "did:nxf:tor-peer", "tor-peer");

        let known =
            known_peer_from_pending_tor_transfer(&pending).expect("expected reconnect seed");
        assert_eq!(known.did, "did:nxf:tor-peer");
        assert_eq!(known.name, "tor-peer");
        assert_eq!(known.peer_id, peer_id.to_string());
        assert_eq!(known.onion_address.as_deref(), Some("peerexample123.onion"));
        assert_eq!(
            known.encryption_public_key_hex,
            Some(hex::encode([7u8; 32]))
        );
        assert_eq!(known.kyber_public_key_hex, Some(hex::encode(vec![8u8; 32])));
    }

    #[test]
    fn remote_offline_pauses_tor_transfer_without_reconnect() {
        let peer_id = libp2p::PeerId::random();
        let mut pending_transfers = HashMap::new();
        let mut pending_reconnects = HashMap::new();
        pending_transfers.insert(
            peer_id.to_string(),
            sample_reconnecting_transfer(peer_id, "did:nxf:tor-peer", "tor-peer"),
        );

        let known = KnownPeer {
            did: "did:nxf:tor-peer".to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("peerexample123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([7u8; 32])),
            verifying_key_hex: None,
            kyber_public_key_hex: Some(hex::encode(vec![8u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };
        assert!(queue_tor_reconnect(&mut pending_reconnects, &known, true));

        let paused = pause_tor_transfer_for_remote_offline(
            &mut pending_transfers,
            &mut pending_reconnects,
            &peer_id,
        )
        .expect("expected paused transfer");

        assert_eq!(
            paused,
            ("tor-peer".to_string(), "did:nxf:tor-peer".to_string(), 3,)
        );
        assert!(!pending_reconnects.contains_key("did:nxf:tor-peer"));

        let transfer = pending_transfers
            .get(&peer_id.to_string())
            .expect("transfer should remain resumable");
        assert!(!transfer.reconnecting);
        assert!(transfer.inflight_request.is_none());
        assert!(!transfer.bridge_warming);
        assert!(transfer.chunk_jitter_until.is_none());
        assert_eq!(transfer.reconnect_wait_secs, 0);
        assert!(transfer.backoff_until.is_some());
    }

    #[test]
    fn paused_incoming_tor_transfer_keeps_background_reconnect_hint_after_remote_offline() {
        let peer_id = libp2p::PeerId::random();
        let sender_did = "did:nxf:tor-peer";
        let mut pending_reconnects = HashMap::new();
        let transfers = DashMap::new();
        transfers.insert(
            "sess-1".to_string(),
            ActiveIncomingIrohTransfer {
                session_id: "sess-1".to_string(),
                sender_did: sender_did.to_string(),
                sender_name: "tor-peer".to_string(),
                total_chunks: 83,
                received_chunks: 6,
                last_progress_at: tokio::time::Instant::now(),
                pause_notified: true,
            },
        );
        let known = KnownPeer {
            did: sender_did.to_string(),
            name: "tor-peer".to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: Some("peerexample123.onion".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([7u8; 32])),
            verifying_key_hex: None,
            kyber_public_key_hex: Some(hex::encode(vec![8u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };

        assert!(has_active_incoming_iroh_transfer_for_sender(
            &transfers, sender_did
        ));
        assert!(queue_tor_reconnect_for_local_role(
            &mut pending_reconnects,
            &known,
            "did:nxf:receiver",
            tokio::time::Duration::from_secs(TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_DELAY_SECS),
            tokio::time::Duration::from_secs(
                TOR_REMOTE_OFFLINE_TRANSFER_RECONNECT_FALLBACK_DELAY_SECS
            ),
            true,
        ));
        assert!(pending_reconnects.contains_key(sender_did));
    }

    #[test]
    fn remote_offline_sender_transfer_context_preserves_pending_transfer_state() {
        let peer_id = libp2p::PeerId::random();
        let mut pending_transfers = HashMap::new();
        let transfers = DashMap::new();
        pending_transfers.insert(
            peer_id.to_string(),
            sample_reconnecting_transfer(peer_id, "did:nxf:tor-peer", "tor-peer"),
        );

        assert!(has_pending_chunk_transfer_for_peer_did(
            &pending_transfers,
            "did:nxf:tor-peer",
        ));
        assert!(!has_pending_chunk_transfer_for_peer_did(
            &pending_transfers,
            "did:nxf:other",
        ));
        assert!(!has_active_incoming_iroh_transfer_for_sender(
            &transfers,
            "did:nxf:tor-peer",
        ));
    }

    #[test]
    fn clear_selected_libp2p_chat_target_clears_matching_peer() {
        let active_target = Arc::new(Mutex::new(Some("did:nxf:sender".to_string())));

        clear_selected_libp2p_chat_target(&active_target, "did:nxf:sender");

        assert!(active_target.lock().unwrap().is_none());
    }

    #[test]
    fn tor_dial_seed_is_consumed_by_bridge_port() {
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
            verifying_key_hex: None,
            kyber_public_key_hex: Some(hex::encode([7u8; 32])),
            last_seen: 1,
            auto_reconnect: true,
        };
        let mut pending = HashMap::new();
        pending.insert(43123, known.clone());
        let endpoint = libp2p::core::ConnectedPoint::Dialer {
            address: "/ip4/127.0.0.1/tcp/43123"
                .parse()
                .expect("valid bridge address"),
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::Reuse,
        };

        let recovered = take_tor_dial_seed_for_endpoint(&endpoint, &mut pending)
            .expect("expected dial seed for bridge port");
        assert_eq!(recovered.did, known.did);
        assert!(pending.is_empty());
        assert!(take_tor_dial_seed_for_endpoint(&endpoint, &mut pending).is_none());
    }
}

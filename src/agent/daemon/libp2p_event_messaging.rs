use super::libp2p_event_handlers::{Libp2pEventHandlerShared, Libp2pEventHandlerState};
use super::*;

struct Libp2pNetworkHandle<'a>(&'a mut NetworkNode);
const TOR_USER_CHAT_TIMEOUT_RECONNECT_FALLBACK_DELAY_SECS: u64 = 12;

fn should_surface_libp2p_outbound_failure(tracked_user_chat_request: bool) -> bool {
    tracked_user_chat_request
}

fn is_libp2p_user_chat_timeout(error: &libp2p::request_response::OutboundFailure) -> bool {
    error
        .to_string()
        .contains("Timeout while waiting for a response")
}

fn should_demote_tor_user_chat_timeout(peer_connected: bool) -> bool {
    !peer_connected
}

fn is_expected_manual_disconnect_ack_race(
    error: &libp2p::request_response::OutboundFailure,
) -> bool {
    matches!(
        error,
        libp2p::request_response::OutboundFailure::ConnectionClosed
    )
}

fn drain_pending_user_chat_requests_for_did(
    pending_user_chat_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        PendingLibp2pUserChatRequest,
    >,
    peer_did: &str,
) {
    pending_user_chat_requests.retain(|_, request| request.peer_did != peer_did);
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

#[allow(unused_variables)]
pub(crate) async fn handle_libp2p_messaging_event(
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
    let pending_disconnect_notices = &mut *state.pending_disconnect_notices;
    let pending_tor_reconnects = &mut *state.pending_tor_reconnects;
    let pending_user_chat_requests = &mut *state.pending_user_chat_requests;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let peer_store_net = shared.peer_store_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let cmd_tx_net = shared.cmd_tx_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let msg_tx = shared.msg_tx;
    let active_recv_for_swarm = shared.active_recv_for_swarm;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;

    match event {
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            let request_is_handshake =
                request.msg_type == crate::network::protocol::MessageKind::Handshake;
            let _ = msg_tx
                .send(crate::network::IncomingRequestEnvelope {
                    peer_id: peer,
                    request,
                    iroh_stable_id: None,
                    iroh_active_session: None,
                })
                .await;

            let _ = network.swarm.behaviour_mut().messaging.send_response(
                channel,
                crate::network::protocol::AgentResponse {
                    success: true,
                    message: "OK".to_string(),
                },
            );

            // Do not proactively answer inbound handshake frames here.
            // The incoming worker needs to verify the signed payload and
            // persist the peer's live crypto capabilities first; otherwise
            // invite-bound strict mode can race and emit an early response
            // without the peer's Kyber/ratchet state.
            if !request_is_handshake
                && !handshake_sent.contains(&peer)
                && should_auto_send_live_handshake(&peer, peers_net, invite_proof_net)
            {
                let consumed_binding = invite_proof_net
                    .remove(&peer.to_string())
                    .map(|(_, code)| code);
                let (invite_code, invite_bound_override) =
                    stored_invite_binding_parts(consumed_binding.clone());
                let handshake_sent_now = send_handshake(
                    &mut network,
                    peers_net,
                    pending_hybrid_ratchet_inits_net,
                    &config_net,
                    &keypair_net,
                    &peer,
                    None,
                    &ratchet_init_pub_hex_net,
                    invite_code,
                    invite_bound_override,
                    false,
                );
                advance_libp2p_invite_binding_after_handshake_send(
                    invite_proof_net,
                    &peer,
                    consumed_binding,
                    handshake_sent_now,
                );
                if handshake_sent_now {
                    handshake_sent.insert(peer);
                }
            }
        }
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::Message {
                peer: _,
                message: request_response::Message::Response { request_id, .. },
                ..
            },
        )) => {
            if let Some(pending_notice) = pending_disconnect_notices.remove(&request_id) {
                let _ = remove_connected_peer_state(
                    peers_net,
                    invite_proof_net,
                    handshake_sent,
                    &pending_notice.peer_id,
                )
                .await;
                if network.swarm.is_connected(&pending_notice.peer_id)
                    && network
                        .swarm
                        .disconnect_peer_id(pending_notice.peer_id)
                        .is_err()
                {
                    tracing::warn!(
                        peer_id = %pending_notice.peer_id,
                        "disconnect_peer_id failed after manual-disconnect notice ack"
                    );
                }
            } else {
                pending_user_chat_requests.remove(&request_id);
                // If this response is for an in-flight chunk, advance that peer's transfer.
                if let Some((_, pct)) = pending_chunk_transfers
                    .iter_mut()
                    .find(|(_, p)| p.inflight_request == Some(request_id))
                {
                    pct.inflight_request = None;
                    pct.next_chunk += 1;
                    pct.retry_count = 0;
                    pct.backoff_until = None;
                    pct.reconnect_wait_secs = 0;
                    // Random inter-chunk jitter: 500-4900ms (0.5s–4.9s)
                    // Prevents traffic timing analysis from correlating
                    // chunk intervals to identify file transfers.
                    // 400ms granularity — wide jumps between consecutive
                    // values (e.g. 0.5s, 2.1s, 4.5s, 1.3s).
                    let jitter_ms = 500 + (rand::random::<u64>() % 12) * 400;
                    pct.chunk_jitter_until = Some(
                        tokio::time::Instant::now() + tokio::time::Duration::from_millis(jitter_ms),
                    );
                    // Mark chunk as acknowledged in session (for resume)
                    if pct.next_chunk > 0 && pct.next_chunk <= pct.session.chunks.len() {
                        pct.session.chunks[pct.next_chunk - 1].sent = true;
                        pct.session.chunks[pct.next_chunk - 1].acknowledged = true;
                    }
                }
            }
        }

        // ── Request-Response failures (timeout, connection drop) ──
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            if let Some(pending_notice) = pending_disconnect_notices.remove(&request_id) {
                if is_expected_manual_disconnect_ack_race(&error) {
                    tracing::debug!(
                        peer_id = %pending_notice.peer_id,
                        %error,
                        "Manual-disconnect notice closed before ack; closing local peer state"
                    );
                } else {
                    tracing::warn!(
                        peer_id = %pending_notice.peer_id,
                        %error,
                        "Manual-disconnect notice failed before ack; closing local peer state"
                    );
                }
                let _ = remove_connected_peer_state(
                    peers_net,
                    invite_proof_net,
                    handshake_sent,
                    &pending_notice.peer_id,
                )
                .await;
                if network.swarm.is_connected(&pending_notice.peer_id)
                    && network
                        .swarm
                        .disconnect_peer_id(pending_notice.peer_id)
                        .is_err()
                {
                    tracing::warn!(
                        peer_id = %pending_notice.peer_id,
                        "disconnect_peer_id failed after manual-disconnect notice failure"
                    );
                }
            } else {
                let failed_user_chat_request = pending_user_chat_requests.remove(&request_id);
                let failed_transfer_key = pending_chunk_transfers
                    .iter()
                    .find(|(_, p)| p.inflight_request == Some(request_id))
                    .map(|(k, _)| k.clone());

                if let Some(transfer_key) = failed_transfer_key {
                    enum AbortReason {
                        ReconnectTimeout,
                        RetryLimit,
                    }

                    let mut abort_reason: Option<AbortReason> = None;
                    if let Some(pct) = pending_chunk_transfers.get_mut(&transfer_key) {
                        pct.inflight_request = None; // allow retry

                        // If reconnection is in progress, ignore this failure —
                        // the old request died with the old circuit.
                        if pct.reconnecting {
                            tracing::debug!("Ignoring OutboundFailure during Tor reconnection");
                        } else {
                            // Check if peer is still connected.
                            let peer_alive = network.swarm.is_connected(&pct.peer_id);

                            if !peer_alive {
                                // Connection dropped — don't count as retry, wait for reconnection.
                                // Tor circuits can recover within 30-90 seconds.
                                pct.backoff_until = Some(
                                    tokio::time::Instant::now()
                                        + tokio::time::Duration::from_secs(10),
                                );
                                pct.reconnect_wait_secs += 10;
                                const MAX_RECONNECT_WAIT: u64 = 180; // 3 minutes patience
                                if pct.reconnect_wait_secs > MAX_RECONNECT_WAIT {
                                    print_async_notice(
                                        &config_net.agent.name,
                                        format!(
                                            "   {} Peer lost >{}s — saving session",
                                            "Paused:".yellow().bold(),
                                            MAX_RECONNECT_WAIT,
                                        ),
                                    );
                                    abort_reason = Some(AbortReason::ReconnectTimeout);
                                } else {
                                    tracing::warn!(
                                        chunk = pct.next_chunk,
                                        waiting_secs = pct.reconnect_wait_secs,
                                        "Peer disconnected — waiting for Tor reconnection"
                                    );
                                }
                            } else {
                                // Peer is connected but request failed — real retry.
                                pct.retry_count += 1;
                                pct.reconnect_wait_secs = 0; // reset reconnect counter
                                const MAX_RETRIES: usize = 20;
                                if pct.retry_count > MAX_RETRIES {
                                    abort_reason = Some(AbortReason::RetryLimit);
                                } else {
                                    // Exponential backoff: 2s, 4s, 8s, 16s, 30s, 60s (capped)
                                    let delay_secs = std::cmp::min(
                                        2u64.saturating_pow(pct.retry_count as u32),
                                        60,
                                    );
                                    pct.backoff_until = Some(
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(delay_secs),
                                    );
                                    tracing::warn!(
                                        chunk = pct.next_chunk,
                                        retry = pct.retry_count,
                                        backoff_secs = delay_secs,
                                        %error,
                                        "Chunk send failed — retrying with backoff"
                                    );
                                }
                            }
                        }
                    }

                    if let Some(reason) = abort_reason {
                        if let Some(mut pct) = pending_chunk_transfers.remove(&transfer_key) {
                            match reason {
                                AbortReason::ReconnectTimeout => {
                                    if no_resume_session_persistence {
                                        println!(
                                                        "   {} transfer aborted — no resume metadata in Tor/Ghost mode",
                                                        "SECURITY:".red().bold()
                                                    );
                                        pct.chunk_source.secure_cleanup();
                                    } else {
                                        pct.session.status =
                                            chunked_transfer::TransferStatus::InProgress;
                                        let session_dir = runtime_temp_path("qypha-sessions");
                                        if let Ok(sp) = chunked_transfer::save_session(
                                            &pct.session,
                                            &session_dir,
                                        ) {
                                            println!(
                                                "   {} session saved: {}",
                                                "Resume:".cyan().bold(),
                                                sp.display(),
                                            );
                                            println!(
                                                            "   {} re-run the same /transfer command to resume from chunk {}/{}",
                                                            "Tip:".cyan(),
                                                            pct.next_chunk + 1,
                                                            pct.session.total_chunks,
                                                        );
                                        }
                                        // Keep temp file for resume — don't delete
                                    }
                                }
                                AbortReason::RetryLimit => {
                                    const MAX_RETRIES: usize = 20;
                                    if no_resume_session_persistence {
                                        println!(
                                                        "\n   {} chunk {} failed after {} retries — transfer data wiped (no resume metadata mode)",
                                                        "SECURITY:".red().bold(),
                                                        pct.next_chunk,
                                                        MAX_RETRIES,
                                                    );
                                        pct.chunk_source.secure_cleanup();
                                    } else {
                                        println!(
                                                        "\n   {} chunk {} failed after {} retries — saving session for resume",
                                                        "Error:".red().bold(),
                                                        pct.next_chunk,
                                                        MAX_RETRIES,
                                                    );
                                        pct.session.status =
                                            chunked_transfer::TransferStatus::InProgress;
                                        let session_dir = runtime_temp_path("qypha-sessions");
                                        if let Ok(sp) = chunked_transfer::save_session(
                                            &pct.session,
                                            &session_dir,
                                        ) {
                                            println!(
                                                "   {} session saved: {}",
                                                "Resume:".cyan().bold(),
                                                sp.display(),
                                            );
                                            println!(
                                                            "   {} re-run the same /transfer command to resume from chunk {}/{}",
                                                            "Tip:".cyan(),
                                                            pct.next_chunk + 1,
                                                            pct.session.total_chunks,
                                                        );
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Non-chunk request failures (cover traffic, keepalive, chat ACK, etc.)
                    // During active transfers (send OR receive) or Tor reconnection these
                    // are expected noise. Only print if no active transfer and peer is connected.
                    let sending = !pending_chunk_transfers.is_empty();
                    let receiving =
                        active_recv_for_swarm.load(std::sync::atomic::Ordering::Relaxed) > 0;
                    let peer_connected = network.swarm.is_connected(&peer);
                    let timed_out_user_chat = failed_user_chat_request
                        .as_ref()
                        .is_some_and(|_| is_libp2p_user_chat_timeout(&error));

                    // Suppress transient Yamux/connection errors — these are not
                    // actionable for the user (cover traffic, handshake timing, etc.)
                    let err_str = format!("{}", error);
                    let is_transient = err_str.contains("max sub-streams")
                        || err_str.contains("connection is closed");

                    // Also suppress errors for peers still in handshake (no verifying key yet)
                    let handshake_done = peers_net
                        .get(&peer.to_string())
                        .map(|p| p.verifying_key.is_some())
                        .unwrap_or(false);

                    if timed_out_user_chat && should_demote_tor_user_chat_timeout(peer_connected) {
                        let failed_chat = failed_user_chat_request
                            .as_ref()
                            .expect("timed out user chat must have tracked request");
                        drain_pending_user_chat_requests_for_did(
                            pending_user_chat_requests,
                            &failed_chat.peer_did,
                        );
                        invite_proof_net.remove(&peer.to_string());
                        handshake_sent.remove(&peer);

                        let reconnect_seed = if failed_chat.peer_did.trim().is_empty() {
                            None
                        } else {
                            let ps = peer_store_net.lock().await;
                            ps.get(&failed_chat.peer_did)
                                .cloned()
                                .filter(|known| known.onion_address.is_some())
                        };

                        if let Some(known) = reconnect_seed {
                            peers_net.insert(
                                peer.to_string(),
                                reconnecting_iroh_placeholder(peer, &known),
                            );
                            let queued_reconnect = queue_tor_reconnect_for_local_role(
                                pending_tor_reconnects,
                                &known,
                                &config_net.agent.did,
                                tokio::time::Duration::ZERO,
                                tokio::time::Duration::from_secs(
                                    TOR_USER_CHAT_TIMEOUT_RECONNECT_FALLBACK_DELAY_SECS,
                                ),
                                true,
                            );
                            if queued_reconnect {
                                emit_headless_direct_peer_event(
                                    "reconnecting",
                                    &known.did,
                                    &known.name,
                                    Some(&peer.to_string()),
                                    "reconnecting",
                                    Some("chat_timeout"),
                                );
                                print_async_notice(
                                    &config_net.agent.name,
                                    format!(
                                        "   {} {} — {}",
                                        "Offline:".yellow().bold(),
                                        failed_chat.peer_name.cyan(),
                                        "reconnecting in background".dimmed(),
                                    ),
                                );
                            }
                        } else {
                            peers_net.remove(&peer.to_string());
                            emit_headless_direct_peer_event(
                                "disconnected",
                                &failed_chat.peer_did,
                                &failed_chat.peer_name,
                                Some(&peer.to_string()),
                                "offline",
                                Some("chat_timeout"),
                            );
                            print_async_notice(
                                &config_net.agent.name,
                                format!(
                                    "   {} {}",
                                    "Offline:".yellow().bold(),
                                    failed_chat.peer_name.cyan(),
                                ),
                            );
                        }
                        tracing::debug!(
                            peer = %peer,
                            did = %failed_chat.peer_did,
                            %error,
                            "Timed-out Tor chat request demoted stale peer to reconnecting"
                        );
                    } else if timed_out_user_chat {
                        let failed_chat = failed_user_chat_request
                            .as_ref()
                            .expect("timed out user chat must have tracked request");
                        drain_pending_user_chat_requests_for_did(
                            pending_user_chat_requests,
                            &failed_chat.peer_did,
                        );
                        tracing::debug!(
                            peer = %peer,
                            did = %failed_chat.peer_did,
                            %error,
                            peer_connected,
                            "Timed-out Tor chat request suppressed while transport is still connected"
                        );
                    } else if should_surface_libp2p_outbound_failure(
                        failed_user_chat_request.is_some(),
                    ) {
                        let peer_name = failed_user_chat_request
                            .as_ref()
                            .map(|request| request.peer_name.clone())
                            .unwrap_or_else(|| peer.to_string());
                        println!(
                            "   {} send to {} failed: {}",
                            "Error:".red().bold(),
                            peer_name.cyan(),
                            error
                        );
                    } else if is_transient || !handshake_done {
                        tracing::debug!(
                            %peer,
                            %error,
                            "OutboundFailure suppressed (transient or handshake pending)"
                        );
                    } else {
                        tracing::debug!(
                            %peer,
                            %error,
                            sending,
                            receiving,
                            peer_connected,
                            "OutboundFailure suppressed (non-user libp2p request)"
                        );
                    }
                }
            }
        }
        SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            tracing::warn!(%peer, %error, "Inbound request failure");
        }

        // ── Connection errors — surface unless peer already connected (mDNS race) ──
        _ => unreachable!("unexpected libp2p event routed to messaging handler"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_expected_manual_disconnect_ack_race, is_libp2p_user_chat_timeout,
        should_demote_tor_user_chat_timeout, should_surface_libp2p_outbound_failure,
    };

    #[test]
    fn only_user_chat_failures_surface_to_terminal() {
        assert!(should_surface_libp2p_outbound_failure(true));
        assert!(!should_surface_libp2p_outbound_failure(false));
    }

    #[test]
    fn tor_user_chat_timeout_detection_matches_request_response_timeout() {
        assert!(is_libp2p_user_chat_timeout(
            &libp2p::request_response::OutboundFailure::Timeout
        ));
        assert!(!is_libp2p_user_chat_timeout(
            &libp2p::request_response::OutboundFailure::ConnectionClosed
        ));
    }

    #[test]
    fn tor_user_chat_timeout_only_demotes_after_real_disconnect() {
        assert!(!should_demote_tor_user_chat_timeout(true));
        assert!(should_demote_tor_user_chat_timeout(false));
    }

    #[test]
    fn manual_disconnect_ack_race_only_matches_connection_closed() {
        assert!(is_expected_manual_disconnect_ack_race(
            &libp2p::request_response::OutboundFailure::ConnectionClosed
        ));
        assert!(!is_expected_manual_disconnect_ack_race(
            &libp2p::request_response::OutboundFailure::Timeout
        ));
    }
}

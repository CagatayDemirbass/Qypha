use super::iroh_command_handlers::{IrohCommandHandlerShared, IrohCommandHandlerState};
use super::iroh_contact_delivery::{
    build_runtime_iroh_did_profile, profile_iroh_relay_service,
    send_request_via_iroh_contact_service,
};
use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
use super::*;
use crate::network::contact_mailbox::build_contact_mailbox_post_request;
use crate::network::did_profile::DidContactService;

const CONTACT_REQUEST_RESPONSE_TIMEOUT_SECS: u64 = 3;

fn pending_display_did(pending: &PendingContactRequest) -> String {
    crate::network::contact_did::encode_contact_did(&pending.sender_profile)
        .unwrap_or_else(|_| pending.sender_did.clone())
}

fn build_runtime_did_profile(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    network: Option<&NetworkNode>,
) -> anyhow::Result<crate::network::did_profile::DidProfile> {
    if matches!(config.network.transport_mode, TransportMode::Tor) {
        let network = network.ok_or_else(|| {
            anyhow::anyhow!("Tor runtime profile requested without a live network")
        })?;
        return build_runtime_tor_did_profile(keypair, config, network);
    }

    crate::network::discovery::build_local_did_profile(keypair, config, None)
}

async fn restore_pending_contact_request(
    registry: &Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pending: PendingContactRequest,
) {
    let PendingContactRequest {
        peer_id,
        request_id,
        sender_name,
        sender_profile,
        intro_message,
        invite_token,
        transport_policy,
        created_at,
        ..
    } = pending;
    let payload = crate::network::contact_request::ContactRequestPayload {
        version: 1,
        request_id,
        sender_profile,
        intro_message,
        invite_token,
        transport_policy,
        created_at,
        signature: Vec::new(),
    };
    let mut locked = registry.lock().await;
    match peer_id {
        Some(peer_id) => {
            locked.upsert_live(peer_id, sender_name.clone(), payload);
        }
        None => {
            locked.upsert_mailbox(sender_name.clone(), payload);
        }
    }
}

async fn build_contact_accept_request(
    local_profile: crate::network::did_profile::DidProfile,
    shared_config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    keypair: &AgentKeyPair,
    pending: &PendingContactRequest,
) -> anyhow::Result<AgentRequest> {
    crate::network::contact_request::build_contact_accept_agent_request(
        shared_config,
        sign_key,
        keypair,
        local_profile,
        &pending.sender_profile,
        pending.request_id.clone(),
    )
}

async fn build_contact_reject_request(
    local_profile: crate::network::did_profile::DidProfile,
    shared_config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    keypair: &AgentKeyPair,
    pending: &PendingContactRequest,
    reason: Option<String>,
) -> anyhow::Result<AgentRequest> {
    crate::network::contact_request::build_contact_reject_agent_request(
        shared_config,
        sign_key,
        keypair,
        local_profile,
        &pending.sender_profile,
        pending.request_id.clone(),
        reason,
    )
}

fn sender_tor_mailbox_service(pending: &PendingContactRequest) -> Option<&DidContactService> {
    pending
        .sender_profile
        .services
        .iter()
        .find(|service| matches!(service, DidContactService::TorMailbox { .. }))
}

fn sender_iroh_relay_service(pending: &PendingContactRequest) -> Option<&DidContactService> {
    profile_iroh_relay_service(&pending.sender_profile)
}

async fn clear_manual_disconnect_tombstone_for_contact_accept(
    manual_disconnect_dids: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    sender_did: &str,
) {
    let mut manual = manual_disconnect_dids.lock().await;
    manual.remove(sender_did);
}

async fn promote_local_contact_accept(
    profile: &crate::network::did_profile::DidProfile,
    sender_name: &str,
    log_mode: &LogMode,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    direct_peer_dids: &Arc<DashMap<String, bool>>,
    peers: &Arc<DashMap<String, PeerInfo>>,
    live_peer_id: Option<libp2p::PeerId>,
) -> TrustedContactPromotion {
    promote_accepted_contact(
        profile,
        sender_name,
        DEFAULT_AGENT_ROLE,
        log_mode,
        peer_store,
        direct_peer_dids,
        Some(peers),
        live_peer_id,
        None,
    )
    .await
}

async fn post_contact_response_via_mailbox(
    transport: &ContactMailboxTransport,
    pending: &PendingContactRequest,
    request: &AgentRequest,
    sender_verifying_key_hex: String,
) -> anyhow::Result<()> {
    let Some(service) = sender_tor_mailbox_service(pending) else {
        anyhow::bail!(
            "No Tor contact mailbox service advertised for {}",
            pending.sender_did
        );
    };
    let DidContactService::TorMailbox {
        mailbox_namespace, ..
    } = service
    else {
        unreachable!()
    };
    let post = build_contact_mailbox_post_request(
        pending.sender_did.clone(),
        mailbox_namespace.clone(),
        sender_verifying_key_hex,
        request.clone(),
    );
    transport.post(service, &post).await
}

pub(crate) async fn handle_libp2p_contact_request_command(
    cmd: NetworkCommand,
    state: &mut Libp2pCommandHandlerState<'_>,
    shared: &Libp2pCommandHandlerShared<'_>,
) {
    match cmd {
        NetworkCommand::SendContactAccept { pending } => {
            let local_profile = match build_runtime_did_profile(
                shared.keypair_net,
                shared.config_net,
                Some(state.network),
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            let request = match build_contact_accept_request(
                local_profile,
                shared.config_net,
                shared.sign_key,
                shared.keypair_net,
                &pending,
            )
            .await
            {
                Ok(request) => request,
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            clear_manual_disconnect_tombstone_for_contact_accept(
                shared.manual_disconnect_dids_net,
                &pending.sender_did,
            )
            .await;

            if let Some(peer_id) = pending.peer_id.clone() {
                if state.network.swarm.is_connected(&peer_id) {
                    state
                        .network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&peer_id, request);
                    let mut promotion = promote_local_contact_accept(
                        &pending.sender_profile,
                        &pending.sender_name,
                        shared.log_mode_net,
                        shared.peer_store_net,
                        shared.direct_peer_dids_net,
                        shared.peers_net,
                        Some(peer_id),
                    )
                    .await;
                    if !state.handshake_sent.contains(&peer_id) {
                        if send_handshake(
                            state.network,
                            shared.peers_net,
                            shared.pending_hybrid_ratchet_inits_net,
                            shared.config_net,
                            shared.keypair_net,
                            &peer_id,
                            Some(&pending.sender_did),
                            shared.ratchet_init_pub_hex_net,
                            None,
                            false,
                            false,
                        ) {
                            state.handshake_sent.insert(peer_id);
                            promotion.live_handshake_queued = true;
                        }
                    }
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({})",
                        "Contact accepted:".green().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed()
                    );
                    print_trusted_contact_promotion(promotion);
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_ACCEPT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={}",
                            pending.request_id, pending.sender_did
                        ),
                    );
                    return;
                }
            }

            match post_contact_response_via_mailbox(
                shared.contact_mailbox_transport_net.as_ref(),
                &pending,
                &request,
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
            )
            .await
            {
                Ok(()) => {
                    let promotion = promote_local_contact_accept(
                        &pending.sender_profile,
                        &pending.sender_name,
                        shared.log_mode_net,
                        shared.peer_store_net,
                        shared.direct_peer_dids_net,
                        shared.peers_net,
                        None,
                    )
                    .await;
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({}) {}",
                        "Contact accepted:".green().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    print_trusted_contact_promotion(promotion);
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_ACCEPT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={} delivery=tor_mailbox",
                            pending.request_id, pending.sender_did
                        ),
                    );
                }
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                }
            }
        }
        NetworkCommand::SendContactReject { pending, reason } => {
            let local_profile = match build_runtime_did_profile(
                shared.keypair_net,
                shared.config_net,
                Some(state.network),
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            let request = match build_contact_reject_request(
                local_profile,
                shared.config_net,
                shared.sign_key,
                shared.keypair_net,
                &pending,
                reason.clone(),
            )
            .await
            {
                Ok(request) => request,
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };

            if let Some(peer_id) = pending.peer_id.clone() {
                if state.network.swarm.is_connected(&peer_id) {
                    state
                        .network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&peer_id, request);
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({})",
                        "Contact rejected:".yellow().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed()
                    );
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_REJECT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={}",
                            pending.request_id, pending.sender_did
                        ),
                    );
                    return;
                }
            }

            match post_contact_response_via_mailbox(
                shared.contact_mailbox_transport_net.as_ref(),
                &pending,
                &request,
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
            )
            .await
            {
                Ok(()) => {
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({}) {}",
                        "Contact rejected:".yellow().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_REJECT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={} delivery=tor_mailbox",
                            pending.request_id, pending.sender_did
                        ),
                    );
                }
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                }
            }
        }
        _ => unreachable!("libp2p contact request handler received non-contact command"),
    }
}

pub(crate) async fn handle_iroh_contact_request_command(
    cmd: NetworkCommand,
    state: &mut IrohCommandHandlerState<'_>,
    shared: &IrohCommandHandlerShared<'_>,
) {
    match cmd {
        NetworkCommand::SendContactAccept { pending } => {
            let local_profile = match build_runtime_iroh_did_profile(
                shared.keypair_net,
                shared.config_net,
                state.iroh_network,
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            let request = match build_contact_accept_request(
                local_profile,
                shared.config_net,
                shared.sign_key,
                shared.keypair_net,
                &pending,
            )
            .await
            {
                Ok(request) => request,
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            clear_manual_disconnect_tombstone_for_contact_accept(
                shared.manual_disconnect_dids_net,
                &pending.sender_did,
            )
            .await;

            if let Some(peer_id) = pending.peer_id.clone() {
                if state.iroh_network.is_connected(&peer_id).await {
                    let send_result = tokio::time::timeout(
                        tokio::time::Duration::from_secs(CONTACT_REQUEST_RESPONSE_TIMEOUT_SECS),
                        state.iroh_network.send_request(&peer_id, &request),
                    )
                    .await;
                    match send_result {
                        Ok(Ok(_)) => {
                            let mut promotion = promote_local_contact_accept(
                                &pending.sender_profile,
                                &pending.sender_name,
                                shared.log_mode_net,
                                shared.peer_store_net,
                                shared.direct_peer_dids_net,
                                shared.peers_net,
                                Some(peer_id),
                            )
                            .await;
                            if should_send_iroh_handshake_for_live_session(
                                state.handshake_sent,
                                shared.iroh_peer_liveness_net,
                                &peer_id,
                            ) {
                                if let IrohHandshakeSendOutcome::Sent(message_id) =
                                    send_handshake_iroh(
                                        state.iroh_network,
                                        shared.peers_net,
                                        shared.pending_hybrid_ratchet_inits_net,
                                        shared.config_net,
                                        shared.keypair_net,
                                        &peer_id,
                                        Some(&pending.sender_did),
                                        shared.ratchet_init_pub_hex_net,
                                        None,
                                        false,
                                        None,
                                        false,
                                    )
                                    .await
                                {
                                    record_iroh_handshake_sent(
                                        state.handshake_sent,
                                        shared.iroh_peer_liveness_net,
                                        &peer_id,
                                    );
                                    note_iroh_handshake_message_sent(
                                        shared.iroh_handshake_sync_net,
                                        &peer_id,
                                        &message_id,
                                    );
                                    promotion.live_handshake_queued = true;
                                }
                            }
                            let display_did = pending_display_did(&pending);
                            println!(
                                "   {} {} ({})",
                                "Contact accepted:".green().bold(),
                                pending.sender_name.cyan(),
                                display_did.dimmed()
                            );
                            print_trusted_contact_promotion(promotion);
                            let mut a = shared.audit_net.lock().await;
                            a.record(
                                "CONTACT_REQUEST_ACCEPT_SENT",
                                &shared.config_net.agent.did,
                                &format!(
                                    "request_id={} peer_did={}",
                                    pending.request_id, pending.sender_did
                                ),
                            );
                            return;
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%error, "Live iroh contact accept delivery failed");
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Live iroh contact accept delivery timed out after {}s",
                                CONTACT_REQUEST_RESPONSE_TIMEOUT_SECS
                            );
                        }
                    }
                }
            }

            if let Some(service) = sender_iroh_relay_service(&pending) {
                match send_request_via_iroh_contact_service(state.iroh_network, service, &request)
                    .await
                {
                    Ok((peer_id, _response)) => {
                        let mut promotion = promote_local_contact_accept(
                            &pending.sender_profile,
                            &pending.sender_name,
                            shared.log_mode_net,
                            shared.peer_store_net,
                            shared.direct_peer_dids_net,
                            shared.peers_net,
                            Some(peer_id),
                        )
                        .await;
                        if should_send_iroh_handshake_for_live_session(
                            state.handshake_sent,
                            shared.iroh_peer_liveness_net,
                            &peer_id,
                        ) {
                            if let IrohHandshakeSendOutcome::Sent(message_id) = send_handshake_iroh(
                                state.iroh_network,
                                shared.peers_net,
                                shared.pending_hybrid_ratchet_inits_net,
                                shared.config_net,
                                shared.keypair_net,
                                &peer_id,
                                Some(&pending.sender_did),
                                shared.ratchet_init_pub_hex_net,
                                None,
                                false,
                                None,
                                false,
                            )
                            .await
                            {
                                record_iroh_handshake_sent(
                                    state.handshake_sent,
                                    shared.iroh_peer_liveness_net,
                                    &peer_id,
                                );
                                note_iroh_handshake_message_sent(
                                    shared.iroh_handshake_sync_net,
                                    &peer_id,
                                    &message_id,
                                );
                                promotion.live_handshake_queued = true;
                            }
                        }
                        let display_did = pending_display_did(&pending);
                        println!(
                            "   {} {} ({}) {}",
                            "Contact accepted:".green().bold(),
                            pending.sender_name.cyan(),
                            display_did.dimmed(),
                            "via iroh relay contact".dimmed()
                        );
                        print_trusted_contact_promotion(promotion);
                        let mut a = shared.audit_net.lock().await;
                        a.record(
                            "CONTACT_REQUEST_ACCEPT_SENT",
                            &shared.config_net.agent.did,
                            &format!(
                                "request_id={} peer_did={} delivery=iroh_relay_contact",
                                pending.request_id, pending.sender_did
                            ),
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::debug!(
                            %error,
                            sender_did = %pending.sender_did,
                            "Iroh relay contact accept fallback failed"
                        );
                    }
                }
            }

            match post_contact_response_via_mailbox(
                shared.contact_mailbox_transport_net.as_ref(),
                &pending,
                &request,
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
            )
            .await
            {
                Ok(()) => {
                    let promotion = promote_local_contact_accept(
                        &pending.sender_profile,
                        &pending.sender_name,
                        shared.log_mode_net,
                        shared.peer_store_net,
                        shared.direct_peer_dids_net,
                        shared.peers_net,
                        None,
                    )
                    .await;
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({}) {}",
                        "Contact accepted:".green().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    print_trusted_contact_promotion(promotion);
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_ACCEPT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={} delivery=tor_mailbox",
                            pending.request_id, pending.sender_did
                        ),
                    );
                }
                Err(error) => {
                    println!("   {} {}", "Accept failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                }
            }
        }
        NetworkCommand::SendContactReject { pending, reason } => {
            let local_profile = match build_runtime_iroh_did_profile(
                shared.keypair_net,
                shared.config_net,
                state.iroh_network,
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };
            let request = match build_contact_reject_request(
                local_profile,
                shared.config_net,
                shared.sign_key,
                shared.keypair_net,
                &pending,
                reason.clone(),
            )
            .await
            {
                Ok(request) => request,
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                    return;
                }
            };

            if let Some(peer_id) = pending.peer_id.clone() {
                if state.iroh_network.is_connected(&peer_id).await {
                    let send_result = tokio::time::timeout(
                        tokio::time::Duration::from_secs(CONTACT_REQUEST_RESPONSE_TIMEOUT_SECS),
                        state.iroh_network.send_request(&peer_id, &request),
                    )
                    .await;
                    match send_result {
                        Ok(Ok(_)) => {
                            let display_did = pending_display_did(&pending);
                            println!(
                                "   {} {} ({})",
                                "Contact rejected:".yellow().bold(),
                                pending.sender_name.cyan(),
                                display_did.dimmed()
                            );
                            let mut a = shared.audit_net.lock().await;
                            a.record(
                                "CONTACT_REQUEST_REJECT_SENT",
                                &shared.config_net.agent.did,
                                &format!(
                                    "request_id={} peer_did={}",
                                    pending.request_id, pending.sender_did
                                ),
                            );
                            return;
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%error, "Live iroh contact reject delivery failed");
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Live iroh contact reject delivery timed out after {}s",
                                CONTACT_REQUEST_RESPONSE_TIMEOUT_SECS
                            );
                        }
                    }
                }
            }

            if let Some(service) = sender_iroh_relay_service(&pending) {
                match send_request_via_iroh_contact_service(state.iroh_network, service, &request)
                    .await
                {
                    Ok((_peer_id, _response)) => {
                        let display_did = pending_display_did(&pending);
                        println!(
                            "   {} {} ({}) {}",
                            "Contact rejected:".yellow().bold(),
                            pending.sender_name.cyan(),
                            display_did.dimmed(),
                            "via iroh relay contact".dimmed()
                        );
                        let mut a = shared.audit_net.lock().await;
                        a.record(
                            "CONTACT_REQUEST_REJECT_SENT",
                            &shared.config_net.agent.did,
                            &format!(
                                "request_id={} peer_did={} delivery=iroh_relay_contact",
                                pending.request_id, pending.sender_did
                            ),
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::debug!(
                            %error,
                            sender_did = %pending.sender_did,
                            "Iroh relay contact reject fallback failed"
                        );
                    }
                }
            }

            match post_contact_response_via_mailbox(
                shared.contact_mailbox_transport_net.as_ref(),
                &pending,
                &request,
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
            )
            .await
            {
                Ok(()) => {
                    let display_did = pending_display_did(&pending);
                    println!(
                        "   {} {} ({}) {}",
                        "Contact rejected:".yellow().bold(),
                        pending.sender_name.cyan(),
                        display_did.dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    let mut a = shared.audit_net.lock().await;
                    a.record(
                        "CONTACT_REQUEST_REJECT_SENT",
                        &shared.config_net.agent.did,
                        &format!(
                            "request_id={} peer_did={} delivery=tor_mailbox",
                            pending.request_id, pending.sender_did
                        ),
                    );
                }
                Err(error) => {
                    println!("   {} {}", "Reject failed:".red().bold(), error);
                    restore_pending_contact_request(shared.pending_contact_requests_net, pending)
                        .await;
                }
            }
        }
        _ => unreachable!("iroh contact request handler received non-contact command"),
    }
}

#[cfg(test)]
mod tests {
    use super::clear_manual_disconnect_tombstone_for_contact_accept;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[tokio::test]
    async fn contact_accept_clears_manual_disconnect_tombstone_for_sender() {
        let manual_disconnect_dids = Arc::new(tokio::sync::Mutex::new(HashSet::from([
            "did:nxf:sender".to_string(),
            "did:nxf:other".to_string(),
        ])));

        clear_manual_disconnect_tombstone_for_contact_accept(
            &manual_disconnect_dids,
            "did:nxf:sender",
        )
        .await;

        let manual = manual_disconnect_dids.lock().await;
        assert!(!manual.contains("did:nxf:sender"));
        assert!(manual.contains("did:nxf:other"));
    }
}

use super::did_profile_cache::{import_verified_did_profile, summarize_contact_services};
use super::iroh_command_handlers::{IrohCommandHandlerShared, IrohCommandHandlerState};
use super::iroh_contact_delivery::{
    build_runtime_iroh_did_profile, profile_iroh_relay_service,
    send_request_via_iroh_contact_service,
};
use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
use super::*;
use crate::config::TransportMode;
use crate::network::contact_bundle::ContactBundleGetRequest;
use crate::network::contact_bundle_iroh::lookup_contact_bundle_via_iroh;
use crate::network::contact_bundle_transport::ContactBundleTransport;
use crate::network::contact_did::{decode_contact_did, is_contact_did};
use crate::network::contact_mailbox::build_contact_mailbox_post_request;
use crate::network::contact_request::build_contact_request_agent_request;
use crate::network::did_profile::DidContactService;
use crate::network::did_profile::DidProfile;
use crate::network::direct_invite_token::DirectInviteTransportPolicy;
use crate::network::discovery::tor::resolve_public_bundle_endpoint_from_config;

const DID_CONNECT_SEND_TIMEOUT_SECS: u64 = 3;

struct ResolvedConnectDidTarget {
    canonical_did: String,
    profile: DidProfile,
}

fn build_runtime_did_profile(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    network: Option<&NetworkNode>,
) -> anyhow::Result<DidProfile> {
    if matches!(config.network.transport_mode, TransportMode::Tor) {
        let network = network.ok_or_else(|| {
            anyhow::anyhow!("Tor runtime profile requested without a live network")
        })?;
        return build_runtime_tor_did_profile(keypair, config, network);
    }

    crate::network::discovery::build_local_did_profile(keypair, config, None)
}

fn transport_policy_for_mode(mode: &TransportMode) -> DirectInviteTransportPolicy {
    match mode {
        TransportMode::Internet => DirectInviteTransportPolicy::IrohOnly,
        TransportMode::Tor => DirectInviteTransportPolicy::TorOnly,
        TransportMode::Tcp => DirectInviteTransportPolicy::Any,
    }
}

fn live_peer_for_did(peers_net: &Arc<DashMap<String, PeerInfo>>, did: &str) -> Option<PeerInfo> {
    peers_net
        .iter()
        .find(|entry| entry.value().did == did)
        .map(|entry| entry.value().clone())
}

fn build_outbound_contact_request_with_sender_profile(
    sender_profile: DidProfile,
    config_net: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    keypair_net: &AgentKeyPair,
    recipient_profile: &DidProfile,
    intro_message: Option<String>,
) -> anyhow::Result<AgentRequest> {
    build_contact_request_agent_request(
        config_net,
        sign_key,
        keypair_net,
        sender_profile,
        recipient_profile,
        intro_message,
        None,
        transport_policy_for_mode(&config_net.network.transport_mode),
    )
}

fn print_invalid_did(did: &str) {
    println!(
        "   {} {} is not a valid shareable Qypha DID.",
        "Connect failed:".red().bold(),
        did.cyan()
    );
    println!(
        "   {} expected format: {}",
        "Tip:".dimmed(),
        "did:qypha:...".cyan()
    );
}

fn print_no_live_route(display_did: &str, profile: &DidProfile) {
    println!(
        "   {} resolved {} but there is no live transport route yet.",
        "Connect pending:".yellow().bold(),
        display_did.cyan()
    );
    println!(
        "   {} resolved contact services: {}",
        "Info:".dimmed(),
        summarize_contact_services(profile).cyan()
    );
    println!(
        "   {} no live route succeeded and no iroh relay/Tor mailbox fallback was available.",
        "Note:".dimmed()
    );
}

async fn record_contact_request_sent(
    audit_net: &Arc<tokio::sync::Mutex<AuditLog>>,
    local_did: &str,
    remote_did: &str,
    delivery: &str,
) {
    let mut audit = audit_net.lock().await;
    audit.record(
        "CONTACT_REQUEST_SENT",
        local_did,
        &format!("peer_did={remote_did} delivery={delivery}"),
    );
}

fn profile_tor_mailbox_service(profile: &DidProfile) -> Option<&DidContactService> {
    profile
        .services
        .iter()
        .find(|service| matches!(service, DidContactService::TorMailbox { .. }))
}

async fn resolve_profile_via_tor_bundle(
    config: &AppConfig,
    contact_bundle_transport: &Arc<ContactBundleTransport>,
    display_did: &str,
) -> anyhow::Result<Option<DidProfile>> {
    let canonical_did = decode_contact_did(display_did)?.canonical_did;
    let Some(endpoint) = resolve_public_bundle_endpoint_from_config(config, &canonical_did) else {
        return Ok(None);
    };
    let request = ContactBundleGetRequest::new(display_did.to_string());
    let response = contact_bundle_transport
        .get_from_endpoint(&endpoint, &request)
        .await?;
    response.into_verified_profile()
}

async fn resolve_connect_target(
    agent_data_dir: &std::path::Path,
    config: &AppConfig,
    contact_bundle_transport: &Arc<ContactBundleTransport>,
    did: &str,
) -> anyhow::Result<ResolvedConnectDidTarget> {
    if !is_contact_did(did) {
        anyhow::bail!("Unsupported DID format");
    }

    let resolved = decode_contact_did(did)?;
    let profile = if let Some(profile) =
        lookup_contact_bundle_via_iroh(&config.network.iroh, &resolved.encoded).await?
    {
        profile
    } else if let Some(profile) =
        resolve_profile_via_tor_bundle(config, contact_bundle_transport, &resolved.encoded).await?
    {
        profile
    } else {
        anyhow::bail!(
            "No verified contact bundle was found for {}. The remote agent may be offline or not publishing discovery yet.",
            did
        );
    };
    if let Err(error) = import_verified_did_profile(agent_data_dir, &profile) {
        tracing::debug!(
            %error,
            canonical_did = %resolved.canonical_did,
            "failed to cache resolved contact bundle profile"
        );
    }
    Ok(ResolvedConnectDidTarget {
        canonical_did: resolved.canonical_did,
        profile,
    })
}

pub(crate) async fn handle_libp2p_connect_did_command(
    cmd: NetworkCommand,
    state: &mut Libp2pCommandHandlerState<'_>,
    shared: &Libp2pCommandHandlerShared<'_>,
) {
    let NetworkCommand::ConnectDid { did, intro_message } = cmd else {
        unreachable!("libp2p DID connect handler received non-DID connect command");
    };

    if !is_contact_did(&did) {
        print_invalid_did(&did);
        return;
    }

    let target = match resolve_connect_target(
        shared.agent_data_dir,
        shared.config_net,
        shared.contact_bundle_transport_net,
        &did,
    )
    .await
    {
        Ok(target) => target,
        Err(error) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
            return;
        }
    };
    let display_did = did.clone();
    let canonical_did = target.canonical_did;
    let profile = target.profile;
    {
        let mut manual = shared.manual_disconnect_dids_net.lock().await;
        manual.remove(&canonical_did);
    }
    let pending_tor_direct_contact_requests = &mut *state.pending_tor_direct_contact_requests;

    let Some(peer) = live_peer_for_did(shared.peers_net, &canonical_did) else {
        let sender_profile = match build_runtime_did_profile(
            shared.keypair_net,
            shared.config_net,
            Some(state.network),
        ) {
            Ok(profile) => profile,
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
                return;
            }
        };
        let request = match build_outbound_contact_request_with_sender_profile(
            sender_profile,
            shared.config_net,
            shared.sign_key,
            shared.keypair_net,
            &profile,
            intro_message.clone(),
        ) {
            Ok(request) => request,
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
                return;
            }
        };
        if let Some(seed) =
            known_peer_from_tor_direct_profile(&profile, &display_did, DEFAULT_AGENT_ROLE)
        {
            let queue_result = queue_tor_direct_contact_request(
                state.network,
                state.pending_tor_dial_seeds,
                pending_tor_direct_contact_requests,
                seed,
                PendingTorDirectContactRequest {
                    did: canonical_did.clone(),
                    display_did: display_did.clone(),
                    request: request.clone(),
                    fallback_service: profile_tor_mailbox_service(&profile).cloned(),
                    sender_verifying_key_hex: hex::encode(
                        shared.sign_key.verifying_key().as_bytes(),
                    ),
                    bridge_port: 0,
                    fallback_at: tokio::time::Instant::now()
                        + tokio::time::Duration::from_secs(
                            TOR_DIRECT_CONTACT_REQUEST_FALLBACK_SECS,
                        ),
                },
            )
            .await;
            match queue_result {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Connecting:".yellow().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor direct contact".dimmed()
                    );
                    return;
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        did = %display_did,
                        "Tor direct DID contact dial failed before mailbox fallback"
                    );
                }
            }
        }
        if let Some(service) = profile_tor_mailbox_service(&profile) {
            let DidContactService::TorMailbox {
                mailbox_namespace, ..
            } = service
            else {
                unreachable!()
            };
            let post = build_contact_mailbox_post_request(
                canonical_did.clone(),
                mailbox_namespace.clone(),
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
                request,
            );
            match shared
                .contact_mailbox_transport_net
                .post(service, &post)
                .await
            {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "tor_mailbox",
                    )
                    .await;
                }
                Err(error) => {
                    println!("   {} {}", "Connect failed:".red().bold(), error);
                }
            }
            return;
        }
        print_no_live_route(&display_did, &profile);
        return;
    };

    let sender_profile =
        match build_runtime_did_profile(shared.keypair_net, shared.config_net, Some(state.network))
        {
            Ok(profile) => profile,
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
                return;
            }
        };
    let request = match build_outbound_contact_request_with_sender_profile(
        sender_profile,
        shared.config_net,
        shared.sign_key,
        shared.keypair_net,
        &profile,
        intro_message,
    ) {
        Ok(request) => request,
        Err(error) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
            return;
        }
    };

    if !state.network.swarm.is_connected(&peer.peer_id) {
        if let Some(seed) =
            known_peer_from_tor_direct_profile(&profile, &display_did, DEFAULT_AGENT_ROLE)
        {
            let queue_result = queue_tor_direct_contact_request(
                state.network,
                state.pending_tor_dial_seeds,
                pending_tor_direct_contact_requests,
                seed,
                PendingTorDirectContactRequest {
                    did: canonical_did.clone(),
                    display_did: display_did.clone(),
                    request: request.clone(),
                    fallback_service: profile_tor_mailbox_service(&profile).cloned(),
                    sender_verifying_key_hex: hex::encode(
                        shared.sign_key.verifying_key().as_bytes(),
                    ),
                    bridge_port: 0,
                    fallback_at: tokio::time::Instant::now()
                        + tokio::time::Duration::from_secs(
                            TOR_DIRECT_CONTACT_REQUEST_FALLBACK_SECS,
                        ),
                },
            )
            .await;
            match queue_result {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Connecting:".yellow().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor direct contact".dimmed()
                    );
                    return;
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        did = %display_did,
                        "Tor direct DID contact dial failed before mailbox fallback"
                    );
                }
            }
        }
        if let Some(service) = profile_tor_mailbox_service(&profile) {
            let DidContactService::TorMailbox {
                mailbox_namespace, ..
            } = service
            else {
                unreachable!()
            };
            let post = build_contact_mailbox_post_request(
                canonical_did.clone(),
                mailbox_namespace.clone(),
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
                request,
            );
            match shared
                .contact_mailbox_transport_net
                .post(service, &post)
                .await
            {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "tor_mailbox",
                    )
                    .await;
                }
                Err(error) => {
                    println!("   {} {}", "Connect failed:".red().bold(), error);
                }
            }
            return;
        }
        print_no_live_route(&display_did, &profile);
        return;
    }

    state
        .network
        .swarm
        .behaviour_mut()
        .messaging
        .send_request(&peer.peer_id, request);
    println!(
        "   {} {} ({})",
        "Contact request sent:".green().bold(),
        peer.name.cyan(),
        display_did.dimmed()
    );
    record_contact_request_sent(
        shared.audit_net,
        &shared.config_net.agent.did,
        &canonical_did,
        "live_peer",
    )
    .await;
}

pub(crate) async fn handle_iroh_connect_did_command(
    cmd: NetworkCommand,
    state: &mut IrohCommandHandlerState<'_>,
    shared: &IrohCommandHandlerShared<'_>,
) {
    let NetworkCommand::ConnectDid { did, intro_message } = cmd else {
        unreachable!("iroh DID connect handler received non-DID connect command");
    };

    if !is_contact_did(&did) {
        print_invalid_did(&did);
        return;
    }

    let target = match resolve_connect_target(
        shared.agent_data_dir,
        shared.config_net,
        shared.contact_bundle_transport_net,
        &did,
    )
    .await
    {
        Ok(target) => target,
        Err(error) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
            return;
        }
    };
    let display_did = did.clone();
    let canonical_did = target.canonical_did;
    let profile = target.profile;
    {
        let mut manual = shared.manual_disconnect_dids_net.lock().await;
        manual.remove(&canonical_did);
    }

    let Some(peer) = live_peer_for_did(shared.peers_net, &canonical_did) else {
        let sender_profile = match build_runtime_iroh_did_profile(
            shared.keypair_net,
            shared.config_net,
            state.iroh_network,
        ) {
            Ok(profile) => profile,
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
                return;
            }
        };
        let request = match build_outbound_contact_request_with_sender_profile(
            sender_profile,
            shared.config_net,
            shared.sign_key,
            shared.keypair_net,
            &profile,
            intro_message.clone(),
        ) {
            Ok(request) => request,
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
                return;
            }
        };
        if let Some(service) = profile_iroh_relay_service(&profile) {
            match send_request_via_iroh_contact_service(state.iroh_network, service, &request).await
            {
                Ok((_peer_id, _response)) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via iroh relay contact".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "iroh_relay_contact",
                    )
                    .await;
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, did = %did, "iroh relay contact fallback failed");
                }
            }
        }
        if let Some(service) = profile_tor_mailbox_service(&profile) {
            let DidContactService::TorMailbox {
                mailbox_namespace, ..
            } = service
            else {
                unreachable!()
            };
            let post = build_contact_mailbox_post_request(
                canonical_did.clone(),
                mailbox_namespace.clone(),
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
                request,
            );
            match shared
                .contact_mailbox_transport_net
                .post(service, &post)
                .await
            {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "tor_mailbox",
                    )
                    .await;
                }
                Err(error) => {
                    println!("   {} {}", "Connect failed:".red().bold(), error);
                }
            }
            return;
        }
        print_no_live_route(&display_did, &profile);
        return;
    };

    let sender_profile = match build_runtime_iroh_did_profile(
        shared.keypair_net,
        shared.config_net,
        state.iroh_network,
    ) {
        Ok(profile) => profile,
        Err(error) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
            return;
        }
    };
    let request = match build_outbound_contact_request_with_sender_profile(
        sender_profile,
        shared.config_net,
        shared.sign_key,
        shared.keypair_net,
        &profile,
        intro_message,
    ) {
        Ok(request) => request,
        Err(error) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
            return;
        }
    };

    if !state.iroh_network.is_connected(&peer.peer_id).await {
        if let Some(service) = profile_iroh_relay_service(&profile) {
            match send_request_via_iroh_contact_service(state.iroh_network, service, &request).await
            {
                Ok((_peer_id, _response)) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via iroh relay contact".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "iroh_relay_contact",
                    )
                    .await;
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, did = %did, "iroh relay contact fallback failed");
                }
            }
        }
        if let Some(service) = profile_tor_mailbox_service(&profile) {
            let DidContactService::TorMailbox {
                mailbox_namespace, ..
            } = service
            else {
                unreachable!()
            };
            let post = build_contact_mailbox_post_request(
                canonical_did.clone(),
                mailbox_namespace.clone(),
                hex::encode(shared.sign_key.verifying_key().as_bytes()),
                request,
            );
            match shared
                .contact_mailbox_transport_net
                .post(service, &post)
                .await
            {
                Ok(()) => {
                    println!(
                        "   {} {} ({}) {}",
                        "Contact request sent:".green().bold(),
                        display_did.cyan(),
                        "did".dimmed(),
                        "via Tor mailbox".dimmed()
                    );
                    record_contact_request_sent(
                        shared.audit_net,
                        &shared.config_net.agent.did,
                        &canonical_did,
                        "tor_mailbox",
                    )
                    .await;
                }
                Err(error) => {
                    println!("   {} {}", "Connect failed:".red().bold(), error);
                }
            }
            return;
        }
        print_no_live_route(&display_did, &profile);
        return;
    }

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(DID_CONNECT_SEND_TIMEOUT_SECS),
        state.iroh_network.send_request(&peer.peer_id, &request),
    )
    .await
    {
        Ok(Ok(_)) => {
            println!(
                "   {} {} ({})",
                "Contact request sent:".green().bold(),
                peer.name.cyan(),
                display_did.dimmed()
            );
            record_contact_request_sent(
                shared.audit_net,
                &shared.config_net.agent.did,
                &canonical_did,
                "live_iroh",
            )
            .await;
        }
        Ok(Err(error)) => {
            println!("   {} {}", "Connect failed:".red().bold(), error);
        }
        Err(_) => {
            println!(
                "   {} iroh send timed out after {}s",
                "Connect failed:".red().bold(),
                DID_CONNECT_SEND_TIMEOUT_SECS
            );
        }
    }
}

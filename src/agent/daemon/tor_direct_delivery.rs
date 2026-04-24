use std::collections::HashMap;

use anyhow::Result;
use colored::Colorize;
use sha2::{Digest, Sha256};

use super::*;
use crate::network::contact_mailbox::build_contact_mailbox_post_request;
use crate::network::did_profile::{DidContactService, DidProfile};
use crate::network::discovery::tor::resolve_tor_direct_service;
use crate::network::peer_store::{sanitize_known_peer, KnownPeer};

const PENDING_TOR_DIRECT_PEER_ID_SCOPE: &[u8] = b"QYPHA_PENDING_TOR_DIRECT_PEER_ID_V1:";
pub(crate) const TOR_DIRECT_CONTACT_REQUEST_FALLBACK_SECS: u64 = 8;

#[derive(Debug, Clone)]
pub(crate) struct PendingTorDirectContactRequest {
    pub(crate) did: String,
    pub(crate) display_did: String,
    pub(crate) request: AgentRequest,
    pub(crate) fallback_service: Option<DidContactService>,
    pub(crate) sender_verifying_key_hex: String,
    pub(crate) bridge_port: u16,
    pub(crate) fallback_at: tokio::time::Instant,
}

fn placeholder_peer_id_for_tor_direct_did(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PENDING_TOR_DIRECT_PEER_ID_SCOPE);
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    format!("pending-tor-direct:{}", hex::encode(&digest[..10]))
}

pub(crate) fn build_runtime_tor_did_profile(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    network: &NetworkNode,
) -> Result<DidProfile> {
    let onion_address = network
        .onion_address
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Tor runtime profile is missing the live onion address"))?;
    let onion_port = network
        .tor_manager
        .as_ref()
        .map(|manager| manager.local_port())
        .unwrap_or(config.network.listen_port);
    crate::network::discovery::build_local_did_profile_with_runtime_contact_endpoints(
        keypair,
        config,
        None,
        None,
        Some(onion_address),
        Some(onion_port),
    )
}

pub(crate) fn profile_tor_direct_service(profile: &DidProfile) -> Option<&DidContactService> {
    profile
        .services
        .iter()
        .find(|service| matches!(service, DidContactService::TorDirect { .. }))
}

pub(crate) fn known_peer_from_tor_direct_profile(
    profile: &DidProfile,
    peer_name: &str,
    peer_role: &str,
) -> Option<KnownPeer> {
    let service = profile_tor_direct_service(profile)?;
    let descriptor = resolve_tor_direct_service(service).ok()?;
    let name = peer_name.trim();
    let role = peer_role.trim();
    Some(sanitize_known_peer(KnownPeer {
        did: profile.did.clone(),
        name: if name.is_empty() {
            profile.did.clone()
        } else {
            name.to_string()
        },
        role: if role.is_empty() {
            DEFAULT_AGENT_ROLE.to_string()
        } else {
            role.to_string()
        },
        peer_id: placeholder_peer_id_for_tor_direct_did(&profile.did),
        onion_address: Some(descriptor.onion_address),
        tcp_address: None,
        iroh_endpoint_addr: None,
        onion_port: descriptor.port,
        encryption_public_key_hex: Some(hex::encode(profile.x25519_public_key)),
        verifying_key_hex: Some(hex::encode(profile.verifying_key)),
        kyber_public_key_hex: (!profile.kyber_public_key_hex.is_empty())
            .then_some(profile.kyber_public_key_hex.clone()),
        last_seen: chrono::Utc::now().timestamp() as u64,
        auto_reconnect: true,
    }))
}

pub(crate) async fn queue_tor_direct_contact_request(
    network: &mut NetworkNode,
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
    pending_tor_direct_contact_requests: &mut HashMap<String, PendingTorDirectContactRequest>,
    seed: KnownPeer,
    mut pending_request: PendingTorDirectContactRequest,
) -> Result<()> {
    let Some(ref tor_mgr) = network.tor_manager else {
        anyhow::bail!("Tor direct contact requires an active Tor transport");
    };
    let onion_address = seed.onion_address.clone().ok_or_else(|| {
        anyhow::anyhow!("Resolved Tor direct contact is missing an onion address")
    })?;
    let bridge_port = tor_bridge::create_tor_bridge_isolated(
        tor_mgr,
        &onion_address,
        seed.onion_port,
        Some(&seed.did),
    )
    .await?;
    let dial_addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{bridge_port}")
        .parse()
        .expect("valid tor bridge multiaddr");

    pending_request.bridge_port = bridge_port;
    pending_tor_dial_seeds.insert(bridge_port, seed);
    pending_tor_direct_contact_requests.insert(pending_request.did.clone(), pending_request);

    if let Err(error) = network.swarm.dial(dial_addr) {
        pending_tor_dial_seeds.remove(&bridge_port);
        pending_tor_direct_contact_requests.retain(|_, request| request.bridge_port != bridge_port);
        return Err(error.into());
    }

    Ok(())
}

pub(crate) async fn send_pending_tor_direct_contact_request_for_did(
    network: &mut NetworkNode,
    pending_tor_direct_contact_requests: &mut HashMap<String, PendingTorDirectContactRequest>,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    local_did: &str,
    peer_id: &libp2p::PeerId,
    did: &str,
) -> bool {
    let Some(pending) = pending_tor_direct_contact_requests.remove(did) else {
        return false;
    };

    network
        .swarm
        .behaviour_mut()
        .messaging
        .send_request(peer_id, pending.request);
    println!(
        "   {} {} ({}) {}",
        "Contact request sent:".green().bold(),
        pending.display_did.cyan(),
        "did".dimmed(),
        "via Tor direct contact".dimmed()
    );
    let mut locked = audit.lock().await;
    locked.record(
        "CONTACT_REQUEST_SENT",
        local_did,
        &format!("peer_did={} delivery=tor_direct", did),
    );
    true
}

pub(crate) async fn flush_due_tor_direct_contact_request_fallbacks(
    pending_tor_direct_contact_requests: &mut HashMap<String, PendingTorDirectContactRequest>,
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
    contact_mailbox_transport: &ContactMailboxTransport,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    local_did: &str,
    now: tokio::time::Instant,
) {
    let due = pending_tor_direct_contact_requests
        .iter()
        .filter_map(|(did, pending)| (pending.fallback_at <= now).then_some(did.clone()))
        .collect::<Vec<_>>();

    for did in due {
        let Some(pending) = pending_tor_direct_contact_requests.remove(&did) else {
            continue;
        };
        pending_tor_dial_seeds.remove(&pending.bridge_port);

        let Some(service) = pending.fallback_service else {
            println!(
                "   {} direct Tor route for {} did not come up in time and no mailbox fallback was advertised.",
                "Connect failed:".red().bold(),
                pending.display_did.cyan(),
            );
            continue;
        };

        let DidContactService::TorMailbox {
            mailbox_namespace, ..
        } = &service
        else {
            println!(
                "   {} resolved fallback for {} was not a Tor mailbox service.",
                "Connect failed:".red().bold(),
                pending.display_did.cyan(),
            );
            continue;
        };

        let post = build_contact_mailbox_post_request(
            did.clone(),
            mailbox_namespace.clone(),
            pending.sender_verifying_key_hex.clone(),
            pending.request,
        );
        match contact_mailbox_transport.post(&service, &post).await {
            Ok(()) => {
                println!(
                    "   {} {} ({}) {}",
                    "Contact request sent:".green().bold(),
                    pending.display_did.cyan(),
                    "did".dimmed(),
                    "via Tor mailbox".dimmed()
                );
                let mut locked = audit.lock().await;
                locked.record(
                    "CONTACT_REQUEST_SENT",
                    local_did,
                    &format!("peer_did={} delivery=tor_mailbox", did),
                );
            }
            Err(error) => {
                println!("   {} {}", "Connect failed:".red().bold(), error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_peer_from_tor_direct_profile_extracts_route() {
        let keypair = AgentKeyPair::generate("tor-direct", "agent");
        let profile = DidProfile::generate(
            &keypair,
            vec![DidContactService::TorDirect {
                onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                    .to_string(),
                port: 9090,
            }],
            None,
        );

        let known = known_peer_from_tor_direct_profile(&profile, "alice", "agent")
            .expect("tor direct seed");
        assert_eq!(known.did, keypair.did);
        assert_eq!(known.name, "alice");
        assert_eq!(
            known.onion_address.as_deref(),
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx")
        );
        assert_eq!(known.onion_port, 9090);
        assert!(known.iroh_endpoint_addr.is_none());
    }
}

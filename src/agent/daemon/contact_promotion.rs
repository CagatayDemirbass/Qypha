use std::sync::Arc;

use colored::Colorize;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::peer::{desired_auto_reconnect, print_auto_reconnect_state, should_persist_known_peer};
use super::*;
use crate::control_plane::audit::LogMode;
use crate::network::did_profile::DidProfile;
use crate::network::peer_store::{sanitize_known_peer, KnownPeer, PeerStore};

const PENDING_CONTACT_PEER_ID_SCOPE: &[u8] = b"QYPHA_PENDING_CONTACT_PEER_ID_V1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedContactPromotion {
    pub(crate) persisted: bool,
    pub(crate) reconnect_capable: bool,
    pub(crate) auto_reconnect: bool,
    pub(crate) live_handshake_queued: bool,
}

fn placeholder_peer_id_for_did(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PENDING_CONTACT_PEER_ID_SCOPE);
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    format!("pending-contact:{}", hex::encode(&digest[..10]))
}

fn validated_iroh_endpoint_addr_json(profile: &DidProfile) -> Option<String> {
    profile.services.iter().find_map(|service| {
        crate::network::discovery::iroh::resolve_iroh_relay_service(service)
            .ok()
            .and_then(|descriptor| descriptor.endpoint_addr_json)
    })
}

fn validated_tor_direct_route(profile: &DidProfile) -> Option<(String, u16)> {
    profile.services.iter().find_map(|service| {
        crate::network::discovery::tor::resolve_tor_direct_service(service)
            .ok()
            .map(|descriptor| (descriptor.onion_address, descriptor.port))
    })
}

fn derived_iroh_peer_id(endpoint_addr_json: &str) -> Option<libp2p::PeerId> {
    let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(endpoint_addr_json).ok()?;
    Some(crate::network::iroh_transport::peer_id_from_endpoint_id(
        &endpoint_addr.id,
    ))
}

fn fallback_name(sender_name: &str, existing: Option<&KnownPeer>) -> String {
    let trimmed = sender_name.trim();
    if trimmed.is_empty() {
        existing
            .map(|peer| peer.name.clone())
            .unwrap_or_else(|| "trusted-contact".to_string())
    } else {
        trimmed.to_string()
    }
}

fn fallback_role(sender_role: &str, existing: Option<&KnownPeer>) -> String {
    let trimmed = sender_role.trim();
    if trimmed.is_empty() {
        existing
            .map(|peer| peer.role.clone())
            .unwrap_or_else(|| DEFAULT_AGENT_ROLE.to_string())
    } else {
        trimmed.to_string()
    }
}

fn reconnect_capable(
    validated_iroh_endpoint_addr: Option<&str>,
    validated_tor_direct_route: Option<(&str, u16)>,
    existing: Option<&KnownPeer>,
    live_peer: Option<&PeerInfo>,
) -> bool {
    validated_iroh_endpoint_addr.is_some()
        || validated_tor_direct_route.is_some()
        || existing
            .map(|peer| {
                peer.iroh_endpoint_addr.is_some()
                    || peer.onion_address.is_some()
                    || peer.tcp_address.is_some()
            })
            .unwrap_or(false)
        || live_peer
            .map(|peer| {
                peer.iroh_endpoint_addr.is_some()
                    || peer.onion_address.is_some()
                    || peer.tcp_address.is_some()
            })
            .unwrap_or(false)
}

fn build_known_peer_from_profile(
    profile: &DidProfile,
    sender_name: &str,
    sender_role: &str,
    validated_iroh_endpoint_addr: Option<String>,
    validated_tor_direct_route: Option<(String, u16)>,
    existing: Option<&KnownPeer>,
    live_peer_id: Option<&libp2p::PeerId>,
    auto_reconnect: bool,
) -> KnownPeer {
    let iroh_endpoint_addr = validated_iroh_endpoint_addr
        .or_else(|| existing.and_then(|peer| peer.iroh_endpoint_addr.clone()));
    let profile_onion_address = validated_tor_direct_route
        .as_ref()
        .map(|(onion_address, _)| onion_address.clone());
    let profile_onion_port = validated_tor_direct_route
        .as_ref()
        .map(|(_, port)| *port)
        .unwrap_or_else(|| existing.map_or(9090, |peer| peer.onion_port));
    let peer_id = live_peer_id
        .map(ToString::to_string)
        .or_else(|| {
            iroh_endpoint_addr
                .as_deref()
                .and_then(derived_iroh_peer_id)
                .map(|peer_id| peer_id.to_string())
        })
        .or_else(|| existing.map(|peer| peer.peer_id.clone()))
        .unwrap_or_else(|| placeholder_peer_id_for_did(&profile.did));

    sanitize_known_peer(KnownPeer {
        did: profile.did.clone(),
        name: fallback_name(sender_name, existing),
        role: fallback_role(sender_role, existing),
        peer_id,
        onion_address: if iroh_endpoint_addr.is_some() {
            existing.and_then(|peer| peer.onion_address.clone())
        } else {
            profile_onion_address.or_else(|| existing.and_then(|peer| peer.onion_address.clone()))
        },
        tcp_address: existing.and_then(|peer| peer.tcp_address.clone()),
        iroh_endpoint_addr,
        onion_port: profile_onion_port,
        encryption_public_key_hex: Some(hex::encode(profile.x25519_public_key)),
        verifying_key_hex: Some(hex::encode(profile.verifying_key)),
        kyber_public_key_hex: Some(profile.kyber_public_key_hex.clone()),
        last_seen: chrono::Utc::now().timestamp() as u64,
        auto_reconnect,
    })
}

fn upsert_live_peer_identity(
    peers: &Arc<DashMap<String, PeerInfo>>,
    live_peer_id: &libp2p::PeerId,
    profile: &DidProfile,
    sender_name: &str,
    sender_role: &str,
    validated_iroh_endpoint_addr: Option<String>,
    validated_tor_direct_route: Option<(String, u16)>,
) {
    let peer_key = live_peer_id.to_string();
    let name = fallback_name(sender_name, None);
    let role = fallback_role(sender_role, None);
    let kyber_public_key = if profile.kyber_public_key_hex.is_empty() {
        None
    } else {
        hex::decode(&profile.kyber_public_key_hex).ok()
    };

    if let Some(mut entry) = peers.get_mut(&peer_key) {
        entry.did = profile.did.clone();
        entry.name = name;
        entry.role = role;
        entry.x25519_public_key = Some(profile.x25519_public_key);
        entry.kyber_public_key = kyber_public_key;
        entry.verifying_key = Some(profile.verifying_key);
        if entry.iroh_endpoint_addr.is_none() {
            entry.iroh_endpoint_addr = validated_iroh_endpoint_addr;
        }
        if entry.onion_address.is_none() {
            if let Some((onion_address, port)) = validated_tor_direct_route {
                entry.onion_address = Some(onion_address);
                entry.onion_port = port;
            }
        }
        return;
    }

    let (onion_address, onion_port) = validated_tor_direct_route
        .map(|(onion_address, port)| (Some(onion_address), port))
        .unwrap_or((None, 9090));
    peers.insert(
        peer_key,
        PeerInfo {
            peer_id: *live_peer_id,
            did: profile.did.clone(),
            name,
            role,
            onion_address,
            tcp_address: None,
            iroh_endpoint_addr: validated_iroh_endpoint_addr,
            onion_port,
            x25519_public_key: Some(profile.x25519_public_key),
            kyber_public_key,
            verifying_key: Some(profile.verifying_key),
            aegis_supported: false,
            ratchet_dh_public: None,
        },
    );
}

pub(crate) fn print_trusted_contact_promotion(outcome: TrustedContactPromotion) {
    if outcome.live_handshake_queued {
        println!(
            "   {} secure direct handshake is starting now.",
            "Trusted session primed:".green().bold()
        );
        return;
    }

    if outcome.persisted && outcome.reconnect_capable && outcome.auto_reconnect {
        println!(
            "   {} auto-reconnect is enabled for future sessions.",
            "Trusted peer saved:".green().bold()
        );
        return;
    }

    if outcome.persisted {
        println!(
            "   {} direct session will start once a live route becomes available.",
            "Trusted contact saved:".green().bold()
        );
        return;
    }

    println!(
        "   {} trust is available only in memory for this session.",
        "Ghost mode:".yellow().bold()
    );
}

pub(crate) async fn promote_accepted_contact(
    profile: &DidProfile,
    sender_name: &str,
    sender_role: &str,
    log_mode: &LogMode,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    direct_peer_dids: &Arc<DashMap<String, bool>>,
    peers: Option<&Arc<DashMap<String, PeerInfo>>>,
    live_peer_id: Option<libp2p::PeerId>,
    cmd_tx: Option<&mpsc::Sender<NetworkCommand>>,
) -> TrustedContactPromotion {
    let validated_iroh_endpoint_addr = validated_iroh_endpoint_addr_json(profile);
    let validated_tor_direct_route = validated_tor_direct_route(profile);
    if let (Some(peers), Some(peer_id)) = (peers, live_peer_id.as_ref()) {
        upsert_live_peer_identity(
            peers,
            peer_id,
            profile,
            sender_name,
            sender_role,
            validated_iroh_endpoint_addr.clone(),
            validated_tor_direct_route.clone(),
        );
    }

    direct_peer_dids.insert(profile.did.clone(), true);

    let live_peer_snapshot = live_peer_id.as_ref().and_then(|peer_id| {
        peers.and_then(|map| map.get(&peer_id.to_string()).map(|entry| entry.clone()))
    });

    let (persisted, auto_reconnect, reconnect_capable) = {
        let mut peer_store = peer_store.lock().await;
        let existing = peer_store.get(&profile.did).cloned();
        let reconnect_capable = reconnect_capable(
            validated_iroh_endpoint_addr.as_deref(),
            validated_tor_direct_route
                .as_ref()
                .map(|(onion_address, port)| (onion_address.as_str(), *port)),
            existing.as_ref(),
            live_peer_snapshot.as_ref(),
        );
        let auto_reconnect = if reconnect_capable {
            desired_auto_reconnect(log_mode, existing.as_ref())
        } else {
            false
        };
        let persisted = should_persist_known_peer(log_mode, existing.as_ref(), true);
        if persisted {
            peer_store.upsert(build_known_peer_from_profile(
                profile,
                sender_name,
                sender_role,
                validated_iroh_endpoint_addr.clone(),
                validated_tor_direct_route.clone(),
                existing.as_ref(),
                live_peer_id.as_ref(),
                auto_reconnect,
            ));
        }
        (persisted, auto_reconnect, reconnect_capable)
    };

    print_auto_reconnect_state(&profile.did, auto_reconnect);

    let live_handshake_queued = if let (Some(peer_id), Some(cmd_tx)) = (live_peer_id, cmd_tx) {
        cmd_tx
            .send(NetworkCommand::EnsurePeerHandshake {
                peer_id,
                ack_handshake_message_id: None,
                trusted_known_peer_bootstrap: false,
            })
            .await
            .is_ok()
    } else {
        false
    };

    TrustedContactPromotion {
        persisted,
        reconnect_capable,
        auto_reconnect,
        live_handshake_queued,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::did_profile::{DidContactService, DidProfile};

    fn sample_iroh_profile() -> DidProfile {
        let keypair = AgentKeyPair::generate("IrohContact", "agent");
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &serde_json::from_value(serde_json::json!({
                    "relay_enabled": true,
                    "direct_enabled": false,
                    "relay_urls": ["https://relay.example.com"]
                }))
                .unwrap(),
                [9u8; 32],
            )
            .unwrap()
            .unwrap();
        DidProfile::generate(
            &keypair,
            vec![DidContactService::IrohRelay {
                relay_urls: vec!["https://relay.example.com".to_string()],
                mailbox_topic: "did-contact:test".to_string(),
                endpoint_addr_json: Some(endpoint_addr_json),
            }],
            None,
        )
    }

    fn sample_tor_profile() -> DidProfile {
        let keypair = AgentKeyPair::generate("TorContact", "agent");
        DidProfile::generate(
            &keypair,
            vec![DidContactService::TorMailbox {
                onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                    .to_string(),
                mailbox_namespace: "contact:test".to_string(),
                port: 9444,
            }],
            None,
        )
    }

    fn sample_tor_direct_profile() -> DidProfile {
        let keypair = AgentKeyPair::generate("TorDirectContact", "agent");
        DidProfile::generate(
            &keypair,
            vec![DidContactService::TorDirect {
                onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                    .to_string(),
                port: 9090,
            }],
            None,
        )
    }

    #[tokio::test]
    async fn live_promotion_upgrades_peer_and_queues_handshake() {
        let profile = sample_iroh_profile();
        let live_peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        peers.insert(
            live_peer_id.to_string(),
            PeerInfo {
                peer_id: live_peer_id,
                did: String::new(),
                name: "pending".to_string(),
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
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let direct_peer_dids = Arc::new(DashMap::new());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(2);

        let outcome = promote_accepted_contact(
            &profile,
            "Alice",
            "agent",
            &LogMode::Safe,
            &peer_store,
            &direct_peer_dids,
            Some(&peers),
            Some(live_peer_id),
            Some(&cmd_tx),
        )
        .await;

        assert!(outcome.persisted);
        assert!(outcome.reconnect_capable);
        assert!(outcome.auto_reconnect);
        assert!(outcome.live_handshake_queued);
        assert!(direct_peer_dids.contains_key(&profile.did));

        let stored = peer_store.lock().await;
        let known = stored.get(&profile.did).expect("known peer should exist");
        assert!(known.iroh_endpoint_addr.is_some());
        assert_eq!(known.peer_id, live_peer_id.to_string());
        drop(stored);

        let upgraded = peers
            .get(&live_peer_id.to_string())
            .expect("live peer should be upgraded");
        assert_eq!(upgraded.did, profile.did);
        assert_eq!(upgraded.name, "Alice");
        assert_eq!(upgraded.verifying_key, Some(profile.verifying_key));

        match cmd_rx.recv().await {
            Some(NetworkCommand::EnsurePeerHandshake { peer_id, .. }) => {
                assert_eq!(peer_id, live_peer_id);
            }
            Some(_) => panic!("expected queued handshake command"),
            None => panic!("expected queued handshake command"),
        }
    }

    #[tokio::test]
    async fn mailbox_only_promotion_saves_trust_without_auto_reconnect() {
        let profile = sample_tor_profile();
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let direct_peer_dids = Arc::new(DashMap::new());

        let outcome = promote_accepted_contact(
            &profile,
            "Bob",
            "agent",
            &LogMode::Safe,
            &peer_store,
            &direct_peer_dids,
            None,
            None,
            None,
        )
        .await;

        assert!(outcome.persisted);
        assert!(!outcome.reconnect_capable);
        assert!(!outcome.auto_reconnect);
        assert!(!outcome.live_handshake_queued);
        assert!(direct_peer_dids.contains_key(&profile.did));

        let stored = peer_store.lock().await;
        let known = stored
            .get(&profile.did)
            .expect("trusted mailbox contact should persist");
        assert!(known.peer_id.starts_with("pending-contact:"));
        assert!(!known.auto_reconnect);
        assert!(known.iroh_endpoint_addr.is_none());
        assert!(known.onion_address.is_none());
    }

    #[tokio::test]
    async fn tor_direct_profile_promotion_persists_reconnect_route() {
        let profile = sample_tor_direct_profile();
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let direct_peer_dids = Arc::new(DashMap::new());

        let outcome = promote_accepted_contact(
            &profile,
            "Carol",
            "agent",
            &LogMode::Safe,
            &peer_store,
            &direct_peer_dids,
            None,
            None,
            None,
        )
        .await;

        assert!(outcome.persisted);
        assert!(outcome.reconnect_capable);
        assert!(outcome.auto_reconnect);

        let stored = peer_store.lock().await;
        let known = stored
            .get(&profile.did)
            .expect("trusted tor-direct contact should persist");
        assert_eq!(
            known.onion_address.as_deref(),
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx")
        );
        assert_eq!(known.onion_port, 9090);
        assert!(known.iroh_endpoint_addr.is_none());
        assert!(known.auto_reconnect);
    }
}

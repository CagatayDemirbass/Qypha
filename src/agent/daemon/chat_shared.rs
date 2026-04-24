use super::*;
use crate::network::protocol::RatchetChatPayload;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PendingLibp2pUserChatRequest {
    pub(crate) peer_did: String,
    pub(crate) peer_name: String,
}

pub(crate) enum RatchetPayloadError {
    MissingSession,
    SessionNotSendReady,
    Encrypt(String),
    Serialize(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectChatReadiness {
    Ready,
    UnverifiedPeer,
    MissingSession,
    AwaitingRatchetSend,
}

pub(crate) async fn encrypt_ratchet_payload(
    ratchet_mgr: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
    plaintext: &[u8],
    require_existing_session: bool,
) -> std::result::Result<Vec<u8>, RatchetPayloadError> {
    let mut rmgr = ratchet_mgr.lock().await;
    if require_existing_session && !rmgr.has_session(peer_did) {
        return Err(RatchetPayloadError::MissingSession);
    }
    if require_existing_session && !rmgr.session_send_ready(peer_did) {
        return Err(RatchetPayloadError::SessionNotSendReady);
    }

    let (header, ciphertext) = rmgr
        .encrypt_for_peer(peer_did, plaintext)
        .map_err(|e| RatchetPayloadError::Encrypt(e.to_string()))?;
    let payload = RatchetChatPayload { header, ciphertext };
    let serialized =
        bincode::serialize(&payload).map_err(|e| RatchetPayloadError::Serialize(e.to_string()))?;

    let mut buf = vec![0x02u8];
    buf.extend(serialized);
    Ok(buf)
}

pub(crate) async fn direct_chat_readiness(
    peers: &Arc<dashmap::DashMap<String, PeerInfo>>,
    ratchet_mgr: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
) -> DirectChatReadiness {
    let verified = peers
        .iter()
        .any(|entry| entry.value().did == peer_did && entry.value().verifying_key.is_some());
    if !verified {
        return DirectChatReadiness::UnverifiedPeer;
    }

    let rmgr = ratchet_mgr.lock().await;
    if !rmgr.has_session(peer_did) {
        return DirectChatReadiness::MissingSession;
    }
    if !rmgr.session_send_ready(peer_did) {
        return DirectChatReadiness::AwaitingRatchetSend;
    }
    DirectChatReadiness::Ready
}

pub(crate) async fn wait_for_direct_chat_ready(
    peers: &Arc<dashmap::DashMap<String, PeerInfo>>,
    ratchet_mgr: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
    timeout: tokio::time::Duration,
) -> DirectChatReadiness {
    let start = tokio::time::Instant::now();
    let mut last_state = direct_chat_readiness(peers, ratchet_mgr, peer_did).await;
    while start.elapsed() < timeout {
        if last_state == DirectChatReadiness::Ready {
            return last_state;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        last_state = direct_chat_readiness(peers, ratchet_mgr, peer_did).await;
    }
    last_state
}

pub(crate) fn should_send_final_iroh_bootstrap_ack(
    peer_acked_current_handshake: bool,
    is_initiator: bool,
    readiness: DirectChatReadiness,
) -> bool {
    peer_acked_current_handshake
        && !is_initiator
        && matches!(readiness, DirectChatReadiness::AwaitingRatchetSend)
}

pub(crate) fn should_accept_ack_only_iroh_handshake(
    peer_acked_current_handshake: bool,
    has_existing_session: bool,
    ratchet_matches_known_peer: bool,
    hybrid_ready: bool,
) -> bool {
    peer_acked_current_handshake
        && has_existing_session
        && ratchet_matches_known_peer
        && !hybrid_ready
}

pub(crate) fn should_accept_trusted_iroh_reconnect_probe(
    peer_acked_current_handshake: bool,
    has_existing_session: bool,
    ratchet_matches_known_peer: bool,
    hybrid_ready: bool,
) -> bool {
    !peer_acked_current_handshake
        && has_existing_session
        && ratchet_matches_known_peer
        && !hybrid_ready
}

pub(crate) fn ack_only_iroh_handshake_matches_trusted_ratchet(
    peer_ratchet_dh: Option<[u8; 32]>,
    live_peer_ratchet_dh: Option<[u8; 32]>,
    persisted_session_ratchet_dh: Option<[u8; 32]>,
) -> bool {
    let trusted_ratchet_dh = live_peer_ratchet_dh.or(persisted_session_ratchet_dh);
    peer_ratchet_dh.is_some() && trusted_ratchet_dh == peer_ratchet_dh
}

pub(crate) fn build_signed_chat_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    payload: Vec<u8>,
) -> AgentRequest {
    build_signed_payload_request(config, sign_key, MessageKind::Chat, payload)
}

pub(crate) fn build_signed_payload_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    msg_type: MessageKind,
    payload: Vec<u8>,
) -> AgentRequest {
    let nonce = crate::crypto::next_request_nonce();
    let mt_bytes = serde_json::to_vec(&msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(mt_bytes.len() + payload.len() + 16);
    signed_data.extend_from_slice(&mt_bytes);
    signed_data.extend_from_slice(&payload);
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    let signature = signing::sign_data(sign_key, &signed_data);

    AgentRequest {
        message_id: uuid::Uuid::new_v4().to_string(),
        sender_did: config.agent.did.clone(),
        sender_name: config.agent.name.clone(),
        sender_role: DEFAULT_AGENT_ROLE.to_string(),
        msg_type,
        payload,
        signature,
        nonce,
        timestamp: nonce,
        ttl_ms: config.security.message_ttl_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::daemon::PeerInfo;
    use serde_json::json;

    #[test]
    fn signed_chat_request_sets_chat_message_kind() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let config: AppConfig = serde_json::from_value(json!({
            "agent": {
                "name": "tester",
                "role": "agent",
                "did": "did:nxf:test"
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false
            },
            "security": {
                "require_mtls": false,
                "max_message_size_bytes": 65536,
                "nonce_window_size": 64,
                "shadow_mode_enabled": false,
                "message_ttl_ms": 60000
            }
        }))
        .unwrap();
        let request = build_signed_chat_request(&config, &key, b"hello".to_vec());
        assert_eq!(request.msg_type, MessageKind::Chat);
        assert_eq!(request.payload, b"hello".to_vec());
    }

    #[tokio::test]
    async fn direct_chat_readiness_distinguishes_verified_and_send_ready_sessions() {
        let peers = Arc::new(dashmap::DashMap::new());
        let verified_peer_id = libp2p::PeerId::random();
        peers.insert(
            verified_peer_id.to_string(),
            PeerInfo {
                peer_id: verified_peer_id,
                did: "did:nxf:ready".to_string(),
                name: "ready".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: Some([7u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: None,
            },
        );

        let mut rmgr = crate::crypto::double_ratchet::RatchetManager::new(None, None);
        let shared_secret = rand::random::<[u8; 32]>();
        let initiator_remote = crate::crypto::double_ratchet::RatchetKeyPair::generate();
        let responder_keypair = crate::crypto::double_ratchet::RatchetKeyPair::generate();
        rmgr.get_or_init(
            "did:nxf:ready",
            &shared_secret,
            &initiator_remote.public,
            true,
            None,
        );
        rmgr.get_or_init(
            "did:nxf:awaiting",
            &shared_secret,
            &initiator_remote.public,
            false,
            Some(responder_keypair.secret.to_bytes()),
        );
        let ratchet_mgr = Arc::new(tokio::sync::Mutex::new(rmgr));

        assert_eq!(
            direct_chat_readiness(&peers, &ratchet_mgr, "did:nxf:ready").await,
            DirectChatReadiness::Ready
        );
        assert_eq!(
            direct_chat_readiness(&peers, &ratchet_mgr, "did:nxf:missing").await,
            DirectChatReadiness::UnverifiedPeer
        );

        let awaiting_peer_id = libp2p::PeerId::random();
        peers.insert(
            awaiting_peer_id.to_string(),
            PeerInfo {
                peer_id: awaiting_peer_id,
                did: "did:nxf:awaiting".to_string(),
                name: "awaiting".to_string(),
                role: "agent".to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: None,
                kyber_public_key: None,
                verifying_key: Some([8u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: None,
            },
        );
        assert_eq!(
            direct_chat_readiness(&peers, &ratchet_mgr, "did:nxf:awaiting").await,
            DirectChatReadiness::AwaitingRatchetSend
        );
    }

    #[test]
    fn final_iroh_bootstrap_ack_only_triggers_for_responder_waiting_on_bootstrap() {
        assert!(should_send_final_iroh_bootstrap_ack(
            true,
            false,
            DirectChatReadiness::AwaitingRatchetSend
        ));
        assert!(!should_send_final_iroh_bootstrap_ack(
            false,
            false,
            DirectChatReadiness::AwaitingRatchetSend
        ));
        assert!(!should_send_final_iroh_bootstrap_ack(
            true,
            true,
            DirectChatReadiness::AwaitingRatchetSend
        ));
        assert!(!should_send_final_iroh_bootstrap_ack(
            true,
            false,
            DirectChatReadiness::Ready
        ));
    }

    #[test]
    fn ack_only_iroh_handshake_requires_existing_live_session_and_matching_ratchet() {
        assert!(should_accept_ack_only_iroh_handshake(
            true, true, true, false
        ));
        assert!(!should_accept_ack_only_iroh_handshake(
            false, true, true, false
        ));
        assert!(!should_accept_ack_only_iroh_handshake(
            true, false, true, false
        ));
        assert!(!should_accept_ack_only_iroh_handshake(
            true, true, false, false
        ));
        assert!(!should_accept_ack_only_iroh_handshake(
            true, true, true, true
        ));
    }

    #[test]
    fn trusted_iroh_reconnect_probe_requires_existing_session_and_matching_ratchet() {
        assert!(should_accept_trusted_iroh_reconnect_probe(
            false, true, true, false
        ));
        assert!(!should_accept_trusted_iroh_reconnect_probe(
            true, true, true, false
        ));
        assert!(!should_accept_trusted_iroh_reconnect_probe(
            false, false, true, false
        ));
        assert!(!should_accept_trusted_iroh_reconnect_probe(
            false, true, false, false
        ));
        assert!(!should_accept_trusted_iroh_reconnect_probe(
            false, true, true, true
        ));
    }

    #[test]
    fn ack_only_iroh_handshake_can_match_persisted_session_ratchet_when_live_slot_is_demoted() {
        let ratchet = Some([9u8; 32]);
        assert!(ack_only_iroh_handshake_matches_trusted_ratchet(
            ratchet, None, ratchet
        ));
        assert!(ack_only_iroh_handshake_matches_trusted_ratchet(
            ratchet, ratchet, None
        ));
        assert!(!ack_only_iroh_handshake_matches_trusted_ratchet(
            ratchet,
            None,
            Some([8u8; 32])
        ));
        assert!(!ack_only_iroh_handshake_matches_trusted_ratchet(
            None, None, ratchet
        ));
    }
}

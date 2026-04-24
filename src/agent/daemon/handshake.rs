use std::future::Future;
use std::sync::Arc;

use crate::config::{AppConfig, TransportMode};
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::signing;
use crate::network::iroh_transport::IrohTransport;
use crate::network::protocol::{AgentRequest, HandshakePayload, MessageKind};
use crate::network::NetworkNode;
use dashmap::DashMap;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const HYBRID_RATCHET_KDF_SUITE_V1: &str = "qypha/x25519+kyber1024/ratchet-init/v1";
pub(crate) const INVITE_RESPONSE_BOUND_MARKER: &str = "__qypha_invite_response_bound__";
pub(crate) const INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER: &str =
    "__qypha_invite_consumer_awaiting_reciprocal__";
const IROH_HANDSHAKE_SEND_TIMEOUT_SECS: u64 = 3;

pub(crate) struct PendingHybridRatchetInit {
    pub(crate) expected_did: Option<String>,
    pub(crate) suite: String,
    pub(crate) kyber_shared_secret: Zeroizing<Vec<u8>>,
}

struct OutboundHybridRatchetInit {
    suite: String,
    kyber_ciphertext_hex: String,
}

pub(crate) fn stored_invite_binding_parts(stored: Option<String>) -> (Option<String>, bool) {
    match stored {
        Some(stored)
            if stored == INVITE_RESPONSE_BOUND_MARKER
                || stored == INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER =>
        {
            (None, true)
        }
        Some(stored) => (Some(stored), false),
        None => (None, false),
    }
}

pub(crate) fn advance_libp2p_invite_binding_after_handshake_send(
    invite_proof_by_peer: &Arc<DashMap<String, String>>,
    peer_id: &libp2p::PeerId,
    consumed_binding: Option<String>,
    send_succeeded: bool,
) {
    let Some(consumed_binding) = consumed_binding else {
        return;
    };

    let next_binding = match consumed_binding.as_str() {
        INVITE_RESPONSE_BOUND_MARKER => (!send_succeeded).then_some(consumed_binding),
        INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER => Some(consumed_binding),
        _ if send_succeeded => Some(INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER.to_string()),
        _ => Some(consumed_binding),
    };

    if let Some(next_binding) = next_binding {
        invite_proof_by_peer.insert(peer_id.to_string(), next_binding);
    }
}

pub(crate) fn take_invite_consumer_reciprocal_pending(
    invite_proof_by_peer: &Arc<DashMap<String, String>>,
    peer_id: &libp2p::PeerId,
) -> bool {
    let key = peer_id.to_string();
    let is_pending = invite_proof_by_peer
        .get(&key)
        .is_some_and(|entry| entry.value() == INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER);
    if is_pending {
        invite_proof_by_peer.remove(&key);
    }
    is_pending
}

fn should_send_iroh_handshake(
    hybrid_ratchet: Option<&OutboundHybridRatchetInit>,
    invite_bound: bool,
    ack_response: bool,
    trusted_known_peer_bootstrap: bool,
) -> bool {
    hybrid_ratchet.is_some() || invite_bound || ack_response || trusted_known_peer_bootstrap
}

fn should_send_libp2p_handshake(
    hybrid_ratchet: Option<&OutboundHybridRatchetInit>,
    invite_bound: bool,
    transport_mode: &TransportMode,
    trusted_known_peer_bootstrap: bool,
) -> bool {
    !matches!(transport_mode, TransportMode::Tor)
        || hybrid_ratchet.is_some()
        || invite_bound
        || trusted_known_peer_bootstrap
}

fn write_len_prefixed(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn build_hybrid_ratchet_transcript_hash(
    local_did: &str,
    local_verifying_key: &[u8; 32],
    local_x25519_public: &[u8; 32],
    local_handshake_ratchet_public: &[u8; 32],
    remote_did: &str,
    remote_verifying_key: &[u8; 32],
    remote_x25519_public: &[u8; 32],
    remote_handshake_ratchet_public: &[u8; 32],
) -> [u8; 32] {
    let local_is_initiator = local_did < remote_did;
    let (
        initiator_did,
        initiator_vk,
        initiator_x25519,
        initiator_ratchet,
        responder_did,
        responder_vk,
        responder_x25519,
        responder_ratchet,
    ) = if local_is_initiator {
        (
            local_did.as_bytes(),
            local_verifying_key.as_slice(),
            local_x25519_public.as_slice(),
            local_handshake_ratchet_public.as_slice(),
            remote_did.as_bytes(),
            remote_verifying_key.as_slice(),
            remote_x25519_public.as_slice(),
            remote_handshake_ratchet_public.as_slice(),
        )
    } else {
        (
            remote_did.as_bytes(),
            remote_verifying_key.as_slice(),
            remote_x25519_public.as_slice(),
            remote_handshake_ratchet_public.as_slice(),
            local_did.as_bytes(),
            local_verifying_key.as_slice(),
            local_x25519_public.as_slice(),
            local_handshake_ratchet_public.as_slice(),
        )
    };

    let mut transcript = Vec::with_capacity(512);
    write_len_prefixed(HYBRID_RATCHET_KDF_SUITE_V1.as_bytes(), &mut transcript);
    write_len_prefixed(initiator_did, &mut transcript);
    write_len_prefixed(initiator_vk, &mut transcript);
    write_len_prefixed(initiator_x25519, &mut transcript);
    write_len_prefixed(initiator_ratchet, &mut transcript);
    write_len_prefixed(responder_did, &mut transcript);
    write_len_prefixed(responder_vk, &mut transcript);
    write_len_prefixed(responder_x25519, &mut transcript);
    write_len_prefixed(responder_ratchet, &mut transcript);

    let digest = Sha256::digest(&transcript);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub(crate) fn derive_hybrid_ratchet_seed(
    x25519_shared_secret: &[u8],
    kyber_shared_secret: &[u8],
    local_did: &str,
    local_verifying_key: &[u8; 32],
    local_x25519_public: &[u8; 32],
    local_handshake_ratchet_public: &[u8; 32],
    remote_did: &str,
    remote_verifying_key: &[u8; 32],
    remote_x25519_public: &[u8; 32],
    remote_handshake_ratchet_public: &[u8; 32],
) -> [u8; 32] {
    let transcript_hash = build_hybrid_ratchet_transcript_hash(
        local_did,
        local_verifying_key,
        local_x25519_public,
        local_handshake_ratchet_public,
        remote_did,
        remote_verifying_key,
        remote_x25519_public,
        remote_handshake_ratchet_public,
    );

    let mut ikm = Vec::with_capacity(
        x25519_shared_secret.len() + kyber_shared_secret.len() + transcript_hash.len(),
    );
    ikm.extend_from_slice(x25519_shared_secret);
    ikm.extend_from_slice(kyber_shared_secret);
    ikm.extend_from_slice(&transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-Hybrid-Ratchet-Init-V1"), &ikm);
    let mut seed = [0u8; 32];
    hk.expand(b"Qypha-Hybrid-Ratchet-Seed", &mut seed)
        .expect("HKDF expand 32 bytes");
    ikm.zeroize();
    seed
}

fn prepare_outbound_hybrid_ratchet_init(
    peers: &Arc<DashMap<String, super::peer::PeerInfo>>,
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    our_did: &str,
    peer_id: &libp2p::PeerId,
    peer_did_hint: Option<&str>,
    invite_bound: bool,
) -> Option<OutboundHybridRatchetInit> {
    let peer = peers.get(&peer_id.to_string())?;
    if peer.ratchet_dh_public.is_some() && !invite_bound {
        // Once the peer has already advertised a handshake ratchet key for this live
        // session, do not mint a second hybrid init ciphertext on ordinary handshakes.
        // Invite-bound bootstrap is the one exception: the responder learns the
        // remote ratchet key from the invite consumer's first handshake and must still
        // produce exactly one hybrid init ciphertext in its reciprocal response.
        return None;
    }
    let recipient_kyber = peer.kyber_public_key.clone()?;
    let expected_did = peer_did_hint
        .map(str::to_string)
        .or_else(|| (!peer.did.is_empty()).then(|| peer.did.clone()));
    if !invite_bound
        && expected_did
            .as_deref()
            .is_some_and(|peer_did| our_did > peer_did)
    {
        return None;
    }
    drop(peer);

    let mut rng = rand::thread_rng();
    let (ciphertext, shared_secret) = match pqc_kyber::encapsulate(
        recipient_kyber.as_slice(),
        &mut rng,
    ) {
        Ok((ct, ss)) => (ct, ss),
        Err(error) => {
            tracing::warn!(peer = %peer_id, ?error, "Hybrid ratchet Kyber encapsulation failed");
            return None;
        }
    };

    pending_hybrid_ratchet_inits.insert(
        peer_id.to_string(),
        PendingHybridRatchetInit {
            expected_did,
            suite: HYBRID_RATCHET_KDF_SUITE_V1.to_string(),
            kyber_shared_secret: Zeroizing::new(shared_secret.to_vec()),
        },
    );

    Some(OutboundHybridRatchetInit {
        suite: HYBRID_RATCHET_KDF_SUITE_V1.to_string(),
        kyber_ciphertext_hex: hex::encode(ciphertext),
    })
}

pub(crate) fn take_pending_hybrid_ratchet_init(
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    peer_id: &libp2p::PeerId,
    peer_did: &str,
) -> Option<PendingHybridRatchetInit> {
    let (_, pending) = pending_hybrid_ratchet_inits.remove(&peer_id.to_string())?;
    if pending
        .expected_did
        .as_deref()
        .is_some_and(|expected| expected != peer_did)
    {
        tracing::warn!(
            peer = %peer_id,
            expected = ?pending.expected_did,
            actual = %peer_did,
            "Discarding pending hybrid ratchet init due to DID mismatch"
        );
        return None;
    }
    Some(pending)
}

fn build_handshake_request(
    config: &AppConfig,
    keypair: &AgentKeyPair,
    onion_address: Option<String>,
    iroh_endpoint_addr: Option<String>,
    ratchet_dh_pub_hex: &str,
    invite_code: Option<String>,
    ack_handshake_message_id: Option<String>,
    hybrid_ratchet: Option<OutboundHybridRatchetInit>,
) -> AgentRequest {
    let payload = serde_json::to_vec(&HandshakePayload {
        x25519_public_key: keypair.x25519_public_key_bytes(),
        role: "agent".to_string(),
        onion_address,
        kyber_public_key_hex: hex::encode(&keypair.kyber_public),
        verifying_key_hex: Some(hex::encode(keypair.verifying_key.as_bytes())),
        pqc_enforced: true,
        ratchet_hybrid_kdf_suite: hybrid_ratchet.as_ref().map(|init| init.suite.clone()),
        ratchet_hybrid_kyber_ciphertext_hex: hybrid_ratchet
            .as_ref()
            .map(|init| init.kyber_ciphertext_hex.clone()),
        ratchet_dh_public_hex: Some(ratchet_dh_pub_hex.to_string()),
        aegis_supported: true,
        invite_code,
        iroh_endpoint_addr,
        ack_handshake_message_id,
    })
    .unwrap_or_default();

    let nonce = crate::crypto::next_request_nonce();
    let timestamp = nonce;
    let ttl_ms = config.security.message_ttl_ms;
    let mt_bytes = serde_json::to_vec(&MessageKind::Handshake).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(mt_bytes.len() + payload.len() + 16);
    signed_data.extend_from_slice(&mt_bytes);
    signed_data.extend_from_slice(&payload);
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    signed_data.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing::sign_data(&keypair.signing_key, &signed_data);

    AgentRequest {
        message_id: uuid::Uuid::new_v4().to_string(),
        sender_did: config.agent.did.clone(),
        sender_name: config.agent.name.clone(),
        sender_role: "agent".to_string(),
        msg_type: MessageKind::Handshake,
        payload,
        signature,
        nonce,
        timestamp,
        ttl_ms,
    }
}

fn encode_handshake_iroh_endpoint_addr(endpoint_addr: iroh::EndpointAddr) -> Option<String> {
    crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr(endpoint_addr)
        .ok()
        .and_then(|relay_only| serde_json::to_string(&relay_only).ok())
}

async fn await_iroh_handshake_send<F>(
    send_future: F,
    timeout: std::time::Duration,
) -> anyhow::Result<crate::network::protocol::AgentResponse>
where
    F: Future<Output = anyhow::Result<crate::network::protocol::AgentResponse>>,
{
    match tokio::time::timeout(timeout, send_future).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("iroh handshake send timed out after {}s", timeout.as_secs()),
    }
}

pub(crate) async fn send_handshake_iroh(
    iroh_network: &IrohTransport,
    peers: &Arc<DashMap<String, super::peer::PeerInfo>>,
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    config: &AppConfig,
    keypair: &AgentKeyPair,
    peer_id: &libp2p::PeerId,
    peer_did_hint: Option<&str>,
    ratchet_dh_pub_hex: &str,
    invite_code: Option<String>,
    invite_bound_override: bool,
    ack_handshake_message_id: Option<String>,
    trusted_known_peer_bootstrap: bool,
) -> IrohHandshakeSendOutcome {
    let peer_label = peer_did_hint
        .map(crate::agent::contact_identity::displayed_did)
        .or_else(|| {
            peers.get(&peer_id.to_string()).and_then(|entry| {
                (!entry.value().did.trim().is_empty())
                    .then(|| crate::agent::contact_identity::displayed_did(&entry.value().did))
            })
        })
        .unwrap_or_else(|| peer_id.to_string());
    let iroh_endpoint_addr = encode_handshake_iroh_endpoint_addr(
        iroh_network.endpoint_addr_for_invite(config.network.hide_ip),
    );
    // Invite-bound first contact is special: the invite consumer already has the
    // issuer's PQC key, while the issuer may not yet know the consumer's Kyber key.
    // In that case we still allow the invite consumer to seed the hybrid ratchet.
    let invite_bound = invite_code.is_some() || invite_bound_override;
    let ack_response = ack_handshake_message_id
        .as_deref()
        .is_some_and(|message_id| !message_id.trim().is_empty());
    let hybrid_ratchet = prepare_outbound_hybrid_ratchet_init(
        peers,
        pending_hybrid_ratchet_inits,
        &config.agent.did,
        peer_id,
        peer_did_hint,
        invite_bound,
    );
    if !should_send_iroh_handshake(
        hybrid_ratchet.as_ref(),
        invite_bound,
        ack_response,
        trusted_known_peer_bootstrap,
    ) {
        tracing::info!(
            peer = %peer_label,
            peer_did = ?peer_did_hint,
            "Suppressing proactive iroh handshake without strict hybrid ratchet init"
        );
        return IrohHandshakeSendOutcome::Suppressed;
    }
    let request = build_handshake_request(
        config,
        keypair,
        None,
        iroh_endpoint_addr,
        ratchet_dh_pub_hex,
        invite_code,
        ack_handshake_message_id,
        hybrid_ratchet,
    );
    let message_id = request.message_id.clone();

    if let Err(e) = await_iroh_handshake_send(
        iroh_network.send_request(peer_id, &request),
        std::time::Duration::from_secs(IROH_HANDSHAKE_SEND_TIMEOUT_SECS),
    )
    .await
    {
        let error_text = e.to_string();
        if error_text.contains("No active iroh connection for peer")
            || error_text.contains("read response failed")
            || error_text.contains("iroh handshake send timed out")
        {
            tracing::debug!(
                peer = %peer_label,
                %e,
                "iroh handshake send deferred until connection is live"
            );
        } else {
            tracing::warn!(peer = %peer_label, %e, "iroh handshake send failed");
        }
        IrohHandshakeSendOutcome::Failed
    } else {
        tracing::info!(peer = %peer_label, "iroh handshake sent (signed)");
        IrohHandshakeSendOutcome::Sent(message_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IrohHandshakeSendOutcome {
    Sent(String),
    Suppressed,
    Failed,
}

pub(crate) fn send_handshake(
    network: &mut NetworkNode,
    peers: &Arc<DashMap<String, super::peer::PeerInfo>>,
    pending_hybrid_ratchet_inits: &Arc<DashMap<String, PendingHybridRatchetInit>>,
    config: &AppConfig,
    keypair: &AgentKeyPair,
    peer_id: &libp2p::PeerId,
    peer_did_hint: Option<&str>,
    ratchet_dh_pub_hex: &str,
    invite_code: Option<String>,
    invite_bound_override: bool,
    trusted_known_peer_bootstrap: bool,
) -> bool {
    let invite_bound = invite_code.is_some() || invite_bound_override;
    let hybrid_ratchet = prepare_outbound_hybrid_ratchet_init(
        peers,
        pending_hybrid_ratchet_inits,
        &config.agent.did,
        peer_id,
        peer_did_hint,
        invite_bound,
    );
    if !should_send_libp2p_handshake(
        hybrid_ratchet.as_ref(),
        invite_bound,
        &config.network.transport_mode,
        trusted_known_peer_bootstrap,
    ) {
        tracing::debug!(
            peer = ?peer_did_hint.unwrap_or("unknown"),
            peer_id = %peer_id,
            "Suppressing proactive libp2p handshake without strict hybrid ratchet init"
        );
        return false;
    }
    let request = build_handshake_request(
        config,
        keypair,
        network.onion_address.clone(),
        None,
        ratchet_dh_pub_hex,
        invite_code,
        None,
        hybrid_ratchet,
    );

    network
        .swarm
        .behaviour_mut()
        .messaging
        .send_request(peer_id, request);
    tracing::info!(%peer_id, "Handshake sent (signed, with X25519 key)");
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::daemon::peer;
    use crate::crypto::double_ratchet::{RatchetKeyPair, RatchetState};
    use dashmap::DashMap;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::time::Duration;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    fn make_peer(peer_id: libp2p::PeerId, did: &str, kyber_public_key: Vec<u8>) -> peer::PeerInfo {
        peer::PeerInfo {
            peer_id,
            did: did.to_string(),
            name: "peer".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: Some(kyber_public_key),
            verifying_key: None,
            aegis_supported: false,
            ratchet_dh_public: None,
        }
    }

    fn generate_kyber_public_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        pqc_kyber::keypair(&mut rng).unwrap().public.to_vec()
    }

    #[test]
    fn non_invite_handshake_keeps_single_lexicographic_hybrid_initiator() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let pending = Arc::new(DashMap::new());
        peers.insert(
            peer_id.to_string(),
            make_peer(peer_id, "did:nxf:1000", generate_kyber_public_key()),
        );

        let result = prepare_outbound_hybrid_ratchet_init(
            &peers,
            &pending,
            "did:nxf:9000",
            &peer_id,
            Some("did:nxf:1000"),
            false,
        );

        assert!(result.is_none());
        assert!(pending.is_empty());
    }

    #[test]
    fn invite_bound_handshake_allows_consumer_seed_even_when_did_orders_later() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let pending = Arc::new(DashMap::new());
        peers.insert(
            peer_id.to_string(),
            make_peer(peer_id, "did:nxf:1000", generate_kyber_public_key()),
        );

        let result = prepare_outbound_hybrid_ratchet_init(
            &peers,
            &pending,
            "did:nxf:9000",
            &peer_id,
            Some("did:nxf:1000"),
            true,
        );

        assert!(result.is_some());
        let pending_entry = pending
            .remove(&peer_id.to_string())
            .expect("invite-bound hybrid init should be staged")
            .1;
        assert_eq!(pending_entry.expected_did.as_deref(), Some("did:nxf:1000"));
        assert_eq!(pending_entry.suite, HYBRID_RATCHET_KDF_SUITE_V1);
        assert!(!pending_entry.kyber_shared_secret.is_empty());
    }

    #[test]
    fn invite_bound_handshake_allows_reciprocal_hybrid_init_with_existing_peer_material() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let pending = Arc::new(DashMap::new());
        let mut peer = make_peer(peer_id, "did:nxf:1000", generate_kyber_public_key());
        peer.ratchet_dh_public = Some([9u8; 32]);
        peers.insert(peer_id.to_string(), peer);

        let result = prepare_outbound_hybrid_ratchet_init(
            &peers,
            &pending,
            "did:nxf:9000",
            &peer_id,
            Some("did:nxf:1000"),
            true,
        );

        assert!(result.is_some());
        let pending_entry = pending
            .remove(&peer_id.to_string())
            .expect("invite-bound reciprocal hybrid init should be staged")
            .1;
        assert_eq!(pending_entry.expected_did.as_deref(), Some("did:nxf:1000"));
        assert_eq!(pending_entry.suite, HYBRID_RATCHET_KDF_SUITE_V1);
        assert!(!pending_entry.kyber_shared_secret.is_empty());
    }

    #[test]
    fn responder_seeded_hybrid_init_still_produces_matching_ratchet_session() {
        let initiator_did = "did:nxf:1000";
        let responder_did = "did:nxf:9000";

        let initiator_sign = SigningKey::generate(&mut OsRng);
        let responder_sign = SigningKey::generate(&mut OsRng);
        let initiator_vk = initiator_sign.verifying_key().to_bytes();
        let responder_vk = responder_sign.verifying_key().to_bytes();

        let initiator_x_secret = StaticSecret::random_from_rng(OsRng);
        let initiator_x_public = X25519PublicKey::from(&initiator_x_secret);
        let responder_x_secret = StaticSecret::random_from_rng(OsRng);
        let responder_x_public = X25519PublicKey::from(&responder_x_secret);

        let initiator_handshake = RatchetKeyPair::generate();
        let responder_handshake = RatchetKeyPair::generate();

        let mut rng = rand::thread_rng();
        let initiator_kyber = pqc_kyber::keypair(&mut rng).unwrap();
        let (ciphertext, responder_shared_secret) =
            pqc_kyber::encapsulate(&initiator_kyber.public, &mut rng).unwrap();
        let initiator_shared_secret =
            pqc_kyber::decapsulate(&ciphertext, initiator_kyber.secret.as_slice()).unwrap();

        let initiator_identity_ss = initiator_x_secret.diffie_hellman(&responder_x_public);
        let responder_identity_ss = responder_x_secret.diffie_hellman(&initiator_x_public);

        let initiator_seed = derive_hybrid_ratchet_seed(
            initiator_identity_ss.as_bytes(),
            initiator_shared_secret.as_slice(),
            initiator_did,
            &initiator_vk,
            initiator_x_public.as_bytes(),
            initiator_handshake.public.as_bytes(),
            responder_did,
            &responder_vk,
            responder_x_public.as_bytes(),
            responder_handshake.public.as_bytes(),
        );
        let responder_seed = derive_hybrid_ratchet_seed(
            responder_identity_ss.as_bytes(),
            responder_shared_secret.as_slice(),
            responder_did,
            &responder_vk,
            responder_x_public.as_bytes(),
            responder_handshake.public.as_bytes(),
            initiator_did,
            &initiator_vk,
            initiator_x_public.as_bytes(),
            initiator_handshake.public.as_bytes(),
        );

        assert_eq!(initiator_seed, responder_seed);

        let mut initiator_state =
            RatchetState::init_initiator(&initiator_seed, &responder_handshake.public);
        let mut responder_state = RatchetState::init_responder(
            &responder_seed,
            RatchetKeyPair::from_secret_bytes(responder_handshake.secret.to_bytes()),
        );

        let (header, ciphertext) = initiator_state.encrypt(b"bootstrap").unwrap();
        let plaintext = responder_state.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(plaintext, b"bootstrap");
    }

    #[test]
    fn proactive_iroh_handshake_requires_hybrid_or_explicit_exception() {
        assert!(!should_send_iroh_handshake(None, false, false, false));
        assert!(should_send_iroh_handshake(None, true, false, false));
        assert!(should_send_iroh_handshake(None, false, true, false));
        assert!(should_send_iroh_handshake(None, false, false, true));

        let outbound = OutboundHybridRatchetInit {
            suite: HYBRID_RATCHET_KDF_SUITE_V1.to_string(),
            kyber_ciphertext_hex: "abcd".to_string(),
        };
        assert!(should_send_iroh_handshake(
            Some(&outbound),
            false,
            false,
            false
        ));
    }

    #[test]
    fn proactive_tor_libp2p_handshake_requires_hybrid_or_invite_binding() {
        assert!(!should_send_libp2p_handshake(
            None,
            false,
            &TransportMode::Tor,
            false,
        ));
        assert!(should_send_libp2p_handshake(
            None,
            true,
            &TransportMode::Tor,
            false,
        ));

        let outbound = OutboundHybridRatchetInit {
            suite: HYBRID_RATCHET_KDF_SUITE_V1.to_string(),
            kyber_ciphertext_hex: "abcd".to_string(),
        };
        assert!(should_send_libp2p_handshake(
            Some(&outbound),
            false,
            &TransportMode::Tor,
            false,
        ));
    }

    #[test]
    fn trusted_tor_reconnect_probe_can_send_bootstrap_handshake_without_hybrid() {
        assert!(should_send_libp2p_handshake(
            None,
            false,
            &TransportMode::Tor,
            true,
        ));
    }

    #[test]
    fn non_tor_libp2p_handshake_keeps_legacy_proactive_path() {
        assert!(should_send_libp2p_handshake(
            None,
            false,
            &TransportMode::Tcp,
            false,
        ));
    }

    #[test]
    fn displayed_did_prefers_shareable_hint_for_iroh_handshake_logs() {
        let canonical = "did:nxf:b55c6d5f3f3dedf5e0950cbce02a91eb0b029e582f54a8eaf7a1effde6eb2ffb";
        let label = crate::agent::contact_identity::displayed_did(canonical);
        assert!(label.starts_with("did:qypha:"));
    }

    #[test]
    fn reconnect_race_iroh_handshake_errors_are_expected() {
        let no_active = "No active iroh connection for peer 12D3KooWTest";
        let read_failed = "read response failed";
        let unexpected = "permission denied";

        assert!(
            no_active.contains("No active iroh connection for peer")
                || no_active.contains("read response failed")
        );
        assert!(
            read_failed.contains("No active iroh connection for peer")
                || read_failed.contains("read response failed")
        );
        assert!(
            !(unexpected.contains("No active iroh connection for peer")
                || unexpected.contains("read response failed"))
        );
    }

    #[test]
    fn handshake_iroh_endpoint_payload_omits_empty_relay_set() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[17u8; 32]).public();
        let empty_endpoint =
            iroh::EndpointAddr::from_parts(endpoint_id, std::iter::empty::<iroh::TransportAddr>());

        assert!(encode_handshake_iroh_endpoint_addr(empty_endpoint).is_none());
    }

    #[test]
    fn handshake_iroh_endpoint_payload_preserves_relay_only_endpoint() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[18u8; 32]).public();
        let relay_endpoint = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [iroh::TransportAddr::Relay(
                "https://relay.example.test"
                    .parse::<iroh::RelayUrl>()
                    .expect("valid relay url"),
            )],
        );

        let encoded = encode_handshake_iroh_endpoint_addr(relay_endpoint.clone())
            .expect("relay-only endpoint should be encoded");
        let decoded: iroh::EndpointAddr =
            serde_json::from_str(&encoded).expect("encoded endpoint should decode");
        assert_eq!(decoded, relay_endpoint);
    }

    #[test]
    fn stored_invite_binding_parts_treats_consumer_reciprocal_marker_as_invite_bound() {
        assert_eq!(
            stored_invite_binding_parts(Some(
                INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER.to_string()
            )),
            (None, true)
        );
    }

    #[test]
    fn libp2p_invite_binding_state_advances_from_code_to_consumer_marker() {
        let invite_proof_by_peer = Arc::new(DashMap::new());
        let peer_id = libp2p::PeerId::random();

        advance_libp2p_invite_binding_after_handshake_send(
            &invite_proof_by_peer,
            &peer_id,
            Some("invite-code".to_string()),
            true,
        );

        let stored = invite_proof_by_peer
            .get(&peer_id.to_string())
            .expect("expected invite binding marker");
        assert_eq!(
            stored.value().as_str(),
            INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER
        );
    }

    #[test]
    fn take_invite_consumer_reciprocal_pending_only_clears_exact_marker() {
        let invite_proof_by_peer = Arc::new(DashMap::new());
        let marked_peer = libp2p::PeerId::random();
        let response_bound_peer = libp2p::PeerId::random();
        let raw_code_peer = libp2p::PeerId::random();

        invite_proof_by_peer.insert(
            marked_peer.to_string(),
            INVITE_CONSUMER_AWAITING_RECIPROCAL_MARKER.to_string(),
        );
        invite_proof_by_peer.insert(
            response_bound_peer.to_string(),
            INVITE_RESPONSE_BOUND_MARKER.to_string(),
        );
        invite_proof_by_peer.insert(raw_code_peer.to_string(), "raw-code".to_string());

        assert!(take_invite_consumer_reciprocal_pending(
            &invite_proof_by_peer,
            &marked_peer
        ));
        assert!(!invite_proof_by_peer.contains_key(&marked_peer.to_string()));
        assert!(!take_invite_consumer_reciprocal_pending(
            &invite_proof_by_peer,
            &response_bound_peer
        ));
        assert!(invite_proof_by_peer.contains_key(&response_bound_peer.to_string()));
        assert!(!take_invite_consumer_reciprocal_pending(
            &invite_proof_by_peer,
            &raw_code_peer
        ));
        assert!(invite_proof_by_peer.contains_key(&raw_code_peer.to_string()));
    }

    #[tokio::test]
    async fn iroh_handshake_send_timeout_fails_fast() {
        let result = await_iroh_handshake_send(
            async {
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok(crate::network::protocol::AgentResponse {
                    success: true,
                    message: "ok".to_string(),
                })
            },
            Duration::from_millis(5),
        )
        .await;

        let error = result.expect_err("expected timeout");
        assert!(error.to_string().contains("iroh handshake send timed out"));
    }

    #[tokio::test]
    async fn iroh_handshake_send_timeout_returns_response_when_ready() {
        let result = await_iroh_handshake_send(
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(crate::network::protocol::AgentResponse {
                    success: true,
                    message: "ok".to_string(),
                })
            },
            Duration::from_millis(25),
        )
        .await
        .expect("expected successful response");

        assert!(result.success);
        assert_eq!(result.message, "ok");
    }
}

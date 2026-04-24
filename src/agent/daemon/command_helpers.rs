use super::*;

pub(crate) use super::transfer_shared::{
    build_transfer_accept_request, build_transfer_reject_request, transfer_session_matches,
};

pub(crate) trait ConnectedPeerHandshakeTracker {
    fn clear_peer(&mut self, peer_id: &libp2p::PeerId);
}

impl ConnectedPeerHandshakeTracker for HashSet<libp2p::PeerId> {
    fn clear_peer(&mut self, peer_id: &libp2p::PeerId) {
        self.remove(peer_id);
    }
}

impl ConnectedPeerHandshakeTracker for IrohHandshakeTracker {
    fn clear_peer(&mut self, peer_id: &libp2p::PeerId) {
        clear_iroh_handshake_tracking(self, peer_id);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisconnectNoticeKind {
    ManualDisconnect,
    AgentOffline,
    InviteRejectedUsed,
}

impl DisconnectNoticeKind {
    fn payload(self) -> &'static [u8] {
        match self {
            DisconnectNoticeKind::ManualDisconnect => b"manual_disconnect",
            DisconnectNoticeKind::AgentOffline => b"agent_offline",
            DisconnectNoticeKind::InviteRejectedUsed => b"invite_rejected_used",
        }
    }
}

pub(crate) fn decode_disconnect_notice_kind(payload: &[u8]) -> DisconnectNoticeKind {
    match std::str::from_utf8(payload).ok() {
        Some("manual_disconnect") => DisconnectNoticeKind::ManualDisconnect,
        Some("agent_offline") => DisconnectNoticeKind::AgentOffline,
        Some("invite_rejected_used") => DisconnectNoticeKind::InviteRejectedUsed,
        _ => DisconnectNoticeKind::AgentOffline,
    }
}

pub(crate) fn build_disconnect_notice_request(
    sign_key: &ed25519_dalek::SigningKey,
    config: &AppConfig,
    kind: DisconnectNoticeKind,
) -> AgentRequest {
    let payload = kind.payload().to_vec();
    let nonce = crate::crypto::next_request_nonce();
    let mt_bytes = serde_json::to_vec(&MessageKind::DisconnectNotice).unwrap_or_default();
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
        msg_type: MessageKind::DisconnectNotice,
        payload,
        signature,
        nonce,
        timestamp: nonce,
        ttl_ms: config.security.message_ttl_ms,
    }
}

pub(crate) async fn remove_connected_peer_state(
    peers: &DashMap<String, PeerInfo>,
    invite_proof_by_peer: &DashMap<String, String>,
    handshake_sent: &mut impl ConnectedPeerHandshakeTracker,
    peer_id: &libp2p::PeerId,
) -> Option<PeerInfo> {
    let peer_key = peer_id.to_string();
    invite_proof_by_peer.remove(&peer_key);
    let removed = peers.remove(&peer_key).map(|(_, peer)| peer);
    handshake_sent.clear_peer(peer_id);
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_disconnect_notice_distinguishes_manual_and_offline() {
        assert_eq!(
            decode_disconnect_notice_kind(b"manual_disconnect"),
            DisconnectNoticeKind::ManualDisconnect
        );
        assert_eq!(
            decode_disconnect_notice_kind(b"agent_offline"),
            DisconnectNoticeKind::AgentOffline
        );
        assert_eq!(
            decode_disconnect_notice_kind(b"invite_rejected_used"),
            DisconnectNoticeKind::InviteRejectedUsed
        );
    }

    #[test]
    fn unknown_disconnect_notice_defaults_to_offline() {
        assert_eq!(
            decode_disconnect_notice_kind(b"unexpected_notice"),
            DisconnectNoticeKind::AgentOffline
        );
    }
}

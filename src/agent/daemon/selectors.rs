use dashmap::DashMap;
use std::collections::HashMap;

use crate::network::contact_did::decode_contact_did;

use super::peer::PeerInfo;
use super::transfer_gate::TransferDecisionState;

pub(crate) enum SenderSelectorResolution {
    Resolved { did: String, name: String },
    NotFound,
    Ambiguous(Vec<(String, String)>),
}

pub(crate) enum ConnectedPeerSelectorResolution {
    Resolved(PeerInfo),
    NotFound,
    Ambiguous(Vec<(String, String)>),
}

pub(crate) fn sorted_connected_peer_list(peers: &DashMap<String, PeerInfo>) -> Vec<PeerInfo> {
    let mut peer_list: Vec<PeerInfo> = peers.iter().map(|e| e.value().clone()).collect();
    peer_list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
    peer_list
}

pub(crate) fn sorted_direct_peer_list(
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
) -> Vec<PeerInfo> {
    let mut peer_list: Vec<PeerInfo> = peers
        .iter()
        .filter_map(|entry| {
            let peer = entry.value();
            (is_direct_peer(peer, direct_peer_dids) && peer.verifying_key.is_some())
                .then(|| peer.clone())
        })
        .collect();
    peer_list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
    peer_list
}

pub(crate) fn is_direct_peer(peer: &PeerInfo, direct_peer_dids: &DashMap<String, bool>) -> bool {
    !peer.did.is_empty() && direct_peer_dids.contains_key(&peer.did)
}

pub(crate) fn canonicalize_did_selector(selector: &str) -> Option<String> {
    if selector.starts_with("did:nxf:") {
        return Some(selector.to_string());
    }
    if selector.starts_with("did:qypha:") {
        return decode_contact_did(selector)
            .ok()
            .map(|resolved| resolved.canonical_did);
    }
    None
}

fn resolve_peer_selector_from_list(
    selector: &str,
    peer_list: &[PeerInfo],
) -> ConnectedPeerSelectorResolution {
    if let Ok(idx) = selector.parse::<usize>() {
        if idx == 0 {
            return ConnectedPeerSelectorResolution::NotFound;
        }
        return peer_list
            .get(idx - 1)
            .cloned()
            .map_or(ConnectedPeerSelectorResolution::NotFound, |peer| {
                ConnectedPeerSelectorResolution::Resolved(peer)
            });
    }

    if let Some(canonical_did) = canonicalize_did_selector(selector) {
        return peer_list
            .iter()
            .find(|peer| peer.did == canonical_did)
            .cloned()
            .map_or(ConnectedPeerSelectorResolution::NotFound, |peer| {
                ConnectedPeerSelectorResolution::Resolved(peer)
            });
    }

    if let Some(peer) = peer_list
        .iter()
        .find(|peer| peer.peer_id.to_string() == selector)
        .cloned()
    {
        return ConnectedPeerSelectorResolution::Resolved(peer);
    }

    let mut by_did: HashMap<String, PeerInfo> = HashMap::new();
    for peer in peer_list.iter().cloned() {
        if peer.name.eq_ignore_ascii_case(selector) {
            by_did.entry(peer.did.clone()).or_insert(peer);
        }
    }

    match by_did.len() {
        0 => ConnectedPeerSelectorResolution::NotFound,
        1 => ConnectedPeerSelectorResolution::Resolved(by_did.into_values().next().unwrap()),
        _ => {
            let mut candidates: Vec<(String, String)> = by_did
                .into_values()
                .map(|peer| (peer.did, peer.name))
                .collect();
            candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            ConnectedPeerSelectorResolution::Ambiguous(candidates)
        }
    }
}

pub(crate) fn resolve_sender_selector(
    selector: &str,
    peers: &DashMap<String, PeerInfo>,
    gate: &TransferDecisionState,
) -> SenderSelectorResolution {
    if let Ok(idx) = selector.parse::<usize>() {
        if idx == 0 {
            return SenderSelectorResolution::NotFound;
        }
        let mut peer_list: Vec<PeerInfo> = peers.iter().map(|e| e.value().clone()).collect();
        peer_list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
        return peer_list
            .get(idx - 1)
            .map_or(SenderSelectorResolution::NotFound, |p| {
                SenderSelectorResolution::Resolved {
                    did: p.did.clone(),
                    name: p.name.clone(),
                }
            });
    }

    if let Some(canonical_did) = canonicalize_did_selector(selector) {
        if let Some(peer) = peers.iter().find_map(|e| {
            if e.value().did == canonical_did {
                Some(e.value().clone())
            } else {
                None
            }
        }) {
            return SenderSelectorResolution::Resolved {
                did: peer.did,
                name: peer.name,
            };
        }
        if let Some(name) = gate.sender_name_for_did(&canonical_did) {
            return SenderSelectorResolution::Resolved {
                did: canonical_did,
                name,
            };
        }
        return SenderSelectorResolution::NotFound;
    }

    let mut by_did: HashMap<String, String> = HashMap::new();
    for peer in peers.iter().map(|e| e.value().clone()) {
        if peer.name.eq_ignore_ascii_case(selector) {
            by_did.entry(peer.did).or_insert(peer.name);
        }
    }
    for (did, name) in gate.pending_senders_named(selector) {
        by_did.entry(did).or_insert(name);
    }

    match by_did.len() {
        0 => SenderSelectorResolution::NotFound,
        1 => {
            let (did, name) = by_did.into_iter().next().unwrap();
            SenderSelectorResolution::Resolved { did, name }
        }
        _ => {
            let mut candidates: Vec<(String, String)> = by_did.into_iter().collect();
            candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            SenderSelectorResolution::Ambiguous(candidates)
        }
    }
}

pub(crate) fn resolve_connected_peer_selector(
    selector: &str,
    peers: &DashMap<String, PeerInfo>,
) -> ConnectedPeerSelectorResolution {
    resolve_peer_selector_from_list(selector, &sorted_connected_peer_list(peers))
}

pub(crate) fn resolve_direct_peer_selector(
    selector: &str,
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
) -> ConnectedPeerSelectorResolution {
    resolve_peer_selector_from_list(selector, &sorted_direct_peer_list(peers, direct_peer_dids))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer(did: &str, name: &str, verified: bool) -> PeerInfo {
        PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: None,
            verifying_key: verified.then_some([1u8; 32]),
            aegis_supported: false,
            ratchet_dh_public: None,
        }
    }

    #[test]
    fn sorted_direct_peer_list_excludes_reconnecting_placeholder() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();

        let live = sample_peer("did:nxf:live", "agent1", true);
        let reconnecting = sample_peer("did:nxf:reconnect", "agent2", false);

        direct_peer_dids.insert(live.did.clone(), true);
        direct_peer_dids.insert(reconnecting.did.clone(), true);
        peers.insert(live.peer_id.to_string(), live.clone());
        peers.insert(reconnecting.peer_id.to_string(), reconnecting);

        let listed = sorted_direct_peer_list(&peers, &direct_peer_dids);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].did, live.did);
    }

    #[test]
    fn resolve_sender_selector_accepts_short_contact_did() {
        let peers = DashMap::new();
        let gate = TransferDecisionState::default();
        let canonical_did =
            "did:nxf:0101010101010101010101010101010101010101010101010101010101010101";
        let short_did =
            crate::network::contact_did::contact_did_from_canonical_did(canonical_did).unwrap();
        let peer = sample_peer(canonical_did, "agent1", true);
        peers.insert(peer.peer_id.to_string(), peer.clone());

        match resolve_sender_selector(&short_did, &peers, &gate) {
            SenderSelectorResolution::Resolved { did, name } => {
                assert_eq!(did, canonical_did);
                assert_eq!(name, "agent1");
            }
            _ => panic!("expected short contact did to resolve"),
        }
    }

    #[test]
    fn resolve_connected_peer_selector_accepts_short_contact_did() {
        let peers = DashMap::new();
        let canonical_did =
            "did:nxf:0202020202020202020202020202020202020202020202020202020202020202";
        let short_did =
            crate::network::contact_did::contact_did_from_canonical_did(canonical_did).unwrap();
        let peer = sample_peer(canonical_did, "agent2", true);
        peers.insert(peer.peer_id.to_string(), peer.clone());

        match resolve_connected_peer_selector(&short_did, &peers) {
            ConnectedPeerSelectorResolution::Resolved(resolved) => {
                assert_eq!(resolved.did, canonical_did);
                assert_eq!(resolved.name, "agent2");
            }
            _ => panic!("expected short contact did to resolve"),
        }
    }
}

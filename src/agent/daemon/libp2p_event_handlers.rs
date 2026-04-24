use super::libp2p_event_domains::{
    handle_libp2p_connectivity_event, handle_libp2p_messaging_event,
};
use super::*;
use crate::agent::daemon::incoming_connect_gate::IncomingConnectGate;

pub(crate) struct Libp2pEventHandlerState<'a> {
    pub(crate) network: &'a mut NetworkNode,
    pub(crate) handshake_sent: &'a mut HashSet<libp2p::PeerId>,
    pub(crate) dialing: &'a mut HashSet<libp2p::PeerId>,
    pub(crate) pending_chunk_transfers: &'a mut HashMap<String, PendingChunkTransfer>,
    pub(crate) pending_disconnect_notices:
        &'a mut HashMap<libp2p::request_response::OutboundRequestId, PendingDisconnectNotice>,
    pub(crate) pending_tor_reconnects: &'a mut HashMap<String, PendingTorReconnect>,
    pub(crate) pending_tor_dial_seeds: &'a mut HashMap<u16, KnownPeer>,
    pub(crate) pending_tor_direct_contact_requests:
        &'a mut HashMap<String, PendingTorDirectContactRequest>,
    pub(crate) pending_user_chat_requests:
        &'a mut HashMap<libp2p::request_response::OutboundRequestId, PendingLibp2pUserChatRequest>,
}

pub(crate) struct Libp2pEventHandlerShared<'a> {
    pub(crate) peers_net: &'a Arc<DashMap<String, PeerInfo>>,
    pub(crate) config_net: &'a AppConfig,
    pub(crate) keypair_net: &'a AgentKeyPair,
    pub(crate) audit_net: &'a Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) peer_store_net: &'a Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) group_mailboxes_net: &'a Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) direct_peer_dids_net: &'a Arc<DashMap<String, bool>>,
    pub(crate) invite_proof_net: &'a Arc<DashMap<String, String>>,
    pub(crate) manual_disconnect_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) remote_offline_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) incoming_connect_gate_net: &'a Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) cmd_tx_net: &'a mpsc::Sender<NetworkCommand>,
    pub(crate) pending_hybrid_ratchet_inits_net: &'a Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_mgr_net:
        &'a Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) ratchet_init_pub_hex_net: &'a str,
    pub(crate) msg_tx: &'a mpsc::Sender<crate::network::IncomingRequestEnvelope>,
    pub(crate) active_recv_for_swarm: &'a Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) active_incoming_iroh_transfers_net:
        &'a Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) active_chat_target_did_net: &'a Arc<Mutex<Option<String>>>,
    pub(crate) our_peer_id: libp2p::PeerId,
    pub(crate) no_resume_session_persistence: bool,
}

pub(crate) async fn handle_libp2p_event(
    event: libp2p::swarm::SwarmEvent<crate::network::node::AgentBehaviourEvent>,
    mut state: Libp2pEventHandlerState<'_>,
    shared: Libp2pEventHandlerShared<'_>,
) {
    use libp2p::request_response;
    use libp2p::swarm::SwarmEvent;

    match event {
        event @ (SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Mdns(
            libp2p::mdns::Event::Discovered(_),
        ))
        | SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Mdns(
            libp2p::mdns::Event::Expired(_),
        ))
        | SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Ping(_))
        | SwarmEvent::ConnectionEstablished { .. }
        | SwarmEvent::ConnectionClosed { .. }
        | SwarmEvent::NewListenAddr { .. }
        | SwarmEvent::OutgoingConnectionError { .. }
        | SwarmEvent::IncomingConnectionError { .. }) => {
            handle_libp2p_connectivity_event(event, &mut state, &shared).await
        }
        event @ (SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::Message {
                message: request_response::Message::Request { .. },
                ..
            },
        ))
        | SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::Message {
                message: request_response::Message::Response { .. },
                ..
            },
        ))
        | SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::OutboundFailure { .. },
        ))
        | SwarmEvent::Behaviour(crate::network::node::AgentBehaviourEvent::Messaging(
            request_response::Event::InboundFailure { .. },
        ))) => handle_libp2p_messaging_event(event, &mut state, &shared).await,
        _ => {}
    }
}

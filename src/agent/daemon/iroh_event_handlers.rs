use super::iroh_event_domains::handle_iroh_connection_event;
use super::*;
use crate::agent::daemon::incoming_connect_gate::IncomingConnectGate;

pub(crate) struct IrohEventHandlerState<'a> {
    pub(crate) iroh_network: &'a mut IrohTransport,
    pub(crate) handshake_sent: &'a mut IrohHandshakeTracker,
    pub(crate) pending_iroh_reconnects: &'a mut HashMap<String, PendingIrohReconnect>,
}

pub(crate) struct IrohEventHandlerShared<'a> {
    pub(crate) peers_net: &'a Arc<DashMap<String, PeerInfo>>,
    pub(crate) config_net: &'a AppConfig,
    pub(crate) keypair_net: &'a AgentKeyPair,
    pub(crate) ratchet_mgr_net:
        &'a Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) audit_net: &'a Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) peer_store_net: &'a Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) group_mailboxes_net: &'a Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) direct_peer_dids_net: &'a Arc<DashMap<String, bool>>,
    pub(crate) invite_proof_net: &'a Arc<DashMap<String, String>>,
    pub(crate) incoming_connect_gate_net: &'a Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) manual_disconnect_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) remote_offline_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) pending_hybrid_ratchet_inits_net: &'a Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_pub_hex_net: &'a str,
    pub(crate) iroh_peer_liveness_net: &'a Arc<DashMap<String, IrohPeerLiveness>>,
    pub(crate) iroh_handshake_sync_net: &'a Arc<DashMap<String, IrohHandshakeSyncState>>,
    pub(crate) iroh_authenticated_sessions_net: &'a Arc<IrohAuthenticatedSessionMap>,
    pub(crate) active_incoming_iroh_transfers_net:
        &'a Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) active_chat_target_did_net: &'a Arc<Mutex<Option<String>>>,
}

pub(crate) enum IrohEventHandlerOutcome {
    Continue,
    Break,
}

pub(crate) async fn handle_iroh_event(
    event: Option<IrohNetworkEvent>,
    mut state: IrohEventHandlerState<'_>,
    shared: IrohEventHandlerShared<'_>,
) -> IrohEventHandlerOutcome {
    match event {
        None => IrohEventHandlerOutcome::Break,
        event @ (Some(IrohNetworkEvent::ConnectionEstablished { .. })
        | Some(IrohNetworkEvent::ConnectionClosed { .. })) => {
            handle_iroh_connection_event(event, &mut state, &shared).await;
            IrohEventHandlerOutcome::Continue
        }
    }
}

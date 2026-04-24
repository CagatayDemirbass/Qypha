use super::handshake_request_gate::HandshakeRequestGate;
use super::libp2p_command_domains::{
    handle_libp2p_chat_command, handle_libp2p_connect_did_command,
    handle_libp2p_contact_request_command, handle_libp2p_invite_command,
    handle_libp2p_peer_command, handle_libp2p_transfer_command,
};
use super::*;

pub(crate) struct Libp2pCommandHandlerState<'a> {
    pub(crate) network: &'a mut NetworkNode,
    pub(crate) handshake_sent: &'a mut HashSet<libp2p::PeerId>,
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

pub(crate) struct Libp2pCommandHandlerShared<'a> {
    pub(crate) agent_data_dir: &'a std::path::Path,
    pub(crate) cmd_tx_net: &'a mpsc::Sender<NetworkCommand>,
    pub(crate) receive_dir_config_net: &'a Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    pub(crate) peers_net: &'a Arc<DashMap<String, PeerInfo>>,
    pub(crate) config_net: &'a AppConfig,
    pub(crate) sign_key: &'a ed25519_dalek::SigningKey,
    pub(crate) keypair_net: &'a AgentKeyPair,
    pub(crate) audit_net: &'a Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) rbac_net: &'a Arc<tokio::sync::RwLock<RbacEngine>>,
    pub(crate) peer_store_net: &'a Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) used_invites_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) used_invites_path_net: &'a Option<std::path::PathBuf>,
    pub(crate) used_invites_persist_key_net: &'a Option<[u8; 32]>,
    pub(crate) group_mailboxes_net: &'a Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) handshake_request_gate_net: &'a Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    pub(crate) mailbox_transport_net: &'a Arc<TorMailboxTransport>,
    pub(crate) contact_mailbox_transport_net: &'a Arc<ContactMailboxTransport>,
    pub(crate) contact_bundle_transport_net:
        &'a Arc<crate::network::contact_bundle_transport::ContactBundleTransport>,
    pub(crate) group_invite_bundle_transport_net:
        &'a Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    pub(crate) public_group_invite_bundle_service_net:
        &'a Option<Arc<crate::network::group_invite_bundle_iroh::IrohGroupInviteBundleService>>,
    pub(crate) direct_peer_dids_net: &'a Arc<DashMap<String, bool>>,
    pub(crate) invite_proof_net: &'a Arc<DashMap<String, String>>,
    pub(crate) manual_disconnect_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) ip_hidden_net: &'a Arc<AtomicBool>,
    pub(crate) ratchet_mgr_net:
        &'a Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) pending_hybrid_ratchet_inits_net: &'a Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_pub_hex_net: &'a str,
    pub(crate) pending_contact_requests_net: &'a Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) log_mode_net: &'a LogMode,
    pub(crate) our_peer_id: libp2p::PeerId,
    pub(crate) no_resume_session_persistence: bool,
    pub(crate) no_persistent_artifact_store: bool,
    pub(crate) ram_only_chunk_staging: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Libp2pCommandDomain {
    Chat,
    Transfer,
    ContactRequest,
    ConnectDid,
    Invite,
    Peer,
}

fn libp2p_command_domain(cmd: &NetworkCommand) -> Libp2pCommandDomain {
    match cmd {
        NetworkCommand::SendRatchetBootstrap { .. }
        | NetworkCommand::EnsurePeerHandshake { .. }
        | NetworkCommand::SendChatToPeer { .. }
        | NetworkCommand::SendChatToGroup { .. }
        | NetworkCommand::SendChat { .. } => Libp2pCommandDomain::Chat,
        NetworkCommand::SendFile { .. }
        | NetworkCommand::SendGroupFile { .. }
        | NetworkCommand::SendGroupFastFileAccept { .. }
        | NetworkCommand::TorRedial { .. }
        | NetworkCommand::TorRedialFailed { .. }
        | NetworkCommand::RebindTorTransferPeer { .. }
        | NetworkCommand::SendTransferAccept { .. }
        | NetworkCommand::SendTransferStatus { .. }
        | NetworkCommand::SendTransferReject { .. }
        | NetworkCommand::TransferRejectedByPeer { .. } => Libp2pCommandDomain::Transfer,
        NetworkCommand::SendContactAccept { .. } | NetworkCommand::SendContactReject { .. } => {
            Libp2pCommandDomain::ContactRequest
        }
        NetworkCommand::ConnectDid { .. } => Libp2pCommandDomain::ConnectDid,
        NetworkCommand::GenerateInvite
        | NetworkCommand::CreateNormalGroup { .. }
        | NetworkCommand::CreateAnonymousGroup { .. }
        | NetworkCommand::GenerateGroupInvite { .. }
        | NetworkCommand::GenerateAnonymousGroupInvite { .. }
        | NetworkCommand::SendHandshakeInvite { .. }
        | NetworkCommand::SendHandshakeInviteScoped { .. }
        | NetworkCommand::ConnectInvite { .. } => Libp2pCommandDomain::Invite,
        NetworkCommand::ListPeers
        | NetworkCommand::ListAllPeers
        | NetworkCommand::ListPeersVerbose
        | NetworkCommand::ListGroups
        | NetworkCommand::WhoAmI
        | NetworkCommand::ShowOnion
        | NetworkCommand::DisconnectPeerWithNotice { .. }
        | NetworkCommand::RemotePeerOffline { .. }
        | NetworkCommand::RemotePeerManualDisconnect { .. }
        | NetworkCommand::TorBackgroundDial { .. }
        | NetworkCommand::TorBackgroundDialFailed { .. }
        | NetworkCommand::DisconnectPeerIntent { .. }
        | NetworkCommand::DisconnectKnownPeer { .. }
        | NetworkCommand::DisconnectPeer { .. }
        | NetworkCommand::KickGroupMember { .. }
        | NetworkCommand::LockGroup { .. }
        | NetworkCommand::UnlockGroup { .. }
        | NetworkCommand::LeaveGroup { .. }
        | NetworkCommand::DisbandGroup { .. }
        | NetworkCommand::OutputDone(_) => Libp2pCommandDomain::Peer,
        NetworkCommand::Shutdown(_) => unreachable!("network shutdown is handled by the runtime"),
    }
}

pub(crate) async fn handle_libp2p_command(
    cmd: NetworkCommand,
    mut state: Libp2pCommandHandlerState<'_>,
    shared: Libp2pCommandHandlerShared<'_>,
) {
    match libp2p_command_domain(&cmd) {
        Libp2pCommandDomain::Chat => handle_libp2p_chat_command(cmd, &mut state, &shared).await,
        Libp2pCommandDomain::Transfer => {
            handle_libp2p_transfer_command(cmd, &mut state, &shared).await
        }
        Libp2pCommandDomain::ContactRequest => {
            handle_libp2p_contact_request_command(cmd, &mut state, &shared).await
        }
        Libp2pCommandDomain::ConnectDid => {
            handle_libp2p_connect_did_command(cmd, &mut state, &shared).await
        }
        Libp2pCommandDomain::Invite => handle_libp2p_invite_command(cmd, &mut state, &shared).await,
        Libp2pCommandDomain::Peer => handle_libp2p_peer_command(cmd, &mut state, &shared).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_background_reconnect_commands_route_to_peer_handler() {
        assert_eq!(
            libp2p_command_domain(&NetworkCommand::TorBackgroundDial {
                did: "did:qypha:test".to_string(),
                bridge_port: 9_999,
            }),
            Libp2pCommandDomain::Peer
        );
        assert_eq!(
            libp2p_command_domain(&NetworkCommand::TorBackgroundDialFailed {
                did: "did:qypha:test".to_string(),
            }),
            Libp2pCommandDomain::Peer
        );
    }

    #[test]
    fn transfer_redial_commands_stay_on_transfer_handler() {
        let peer_id = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert_eq!(
            libp2p_command_domain(&NetworkCommand::TorRedial {
                peer_id,
                peer_did: "did:qypha:test".to_string(),
                bridge_port: 9_999,
            }),
            Libp2pCommandDomain::Transfer
        );
        assert_eq!(
            libp2p_command_domain(&NetworkCommand::TorRedialFailed {
                peer_id,
                peer_did: "did:qypha:test".to_string(),
            }),
            Libp2pCommandDomain::Transfer
        );
    }

    #[test]
    fn tor_transfer_rebind_command_routes_to_transfer_handler() {
        let peer_id = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert_eq!(
            libp2p_command_domain(&NetworkCommand::RebindTorTransferPeer {
                peer_id,
                peer_did: "did:qypha:test".to_string(),
                peer_name: "peer".to_string(),
            }),
            Libp2pCommandDomain::Transfer
        );
    }
}

use super::handshake_request_gate::HandshakeRequestGate;
use super::iroh_command_domains::{
    handle_iroh_chat_command, handle_iroh_connect_did_command, handle_iroh_contact_request_command,
    handle_iroh_invite_command, handle_iroh_peer_command, handle_iroh_transfer_command,
};
use super::*;

pub(crate) struct IrohCommandHandlerState<'a> {
    pub(crate) iroh_network: &'a mut IrohTransport,
    pub(crate) handshake_sent: &'a mut IrohHandshakeTracker,
    pub(crate) pending_iroh_chunk_transfers: &'a mut HashMap<String, PendingIrohChunkTransfer>,
    pub(crate) pending_iroh_reconnects: &'a mut HashMap<String, PendingIrohReconnect>,
}

pub(crate) struct IrohCommandHandlerShared<'a> {
    pub(crate) agent_data_dir: &'a std::path::Path,
    pub(crate) receive_dir_config_net: &'a Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    pub(crate) peers_net: &'a Arc<DashMap<String, PeerInfo>>,
    pub(crate) active_incoming_iroh_transfers_net:
        &'a Arc<DashMap<String, ActiveIncomingIrohTransfer>>,
    pub(crate) active_chat_target_did_net: &'a Arc<Mutex<Option<String>>>,
    pub(crate) peer_store_net: &'a Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) config_net: &'a AppConfig,
    pub(crate) sign_key: &'a ed25519_dalek::SigningKey,
    pub(crate) keypair_net: &'a AgentKeyPair,
    pub(crate) audit_net: &'a Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) rbac_net: &'a Arc<tokio::sync::RwLock<RbacEngine>>,
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
    pub(crate) remote_offline_dids_net: &'a Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) ratchet_mgr_net:
        &'a Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) pending_hybrid_ratchet_inits_net: &'a Arc<DashMap<String, PendingHybridRatchetInit>>,
    pub(crate) ratchet_init_pub_hex_net: &'a str,
    pub(crate) pending_contact_requests_net: &'a Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) iroh_peer_liveness_net: &'a Arc<DashMap<String, IrohPeerLiveness>>,
    pub(crate) iroh_handshake_sync_net: &'a Arc<DashMap<String, IrohHandshakeSyncState>>,
    pub(crate) iroh_authenticated_sessions_net: &'a Arc<IrohAuthenticatedSessionMap>,
    pub(crate) log_mode_net: &'a LogMode,
    pub(crate) iroh_config: &'a crate::config::IrohConfig,
    pub(crate) no_persistent_artifact_store: bool,
}

pub(crate) async fn handle_iroh_command(
    cmd: NetworkCommand,
    mut state: IrohCommandHandlerState<'_>,
    shared: IrohCommandHandlerShared<'_>,
) {
    match cmd {
        cmd @ (NetworkCommand::SendRatchetBootstrap { .. }
        | NetworkCommand::EnsurePeerHandshake { .. }
        | NetworkCommand::SendChatToPeer { .. }
        | NetworkCommand::SendChatToGroup { .. }
        | NetworkCommand::SendChat { .. }) => {
            handle_iroh_chat_command(cmd, &mut state, &shared).await
        }
        cmd @ (NetworkCommand::SendFile { .. }
        | NetworkCommand::SendGroupFile { .. }
        | NetworkCommand::SendGroupFastFileAccept { .. }
        | NetworkCommand::RebindTorTransferPeer { .. }
        | NetworkCommand::SendTransferAccept { .. }
        | NetworkCommand::SendTransferStatus { .. }
        | NetworkCommand::SendTransferReject { .. }
        | NetworkCommand::TransferRejectedByPeer { .. }) => {
            handle_iroh_transfer_command(cmd, &mut state, &shared).await
        }
        cmd @ (NetworkCommand::SendContactAccept { .. }
        | NetworkCommand::SendContactReject { .. }) => {
            handle_iroh_contact_request_command(cmd, &mut state, &shared).await
        }
        cmd @ NetworkCommand::ConnectDid { .. } => {
            handle_iroh_connect_did_command(cmd, &mut state, &shared).await
        }
        cmd @ (NetworkCommand::GenerateInvite
        | NetworkCommand::CreateNormalGroup { .. }
        | NetworkCommand::CreateAnonymousGroup { .. }
        | NetworkCommand::GenerateGroupInvite { .. }
        | NetworkCommand::GenerateAnonymousGroupInvite { .. }
        | NetworkCommand::SendHandshakeInvite { .. }
        | NetworkCommand::SendHandshakeInviteScoped { .. }
        | NetworkCommand::ConnectInvite { .. }) => {
            handle_iroh_invite_command(cmd, &mut state, &shared).await
        }
        cmd @ (NetworkCommand::ListPeers
        | NetworkCommand::ListAllPeers
        | NetworkCommand::ListPeersVerbose
        | NetworkCommand::ListGroups
        | NetworkCommand::WhoAmI
        | NetworkCommand::ShowOnion
        | NetworkCommand::TorRedial { .. }
        | NetworkCommand::TorRedialFailed { .. }
        | NetworkCommand::TorBackgroundDial { .. }
        | NetworkCommand::TorBackgroundDialFailed { .. }
        | NetworkCommand::DisconnectPeer { .. }
        | NetworkCommand::DisconnectPeerWithNotice { .. }
        | NetworkCommand::RemotePeerOffline { .. }
        | NetworkCommand::RemotePeerManualDisconnect { .. }
        | NetworkCommand::DisconnectPeerIntent { .. }
        | NetworkCommand::DisconnectKnownPeer { .. }
        | NetworkCommand::KickGroupMember { .. }
        | NetworkCommand::LockGroup { .. }
        | NetworkCommand::UnlockGroup { .. }
        | NetworkCommand::LeaveGroup { .. }
        | NetworkCommand::DisbandGroup { .. }
        | NetworkCommand::OutputDone(_)) => {
            handle_iroh_peer_command(cmd, &mut state, &shared).await
        }
        NetworkCommand::Shutdown(_) => unreachable!("network shutdown is handled by the runtime"),
    }
}

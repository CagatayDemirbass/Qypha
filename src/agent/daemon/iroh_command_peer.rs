use super::group_mailbox::{emit_ui_event, GroupMailboxUiEvent};
use super::iroh_command_handlers::{IrohCommandHandlerShared, IrohCommandHandlerState};
use super::*;

const IROH_MANUAL_DISCONNECT_NOTICE_GRACE_MS: u64 = 750;

struct IrohTransportHandle<'a>(&'a mut IrohTransport);

impl std::ops::Deref for IrohTransportHandle<'_> {
    type Target = IrohTransport;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for IrohTransportHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

async fn clear_remote_offline_iroh_peer_state(
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    handshake_sent: &mut IrohHandshakeTracker,
    peer_id: &libp2p::PeerId,
) {
    let _ = remove_connected_peer_state(peers_net, invite_proof_net, handshake_sent, peer_id).await;
}

fn clear_selected_iroh_peer_target(
    active_chat_target_did_net: &Arc<Mutex<Option<String>>>,
    peer_did: &str,
) {
    let mut cleared = false;
    if let Ok(mut target) = active_chat_target_did_net.lock() {
        if target.as_deref() == Some(peer_did) {
            *target = None;
            cleared = true;
        }
    }
    if cleared {
        set_active_prompt_target_label(None);
    }
}

fn should_use_iroh_manual_disconnect_close_propagation<T, E>(
    _notice_result: &Result<T, E>,
) -> bool {
    // iROH request/response ACK only confirms the peer received bytes on the
    // wire. It does not guarantee the remote application authenticated and
    // processed the ManualDisconnect notice, which is exactly what reconnect
    // suppression depends on. Always propagate the dedicated manual-disconnect
    // close reason for this path.
    true
}

async fn clear_local_iroh_manual_disconnect_state(
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    ratchet_mgr_net: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
) {
    {
        let mut ps = peer_store_net.lock().await;
        ps.remove(peer_did);
    }
    {
        let mut rmgr = ratchet_mgr_net.lock().await;
        rmgr.remove_session(peer_did);
    }
}

fn reset_pending_iroh_transfer_for_remote_offline(
    pending_iroh_chunk_transfers: &mut HashMap<String, PendingIrohChunkTransfer>,
    peer_did: &str,
) -> bool {
    let Some(transfer_key) = pending_iroh_chunk_transfers
        .iter()
        .find(|(_, pending)| pending.peer_did == peer_did)
        .map(|(key, _)| key.clone())
    else {
        return false;
    };
    let Some(pending) = pending_iroh_chunk_transfers.get_mut(&transfer_key) else {
        return false;
    };
    if super::iroh_runtime::iroh_transfer_restart_already_pending(pending) {
        return true;
    }
    super::iroh_runtime::reset_iroh_transfer_for_reapproval(pending);
    pending.retry_after = Some(tokio::time::Instant::now());
    pending.reconnect_wait_secs = 0;
    true
}

fn sorted_group_member_entries(group: &GroupMailboxSummary) -> Vec<(String, String)> {
    if !group.known_members.is_empty() {
        let mut members = group.known_members.clone();
        members.sort_by(|a, b| {
            let a_name = a.display_name.trim().to_lowercase();
            let b_name = b.display_name.trim().to_lowercase();
            a_name
                .cmp(&b_name)
                .then_with(|| a.member_id.cmp(&b.member_id))
        });
        return members
            .into_iter()
            .map(|member| {
                let label = member.display_name.trim().to_string();
                if label.is_empty() {
                    (member.member_id.clone(), member.member_id)
                } else {
                    (label, member.member_id)
                }
            })
            .collect();
    }

    let mut member_ids = group.known_member_ids.clone();
    member_ids.sort();
    member_ids
        .into_iter()
        .map(|member_id| (member_id.clone(), member_id))
        .collect()
}

#[allow(unused_variables)]
pub(crate) async fn handle_iroh_peer_command(
    cmd: NetworkCommand,
    state: &mut IrohCommandHandlerState<'_>,
    shared: &IrohCommandHandlerShared<'_>,
) {
    let mut iroh_network = IrohTransportHandle(state.iroh_network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_iroh_chunk_transfers = &mut *state.pending_iroh_chunk_transfers;
    let pending_iroh_reconnects = &mut *state.pending_iroh_reconnects;
    let peers_net = shared.peers_net;
    let config_net = shared.config_net;
    let sign_key = shared.sign_key;
    let keypair_net = shared.keypair_net;
    let audit_net = shared.audit_net;
    let rbac_net = shared.rbac_net;
    let peer_store_net = shared.peer_store_net;
    let used_invites_net = shared.used_invites_net;
    let used_invites_path_net = shared.used_invites_path_net;
    let group_mailboxes_net = shared.group_mailboxes_net;
    let mailbox_transport_net = shared.mailbox_transport_net;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let remote_offline_dids_net = shared.remote_offline_dids_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let iroh_peer_liveness_net = shared.iroh_peer_liveness_net;
    let iroh_handshake_sync_net = shared.iroh_handshake_sync_net;
    let iroh_authenticated_sessions_net = shared.iroh_authenticated_sessions_net;
    let active_incoming_iroh_transfers_net = shared.active_incoming_iroh_transfers_net;
    let active_chat_target_did_net = shared.active_chat_target_did_net;
    let receive_dir_config_net = shared.receive_dir_config_net;
    let log_mode_net = shared.log_mode_net;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    match cmd {
        NetworkCommand::ListPeers => {
            let peer_list =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);
            emit_headless_direct_peers(shared.agent_data_dir, &peer_list);
            if peer_list.is_empty() {
                println!("   {}", "No direct peers connected.".dimmed());
            } else {
                for (idx, p) in peer_list.iter().enumerate() {
                    let status = if p.x25519_public_key.is_some() && p.verifying_key.is_some() {
                        "E2EE + SigVerify ready".green().to_string()
                    } else {
                        "connecting...".yellow().to_string()
                    };
                    let contact_did = crate::agent::contact_identity::displayed_peer_contact_did(
                        shared.agent_data_dir,
                        &p.did,
                        p.verifying_key,
                    )
                    .unwrap_or_else(|| "not shared yet".to_string());
                    println!(
                        "   {}. {} — {} — {}",
                        (idx + 1).to_string().cyan(),
                        p.name.cyan(),
                        contact_did.green(),
                        status
                    );
                }
            }
        }
        NetworkCommand::ListAllPeers => {
            let known_peers = {
                let ps = peer_store_net.lock().await;
                ps.all_peers().into_iter().cloned().collect::<Vec<_>>()
            };
            let roster =
                collect_direct_peer_roster_entries(peers_net, direct_peer_dids_net, &known_peers);
            emit_headless_direct_peer_roster(shared.agent_data_dir, &roster);
            if roster.is_empty() {
                println!("   {}", "No known direct peers yet.".dimmed());
            } else {
                println!("   {}", "Known direct peers:".yellow().bold());
                for (idx, entry) in roster.iter().enumerate() {
                    let display_did = crate::agent::contact_identity::cached_peer_contact_did(
                        shared.agent_data_dir,
                        &entry.did,
                    )
                    .unwrap_or_else(|| crate::agent::contact_identity::displayed_did(&entry.did));
                    let status = if entry.online {
                        if entry.ready {
                            "online".green().to_string()
                        } else {
                            "connecting".yellow().to_string()
                        }
                    } else {
                        "offline".dimmed().to_string()
                    };
                    let pairing = if entry.paired {
                        if entry.auto_reconnect {
                            "paired".green().to_string()
                        } else {
                            "known".yellow().to_string()
                        }
                    } else {
                        "live-only".dimmed().to_string()
                    };
                    println!(
                        "   {}. {} — {} — {} — {}",
                        (idx + 1).to_string().cyan(),
                        entry.name.cyan(),
                        display_did.green(),
                        status,
                        pairing
                    );
                }
            }
        }
        NetworkCommand::ListPeersVerbose => {
            let peer_list =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);
            emit_headless_direct_peers(shared.agent_data_dir, &peer_list);
            if peer_list.is_empty() {
                println!("   {}", "No direct peers connected.".dimmed());
            } else {
                for (idx, p) in peer_list.iter().enumerate() {
                    println!(
                        "   {}. {} [{}]",
                        (idx + 1).to_string().cyan(),
                        p.name.cyan(),
                        p.peer_id.to_string().dimmed()
                    );
                    if let Some(contact_did) =
                        crate::agent::contact_identity::displayed_peer_contact_did(
                            shared.agent_data_dir,
                            &p.did,
                            p.verifying_key,
                        )
                    {
                        println!("      Contact DID: {}", contact_did.green());
                    } else {
                        println!("      Contact DID: {}", "not shared yet".yellow());
                    }
                    if headless_enabled() {
                        println!("      Internal DID: {}", p.did.dimmed());
                    }
                    println!("      Role: {}", p.role.yellow());
                }
            }
        }
        NetworkCommand::ListGroups => {
            poll_group_mailboxes_for_user_action(
                group_mailboxes_net,
                shared.handshake_request_gate_net,
                mailbox_transport_net,
                audit_net,
                &config_net.agent.did,
                &config_net.agent.name,
                keypair_net,
                receive_dir_config_net,
                log_mode_net,
                shared.agent_data_dir,
            )
            .await;
            let mailbox_groups = {
                let registry = group_mailboxes_net.lock().await;
                registry.summaries()
            };
            let headless = headless_enabled();
            if mailbox_groups.is_empty() {
                if headless {
                    println!("MAILBOX_GROUPS_EMPTY");
                }
                println!("   {}", "No active groups.".dimmed());
            } else {
                if headless {
                    println!("MAILBOX_GROUPS_BEGIN");
                    for group in &mailbox_groups {
                        if let Ok(encoded) = serde_json::to_string(group) {
                            println!("MAILBOX_GROUP {}", encoded);
                        }
                    }
                    println!("MAILBOX_GROUPS_END");
                }
                println!("   {}", "Active groups:".yellow().bold());
                for (idx, group) in mailbox_groups.iter().enumerate() {
                    println!(
                        "   {}. {} ({}) — mailbox {}{}{}{}",
                        (idx + 1).to_string().cyan(),
                        group
                            .group_name
                            .clone()
                            .unwrap_or_else(|| "Unnamed Group".to_string())
                            .cyan(),
                        group.group_id.dimmed(),
                        if group.anonymous_group {
                            "anonymous"
                        } else {
                            "identified"
                        },
                        match group.persistence {
                            GroupMailboxPersistence::MemoryOnly => ", memory-only",
                            GroupMailboxPersistence::EncryptedDisk => ", encrypted-disk",
                        },
                        if group.join_locked { ", locked" } else { "" },
                        if group.degraded { ", degraded" } else { "" }
                    );
                    if let Some(member_id) = group.local_member_id.as_deref() {
                        println!(
                            "      {} {}",
                            "Local member id:".dimmed(),
                            crate::agent::contact_identity::displayed_did(member_id).dimmed()
                        );
                    }
                    if !group.anonymous_group && !group.known_member_ids.is_empty() {
                        println!("      {}", "Known members:".dimmed());
                        for (member_idx, (label, member_id)) in
                            sorted_group_member_entries(group).into_iter().enumerate()
                        {
                            let displayed_member_id =
                                crate::agent::contact_identity::displayed_did(&member_id);
                            if label == member_id {
                                println!(
                                    "        {} {}",
                                    format!("{}.", member_idx + 1).green(),
                                    displayed_member_id.dimmed()
                                );
                            } else {
                                println!(
                                    "        {} {} {}",
                                    format!("{}.", member_idx + 1).green(),
                                    label.green(),
                                    format!("({})", displayed_member_id).dimmed()
                                );
                            }
                        }
                    }
                    if let Some(owner_member_id) = group.owner_member_id.as_deref() {
                        println!(
                            "      {} {}",
                            "Owner member id:".dimmed(),
                            crate::agent::contact_identity::displayed_did(owner_member_id).dimmed()
                        );
                    }
                    println!(
                        "      {} {}",
                        "Mailbox epoch:".dimmed(),
                        group.mailbox_epoch.to_string().dimmed()
                    );
                }
            }
        }
        NetworkCommand::WhoAmI => {
            let contact_did =
                crate::agent::contact_identity::read_agent_contact_did(&config_net.agent.name);
            let direct_peer_count =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net).len();
            let active_group_count = group_mailboxes_net.lock().await.list_group_ids().len();
            emit_headless_whoami(HeadlessWhoAmISnapshot {
                name: config_net.agent.name.clone(),
                did: config_net.agent.did.clone(),
                contact_did: contact_did.clone(),
                peer_id: iroh_network.logical_peer_id().to_string(),
                transport: "Internet".to_string(),
                iroh_id: Some(iroh_network.endpoint_id().to_string()),
                onion: None,
                ip: None,
                relay_routes: Some(
                    iroh_network
                        .endpoint_addr_for_invite(true)
                        .relay_urls()
                        .count() as u64,
                ),
                direct_peers: direct_peer_count,
                groups: active_group_count,
            });
            println!("   {} {}", "Name:".dimmed(), config_net.agent.name.cyan());
            if let Some(contact_did) = contact_did {
                println!("   {} {}", "Contact DID:".dimmed(), contact_did.green());
            } else {
                println!(
                    "   {} {}",
                    "Contact DID:".dimmed(),
                    "not exported yet".yellow()
                );
            }
            println!(
                "   {} {}",
                "Peer ID:".dimmed(),
                iroh_network.logical_peer_id().to_string().dimmed()
            );
            println!(
                "   {} {}",
                "Iroh ID:".dimmed(),
                iroh_network.endpoint_id().to_string().dimmed()
            );
            println!("   {} {}", "Transport:".dimmed(), "Internet".blue());
            let addr = iroh_network.endpoint_addr_for_invite(true);
            println!("   {} {}", "Direct addrs:".dimmed(), "[hidden]".dimmed());
            println!(
                "   {} {}",
                "Relay routes:".dimmed(),
                addr.relay_urls().count()
            );
            println!("   {} {}", "Direct peers:".dimmed(), direct_peer_count);
            println!("   {} {}", "Groups:".dimmed(), active_group_count);
        }
        NetworkCommand::ShowOnion => {
            println!(
                "   {} Not running in Tor mode.",
                "No .onion address:".yellow()
            );
        }
        NetworkCommand::TorRedial { .. }
        | NetworkCommand::TorRedialFailed { .. }
        | NetworkCommand::TorBackgroundDial { .. }
        | NetworkCommand::TorBackgroundDialFailed { .. } => {
            // Not applicable in iroh transport mode.
        }
        NetworkCommand::DisconnectPeer { peer_id } => {
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            iroh_network.disconnect(&peer_id).await;
        }
        NetworkCommand::DisconnectPeerWithNotice {
            peer_id,
            notice_kind,
        } => {
            let notice = build_disconnect_notice_request(&sign_key, &config_net, notice_kind);
            let notice_result = iroh_network.send_request(&peer_id, &notice).await;
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            if matches!(notice_kind, DisconnectNoticeKind::ManualDisconnect) {
                if should_use_iroh_manual_disconnect_close_propagation(&notice_result) {
                    if let Err(error) = notice_result {
                        tracing::warn!(
                            %peer_id,
                            %error,
                            "iroh manual disconnect notice failed before close propagation"
                        );
                    }
                    iroh_network.disconnect_with_propagation(&peer_id).await;
                }
            } else {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    IROH_MANUAL_DISCONNECT_NOTICE_GRACE_MS,
                ))
                .await;
                iroh_network.disconnect(&peer_id).await;
            }
        }
        NetworkCommand::RemotePeerOffline {
            peer_id,
            peer_did,
            peer_name,
        } => {
            clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &peer_id);
            iroh_peer_liveness_net.remove(&peer_id.to_string());
            clear_iroh_handshake_tracking(handshake_sent, &peer_id);
            clear_iroh_handshake_sync(iroh_handshake_sync_net, &peer_id);

            if !peer_did.is_empty() {
                let mut manual = manual_disconnect_dids_net.lock().await;
                manual.remove(&peer_did);
            }
            if !peer_did.is_empty() {
                let mut offline = remote_offline_dids_net.lock().await;
                offline.insert(peer_did.clone());
            }
            let paused_incoming_transfers = mark_active_incoming_iroh_transfers_paused(
                active_incoming_iroh_transfers_net,
                &peer_did,
            );
            reset_pending_iroh_transfer_for_remote_offline(pending_iroh_chunk_transfers, &peer_did);
            super::iroh_event_connection::notify_paused_incoming_iroh_transfers(
                &config_net.agent.name,
                &paused_incoming_transfers,
                false,
            );
            clear_selected_iroh_peer_target(active_chat_target_did_net, &peer_did);

            emit_headless_direct_peer_event(
                "disconnected",
                &peer_did,
                &peer_name,
                Some(&peer_id.to_string()),
                "offline",
                Some("agent_offline"),
            );
            let reconnect_peer = if peer_did.is_empty() {
                None
            } else {
                let ps = peer_store_net.lock().await;
                ps.get(&peer_did).cloned()
            };
            if let Some(known) = reconnect_peer.filter(|known| known.iroh_endpoint_addr.is_some()) {
                queue_iroh_reconnect(pending_iroh_reconnects, &known, true);
            }
            clear_remote_offline_iroh_peer_state(
                peers_net,
                invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            tracing::debug!(
                peer = %peer_name,
                did = %crate::agent::contact_identity::displayed_did(&peer_did),
                "remote offline notice marked peer offline"
            );

            iroh_network.reset_for_reconnect(&peer_id).await;
        }
        NetworkCommand::RemotePeerManualDisconnect {
            peer_id,
            peer_did,
            peer_name,
        } => {
            clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &peer_id);
            iroh_peer_liveness_net.remove(&peer_id.to_string());
            clear_iroh_handshake_tracking(handshake_sent, &peer_id);
            clear_iroh_handshake_sync(iroh_handshake_sync_net, &peer_id);

            {
                let mut manual = manual_disconnect_dids_net.lock().await;
                manual.insert(peer_did.clone());
            }
            {
                let mut offline = remote_offline_dids_net.lock().await;
                offline.remove(&peer_did);
            }
            pending_iroh_reconnects.remove(&peer_did);
            direct_peer_dids_net.remove(&peer_did);
            clear_selected_iroh_peer_target(active_chat_target_did_net, &peer_did);
            clear_local_iroh_manual_disconnect_state(peer_store_net, ratchet_mgr_net, &peer_did)
                .await;

            let live_peer_ids = live_peer_ids_for_did(peers_net, &peer_did);
            for live_peer_id in live_peer_ids {
                let _ = remove_connected_peer_state(
                    &peers_net,
                    &invite_proof_net,
                    handshake_sent,
                    &live_peer_id,
                )
                .await;
                iroh_peer_liveness_net.remove(&live_peer_id.to_string());
                clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &live_peer_id);
                clear_iroh_handshake_tracking(handshake_sent, &live_peer_id);
                clear_iroh_handshake_sync(iroh_handshake_sync_net, &live_peer_id);
                iroh_network.disconnect(&live_peer_id).await;
            }
            emit_headless_direct_peer_event(
                "disconnected",
                &peer_did,
                &peer_name,
                Some(&peer_id.to_string()),
                "offline",
                Some("manual_disconnect"),
            );
            tracing::info!(
                peer = %peer_name,
                did = %crate::agent::contact_identity::displayed_did(&peer_did),
                "remote manual disconnect removed peer and reconnect state"
            );
        }
        NetworkCommand::DisconnectPeerIntent {
            peer_id,
            peer_did,
            peer_name,
        } => {
            {
                let mut manual = manual_disconnect_dids_net.lock().await;
                manual.insert(peer_did.clone());
            }
            pending_iroh_reconnects.remove(&peer_did);
            let notice = build_disconnect_notice_request(
                &sign_key,
                &config_net,
                DisconnectNoticeKind::ManualDisconnect,
            );
            let notice_result = iroh_network.send_request(&peer_id, &notice).await;
            println!(
                "   {} {} ({})",
                "Disconnecting:".yellow().bold(),
                peer_name.cyan(),
                crate::agent::contact_identity::displayed_known_peer_contact_did(
                    shared.agent_data_dir,
                    &peer_did,
                )
                .dimmed()
            );
            emit_headless_direct_peer_event(
                "disconnected",
                &peer_did,
                &peer_name,
                Some(&peer_id.to_string()),
                "offline",
                Some("manual_disconnect"),
            );
            clear_local_iroh_manual_disconnect_state(peer_store_net, ratchet_mgr_net, &peer_did)
                .await;
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            if should_use_iroh_manual_disconnect_close_propagation(&notice_result) {
                if let Err(error) = notice_result {
                    tracing::warn!(
                        %peer_id,
                        did = %peer_did,
                        %error,
                        "iroh manual disconnect notice failed during explicit disconnect before close propagation"
                    );
                }
                iroh_network.disconnect_with_propagation(&peer_id).await;
            }
        }
        NetworkCommand::DisconnectKnownPeer {
            peer_did,
            peer_name,
        } => {
            {
                let mut manual = manual_disconnect_dids_net.lock().await;
                manual.insert(peer_did.clone());
            }
            {
                let mut offline = remote_offline_dids_net.lock().await;
                offline.remove(&peer_did);
            }
            pending_iroh_reconnects.remove(&peer_did);
            direct_peer_dids_net.remove(&peer_did);
            clear_selected_iroh_peer_target(active_chat_target_did_net, &peer_did);
            clear_local_iroh_manual_disconnect_state(peer_store_net, ratchet_mgr_net, &peer_did)
                .await;

            let live_peer_ids = live_peer_ids_for_did(peers_net, &peer_did);
            for live_peer_id in live_peer_ids {
                let _ = remove_connected_peer_state(
                    &peers_net,
                    &invite_proof_net,
                    handshake_sent,
                    &live_peer_id,
                )
                .await;
                iroh_peer_liveness_net.remove(&live_peer_id.to_string());
                clear_iroh_authenticated_session(iroh_authenticated_sessions_net, &live_peer_id);
                clear_iroh_handshake_tracking(handshake_sent, &live_peer_id);
                clear_iroh_handshake_sync(iroh_handshake_sync_net, &live_peer_id);
                let notice = build_disconnect_notice_request(
                    &sign_key,
                    &config_net,
                    DisconnectNoticeKind::ManualDisconnect,
                );
                let notice_result = iroh_network.send_request(&live_peer_id, &notice).await;
                if should_use_iroh_manual_disconnect_close_propagation(&notice_result) {
                    if let Err(error) = notice_result {
                        tracing::warn!(
                            peer_id = %live_peer_id,
                            did = %peer_did,
                            %error,
                            "iroh manual disconnect notice failed for known peer disconnect before close propagation"
                        );
                    }
                    iroh_network
                        .disconnect_with_propagation(&live_peer_id)
                        .await;
                }
            }

            println!(
                "   {} {} ({})",
                "Disconnected:".yellow().bold(),
                peer_name.cyan(),
                crate::agent::contact_identity::displayed_known_peer_contact_did(
                    shared.agent_data_dir,
                    &peer_did,
                )
                .dimmed()
            );
            emit_headless_direct_peer_event(
                "disconnected",
                &peer_did,
                &peer_name,
                None,
                "offline",
                Some("manual_disconnect"),
            );
        }
        NetworkCommand::KickGroupMember { member_selector } => {
            let member_id = member_selector.trim();
            if member_id.is_empty() {
                println!("   Usage: /kick_g <group-member-did>");
                return;
            }
            let kick_plan = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_owner_kick_target(member_id) {
                    Ok((session, target_profile)) => {
                        match plan_owner_kick_rotation(
                            &session,
                            sign_key,
                            &target_profile.member_id,
                        ) {
                            Ok((rotated_session, _, rotation_messages)) => {
                                Ok((session, target_profile, rotated_session, rotation_messages))
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            };
            let (old_session, target_profile, rotated_session, rotation_messages) = match kick_plan
            {
                Ok(plan) => plan,
                Err(error) => {
                    println!("   {} {}", "Group kick failed:".red(), error);
                    return;
                }
            };

            let kick_notice = local_member_profile(&old_session)
                .and_then(|owner_profile| {
                    build_group_kick_notice_message(
                        &old_session,
                        sign_key,
                        &owner_profile,
                        &target_profile,
                        rotated_session.mailbox_epoch,
                        120_000,
                    )
                })
                .ok();

            {
                let mut registry = group_mailboxes_net.lock().await;
                if let Err(error) = registry.insert_session(rotated_session.clone()) {
                    println!("   {} {}", "Group rotation persist failed:".red(), error);
                    return;
                }
            }
            if let Ok(owner_profile) = local_member_profile(&rotated_session) {
                if let Err(error) = announce_local_identified_membership(
                    group_mailboxes_net,
                    mailbox_transport_net,
                    sign_key,
                    &owner_profile,
                    &rotated_session.group_id,
                )
                .await
                {
                    tracing::warn!(
                        group_id = %rotated_session.group_id,
                        %error,
                        "Failed to announce owner membership after kick rotation"
                    );
                }
            }

            if let Some(kick_notice) = kick_notice {
                if let Err(error) =
                    post_group_mailbox_message(mailbox_transport_net, &old_session, &kick_notice)
                        .await
                {
                    println!(
                        "   {} kick notice did not reach {} ({})",
                        "Warning:".yellow().bold(),
                        crate::agent::contact_identity::displayed_did(&target_profile.member_id)
                            .dimmed(),
                        error
                    );
                }
            }

            let mut delivered = Vec::new();
            let mut failed = Vec::new();
            for (recipient_member_id, message) in rotation_messages {
                match post_group_mailbox_message(mailbox_transport_net, &old_session, &message)
                    .await
                {
                    Ok(_) => delivered.push(recipient_member_id),
                    Err(error) => failed.push((recipient_member_id, error.to_string())),
                }
            }

            println!(
                "   {} {} removed from {}. Mailbox epoch is now {}.",
                "Group kick:".yellow().bold(),
                crate::agent::contact_identity::displayed_did(&target_profile.member_id).dimmed(),
                describe_group(&rotated_session).cyan(),
                rotated_session.mailbox_epoch
            );
            emit_ui_event(&GroupMailboxUiEvent {
                kind: "local_kick".to_string(),
                group_id: rotated_session.group_id.clone(),
                group_name: rotated_session.group_name.clone(),
                anonymous_group: rotated_session.anonymous_group,
                manifest_id: None,
                sender_member_id: rotated_session.local_member_id.clone(),
                message: None,
                filename: None,
                size_bytes: None,
                member_id: None,
                member_display_name: None,
                invite_code: None,
                mailbox_epoch: Some(rotated_session.mailbox_epoch),
                kicked_member_id: Some(target_profile.member_id.clone()),
                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
            });
            if !delivered.is_empty() {
                println!(
                    "   {} rotation delivered to {} member(s).",
                    "Mailbox rotation:".dimmed(),
                    delivered.len()
                );
            }
            for (recipient_member_id, error) in failed {
                println!(
                    "   {} rotation did not reach {} ({})",
                    "Warning:".yellow().bold(),
                    crate::agent::contact_identity::displayed_did(&recipient_member_id).dimmed(),
                    error
                );
            }
            let mut audit = audit_net.lock().await;
            audit.record(
                "GROUP_MAILBOX_KICK",
                &config_net.agent.did,
                &format!(
                    "group_id={} kicked_member_id={} epoch={}",
                    rotated_session.group_id,
                    target_profile.member_id,
                    rotated_session.mailbox_epoch
                ),
            );
        }
        NetworkCommand::LockGroup { group_id } => {
            let group_id = group_id.trim().to_string();
            if group_id.is_empty() {
                println!("   Usage: /lock_g <group-id>");
                return;
            }
            let plan = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_owner_access_control_group(&group_id) {
                    Ok(session) => plan_owner_access_rotation(&session, sign_key, true).map(
                        |(rotated_session, rotation_messages)| {
                            (session, rotated_session, rotation_messages)
                        },
                    ),
                    Err(error) => Err(error),
                }
            };
            let (old_session, rotated_session, rotation_messages) = match plan {
                Ok(plan) => plan,
                Err(error) => {
                    println!("   {} {}", "Group lock failed:".red(), error);
                    return;
                }
            };
            {
                let mut registry = group_mailboxes_net.lock().await;
                if let Err(error) = registry.insert_session(rotated_session.clone()) {
                    println!("   {} {}", "Group lock persist failed:".red(), error);
                    return;
                }
            }
            if let Ok(owner_profile) = local_member_profile(&rotated_session) {
                if let Err(error) = announce_local_identified_membership(
                    group_mailboxes_net,
                    mailbox_transport_net,
                    sign_key,
                    &owner_profile,
                    &rotated_session.group_id,
                )
                .await
                {
                    tracing::warn!(
                        group_id = %rotated_session.group_id,
                        %error,
                        "Failed to announce owner membership after lock rotation"
                    );
                }
            }
            let mut delivered = Vec::new();
            let mut failed = Vec::new();
            for (recipient_member_id, message) in rotation_messages {
                match post_group_mailbox_message(mailbox_transport_net, &old_session, &message)
                    .await
                {
                    Ok(_) => delivered.push(recipient_member_id),
                    Err(error) => failed.push((recipient_member_id, error.to_string())),
                }
            }
            let bridge_outcomes = publish_group_join_bridge_updates(
                mailbox_transport_net,
                &rotated_session,
                sign_key,
                GROUP_JOIN_BRIDGE_NOTICE_TTL_MS,
            )
            .await;
            println!(
                "   {} {} is now locked. Mailbox epoch is now {}.",
                "Group lock:".yellow().bold(),
                describe_group(&rotated_session).cyan(),
                rotated_session.mailbox_epoch
            );
            if !delivered.is_empty() {
                println!(
                    "   {} rotation delivered to {} member(s).",
                    "Mailbox rotation:".dimmed(),
                    delivered.len()
                );
            }
            for (recipient_member_id, error) in failed {
                println!(
                    "   {} rotation did not reach {} ({})",
                    "Warning:".yellow().bold(),
                    recipient_member_id.dimmed(),
                    error
                );
            }
            for (invite_epoch, outcome) in bridge_outcomes {
                if let Err(error) = outcome {
                    println!(
                        "   {} join bridge update did not reach invite epoch {} ({})",
                        "Warning:".yellow().bold(),
                        invite_epoch,
                        error
                    );
                }
            }
            let mut audit = audit_net.lock().await;
            audit.record(
                "GROUP_MAILBOX_LOCK",
                &config_net.agent.did,
                &format!(
                    "group_id={} epoch={}",
                    rotated_session.group_id, rotated_session.mailbox_epoch
                ),
            );
            emit_ui_event(&GroupMailboxUiEvent {
                kind: "mailbox_locked".to_string(),
                group_id: rotated_session.group_id.clone(),
                group_name: rotated_session.group_name.clone(),
                anonymous_group: rotated_session.anonymous_group,
                manifest_id: None,
                sender_member_id: rotated_session.local_member_id.clone(),
                message: Some("group locked by owner".to_string()),
                filename: None,
                size_bytes: None,
                member_id: None,
                member_display_name: None,
                invite_code: None,
                mailbox_epoch: Some(rotated_session.mailbox_epoch),
                kicked_member_id: None,
                ts_ms: chrono::Utc::now().timestamp_millis(),
            });
        }
        NetworkCommand::UnlockGroup { group_id } => {
            let group_id = group_id.trim().to_string();
            if group_id.is_empty() {
                println!("   Usage: /unlock_g <group-id>");
                return;
            }
            let plan = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_owner_access_control_group(&group_id) {
                    Ok(session) => plan_owner_access_rotation(&session, sign_key, false).map(
                        |(rotated_session, rotation_messages)| {
                            (session, rotated_session, rotation_messages)
                        },
                    ),
                    Err(error) => Err(error),
                }
            };
            let (old_session, rotated_session, rotation_messages) = match plan {
                Ok(plan) => plan,
                Err(error) => {
                    println!("   {} {}", "Group unlock failed:".red(), error);
                    return;
                }
            };
            {
                let mut registry = group_mailboxes_net.lock().await;
                if let Err(error) = registry.insert_session(rotated_session.clone()) {
                    println!("   {} {}", "Group unlock persist failed:".red(), error);
                    return;
                }
            }
            if let Ok(owner_profile) = local_member_profile(&rotated_session) {
                if let Err(error) = announce_local_identified_membership(
                    group_mailboxes_net,
                    mailbox_transport_net,
                    sign_key,
                    &owner_profile,
                    &rotated_session.group_id,
                )
                .await
                {
                    tracing::warn!(
                        group_id = %rotated_session.group_id,
                        %error,
                        "Failed to announce owner membership after unlock rotation"
                    );
                }
            }
            let mut delivered = Vec::new();
            let mut failed = Vec::new();
            for (recipient_member_id, message) in rotation_messages {
                match post_group_mailbox_message(mailbox_transport_net, &old_session, &message)
                    .await
                {
                    Ok(_) => delivered.push(recipient_member_id),
                    Err(error) => failed.push((recipient_member_id, error.to_string())),
                }
            }
            let bridge_outcomes = publish_group_join_bridge_updates(
                mailbox_transport_net,
                &rotated_session,
                sign_key,
                GROUP_JOIN_BRIDGE_NOTICE_TTL_MS,
            )
            .await;
            println!(
                "   {} {} is now unlocked. Mailbox epoch is now {}.",
                "Group unlock:".yellow().bold(),
                describe_group(&rotated_session).cyan(),
                rotated_session.mailbox_epoch
            );
            if !delivered.is_empty() {
                println!(
                    "   {} rotation delivered to {} member(s).",
                    "Mailbox rotation:".dimmed(),
                    delivered.len()
                );
            }
            for (recipient_member_id, error) in failed {
                println!(
                    "   {} rotation did not reach {} ({})",
                    "Warning:".yellow().bold(),
                    recipient_member_id.dimmed(),
                    error
                );
            }
            for (invite_epoch, outcome) in bridge_outcomes {
                if let Err(error) = outcome {
                    println!(
                        "   {} join bridge update did not reach invite epoch {} ({})",
                        "Warning:".yellow().bold(),
                        invite_epoch,
                        error
                    );
                }
            }
            let mut audit = audit_net.lock().await;
            audit.record(
                "GROUP_MAILBOX_UNLOCK",
                &config_net.agent.did,
                &format!(
                    "group_id={} epoch={}",
                    rotated_session.group_id, rotated_session.mailbox_epoch
                ),
            );
            emit_ui_event(&GroupMailboxUiEvent {
                kind: "mailbox_unlocked".to_string(),
                group_id: rotated_session.group_id.clone(),
                group_name: rotated_session.group_name.clone(),
                anonymous_group: rotated_session.anonymous_group,
                manifest_id: None,
                sender_member_id: rotated_session.local_member_id.clone(),
                message: Some("group unlocked by owner".to_string()),
                filename: None,
                size_bytes: None,
                member_id: None,
                member_display_name: None,
                invite_code: None,
                mailbox_epoch: Some(rotated_session.mailbox_epoch),
                kicked_member_id: None,
                ts_ms: chrono::Utc::now().timestamp_millis(),
            });
        }
        NetworkCommand::LeaveGroup { group_id } => {
            let group_id = group_id.trim().to_string();
            if group_id.is_empty() {
                println!("   Usage: /leave_g <group-id>");
                return;
            }
            poll_group_mailboxes_for_user_action(
                group_mailboxes_net,
                shared.handshake_request_gate_net,
                mailbox_transport_net,
                audit_net,
                &config_net.agent.did,
                &config_net.agent.name,
                keypair_net,
                receive_dir_config_net,
                log_mode_net,
                shared.agent_data_dir,
            )
            .await;
            let session = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_leave_group(&group_id) {
                    Ok(session) => session,
                    Err(error) => {
                        println!("   {} {}", "Group leave failed:".red(), error);
                        return;
                    }
                }
            };
            let group_name = session
                .group_name
                .clone()
                .unwrap_or_else(|| session.group_id.clone());
            let leave_notice_error = if session.anonymous_group {
                None
            } else {
                let local_profile =
                    if session.local_member_id.as_deref() == Some(config_net.agent.did.as_str()) {
                        Ok(build_local_member_profile(
                            keypair_net,
                            &config_net.agent.name,
                        ))
                    } else {
                        local_member_profile(&session)
                    };
                match local_profile {
                    Ok(local_profile) => announce_local_identified_departure(
                        group_mailboxes_net,
                        mailbox_transport_net,
                        sign_key,
                        &local_profile,
                        &session.group_id,
                    )
                    .await
                    .err()
                    .map(|error| error.to_string()),
                    Err(error) => Some(error.to_string()),
                }
            };
            let removed = {
                let mut registry = group_mailboxes_net.lock().await;
                match registry.remove_group(&session.group_id) {
                    Ok(removed) => removed,
                    Err(error) => {
                        println!("   {} {}", "Group leave failed:".red(), error);
                        return;
                    }
                }
            };
            if removed.is_none() {
                println!(
                    "   {} mailbox group {} was not joined.",
                    "Error:".red(),
                    group_id
                );
                return;
            }
            match shutdown_group_mailbox_service(shared.agent_data_dir, &session).await {
                Ok(true) => println!(
                    "   {} {} ({}) — local state forgotten",
                    "Left group:".yellow().bold(),
                    group_name.cyan(),
                    session.group_id.dimmed()
                ),
                Ok(false) => println!(
                    "   {} {} ({}) — local state forgotten",
                    "Left group:".yellow().bold(),
                    group_name.cyan(),
                    session.group_id.dimmed()
                ),
                Err(error) => println!(
                    "   {} {} ({}) — local state forgotten, but cleanup failed: {}",
                    "Group leave warning:".yellow().bold(),
                    group_name.cyan(),
                    session.group_id.dimmed(),
                    error
                ),
            }
            emit_ui_event(&GroupMailboxUiEvent {
                kind: "group_removed".to_string(),
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: session.anonymous_group,
                manifest_id: None,
                sender_member_id: session.local_member_id.clone(),
                message: Some("left group".to_string()),
                filename: None,
                size_bytes: None,
                member_id: session.local_member_id.clone(),
                member_display_name: Some(config_net.agent.name.clone()),
                invite_code: None,
                mailbox_epoch: Some(session.mailbox_epoch),
                kicked_member_id: None,
                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
            });
            if let Some(error) = leave_notice_error {
                println!(
                    "   {} remote roster may stay stale until the next owner rotation ({})",
                    "Leave notice warning:".yellow().bold(),
                    error
                );
            }
        }
        NetworkCommand::DisbandGroup { group_id } => {
            let group_id = group_id.trim().to_string();
            if group_id.is_empty() {
                println!("   Usage: /disband <group-id>");
                return;
            }
            let session = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_owner_disband_group(&group_id) {
                    Ok(session) => session,
                    Err(error) => {
                        println!("   {} {}", "Group disband failed:".red(), error);
                        return;
                    }
                }
            };
            let group_name = session
                .group_name
                .clone()
                .unwrap_or_else(|| session.group_id.clone());
            let mut disband_notice_error = None;
            let mut deferred_shutdown = false;
            if session.anonymous_group {
                disband_notice_error = Some(
                    "anonymous mailbox groups do not yet have an authenticated disband broadcast"
                        .to_string(),
                );
            } else {
                let local_profile =
                    if session.local_member_id.as_deref() == Some(config_net.agent.did.as_str()) {
                        local_member_profile(&session).or_else(|_| {
                            Ok(build_local_member_profile(
                                keypair_net,
                                &config_net.agent.name,
                            ))
                        })
                    } else {
                        local_member_profile(&session)
                    };
                match local_profile.and_then(|local_profile| {
                    build_group_disband_message(
                        &session,
                        sign_key,
                        &local_profile,
                        GROUP_DISBAND_NOTICE_TTL_MS,
                    )
                }) {
                    Ok(message) => {
                        if let Err(error) =
                            post_group_mailbox_message(mailbox_transport_net, &session, &message)
                                .await
                        {
                            disband_notice_error = Some(error.to_string());
                        } else {
                            deferred_shutdown = true;
                        }
                    }
                    Err(error) => {
                        disband_notice_error = Some(error.to_string());
                    }
                }
            }
            let removed = {
                let mut registry = group_mailboxes_net.lock().await;
                match registry.remove_group_as_disbanded(&session.group_id) {
                    Ok(removed) => removed,
                    Err(error) => {
                        println!("   {} {}", "Group disband failed:".red(), error);
                        return;
                    }
                }
            };
            if removed.is_none() {
                println!(
                    "   {} mailbox group {} was not joined.",
                    "Error:".red(),
                    group_id
                );
                return;
            }
            if deferred_shutdown {
                schedule_group_disband_mailbox_shutdown(
                    shared.agent_data_dir.to_path_buf(),
                    session.clone(),
                );
                println!(
                    "   {} {} ({})",
                    "Disbanded group:".yellow().bold(),
                    group_name.cyan(),
                    session.group_id.dimmed()
                );
            } else {
                match shutdown_group_mailbox_service(shared.agent_data_dir, &session).await {
                    Ok(true) => println!(
                        "   {} {} ({})",
                        "Disbanded group:".yellow().bold(),
                        group_name.cyan(),
                        session.group_id.dimmed()
                    ),
                    Ok(false) => println!(
                        "   {} {} ({}) — local state removed; no local relay was active",
                        "Disbanded group:".yellow().bold(),
                        group_name.cyan(),
                        session.group_id.dimmed()
                    ),
                    Err(error) => println!(
                        "   {} {} ({}) — local state removed, but relay cleanup failed: {}",
                        "Group disband warning:".yellow().bold(),
                        group_name.cyan(),
                        session.group_id.dimmed(),
                        error
                    ),
                }
            }
            if let Some(error) = disband_notice_error {
                println!(
                    "   {} remote members may keep retrying until the relay disappears ({})",
                    "Group disband warning:".yellow().bold(),
                    error
                );
            }
            emit_ui_event(&GroupMailboxUiEvent {
                kind: "group_disbanded".to_string(),
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: session.anonymous_group,
                manifest_id: None,
                sender_member_id: session.local_member_id.clone(),
                message: Some("group disbanded by owner".to_string()),
                filename: None,
                size_bytes: None,
                member_id: session.local_member_id.clone(),
                member_display_name: Some(config_net.agent.name.clone()),
                invite_code: None,
                mailbox_epoch: Some(session.mailbox_epoch),
                kicked_member_id: None,
                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
            });
        }
        NetworkCommand::OutputDone(done) => {
            let _ = done.send(());
        }
        _ => unreachable!("unexpected command routed to handle_iroh_peer_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::chunked_transfer;

    fn sample_peer(peer_id: libp2p::PeerId, did: &str, name: &str) -> PeerInfo {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(63);
        PeerInfo {
            peer_id,
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            x25519_public_key: Some([9u8; 32]),
            kyber_public_key: Some(vec![7u8; 32]),
            verifying_key: Some([5u8; 32]),
            aegis_supported: true,
            ratchet_dh_public: Some([3u8; 32]),
        }
    }

    fn sample_known_peer(peer_id: &libp2p::PeerId, did: &str, name: &str) -> KnownPeer {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(64);
        KnownPeer {
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            peer_id: peer_id.to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: Some(hex::encode([9u8; 32])),
            verifying_key_hex: Some(hex::encode([8u8; 32])),
            kyber_public_key_hex: Some(hex::encode(vec![7u8; 32])),
            last_seen: 0,
            auto_reconnect: true,
        }
    }

    #[tokio::test]
    async fn remote_offline_notice_clears_live_peer_state_without_dropping_reconnect() {
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        let invite_proof = Arc::new(DashMap::new());
        let mut handshake_sent = IrohHandshakeTracker::new();
        let mut pending_reconnects = HashMap::new();
        let known = sample_known_peer(&peer_id, "did:nxf:agent2", "agent2");

        peers.insert(
            peer_id.to_string(),
            sample_peer(peer_id, "did:nxf:agent2", "agent2"),
        );
        invite_proof.insert(peer_id.to_string(), "invite-proof".to_string());
        handshake_sent.insert(
            peer_id,
            IrohHandshakeState::SentForSession(tokio::time::Instant::now()),
        );
        assert!(queue_iroh_reconnect(&mut pending_reconnects, &known, true));

        clear_remote_offline_iroh_peer_state(&peers, &invite_proof, &mut handshake_sent, &peer_id)
            .await;

        assert!(pending_reconnects.get("did:nxf:agent2").is_some());
        assert!(peers.get(&peer_id.to_string()).is_none());
        assert!(invite_proof.get(&peer_id.to_string()).is_none());
        assert!(!handshake_sent.contains_key(&peer_id));
    }

    #[test]
    fn clear_selected_iroh_peer_target_clears_matching_prompt_target() {
        let active_target = Arc::new(Mutex::new(Some("did:nxf:agent2".to_string())));

        clear_selected_iroh_peer_target(&active_target, "did:nxf:agent2");

        assert!(active_target.lock().unwrap().is_none());
    }

    #[test]
    fn remote_offline_resets_pending_iroh_transfer_for_reapproval() {
        let sender = AgentKeyPair::generate("sender", "agent");
        let (session, chunks) = chunked_transfer::prepare_session(
            &sender,
            "did:nxf:agent2",
            "payload.bin",
            "confidential",
            b"hello world over iroh transfer",
            4,
        )
        .expect("sample transfer session");
        let peer_id = libp2p::PeerId::random();
        let mut pending = HashMap::new();
        pending.insert(
            peer_id.to_string(),
            PendingIrohChunkTransfer {
                peer_id,
                peer_name: "agent2".to_string(),
                peer_did: "did:nxf:agent2".to_string(),
                session,
                merkle_proof_cache: Vec::new(),
                chunk_source: ChunkSource::InMemory(chunks),
                next_chunk: 6,
                chunk_size: 4,
                x25519_pk: [7u8; 32],
                kyber_pk: vec![8u8; 32],
                ttl: 0,
                path: "/tmp/payload.bin".to_string(),
                packed_mb: 0.0,
                packed_size: 16,
                awaiting_receiver_accept: false,
                awaiting_started_at: tokio::time::Instant::now(),
                approval_poll_after: Some(
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(30),
                ),
                retry_after: Some(
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(30),
                ),
                reconnect_wait_secs: 45,
                needs_reinit: false,
            },
        );

        assert!(reset_pending_iroh_transfer_for_remote_offline(
            &mut pending,
            "did:nxf:agent2",
        ));
        let pending = pending
            .get(&peer_id.to_string())
            .expect("pending transfer should remain");
        assert!(pending.awaiting_receiver_accept);
        assert!(pending.needs_reinit);
        assert!(pending.approval_poll_after.is_none());
        assert!(pending.retry_after.is_some());
        assert_eq!(pending.reconnect_wait_secs, 0);
    }

    #[test]
    fn manual_disconnect_close_propagation_is_always_used_for_manual_disconnect() {
        let delivered: anyhow::Result<()> = Ok(());
        let failed: anyhow::Result<()> = Err(anyhow::anyhow!("send failed"));

        assert!(should_use_iroh_manual_disconnect_close_propagation(
            &delivered
        ));
        assert!(should_use_iroh_manual_disconnect_close_propagation(&failed));
    }

    #[tokio::test]
    async fn clearing_local_manual_disconnect_state_forgets_peer() {
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let ratchet_mgr = Arc::new(tokio::sync::Mutex::new(
            crate::crypto::double_ratchet::RatchetManager::new(None, None),
        ));
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: "did:qypha:peer".to_string(),
                name: "peer".to_string(),
                role: "agent".to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: Some(
                    crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(7),
                ),
                onion_port: 9090,
                encryption_public_key_hex: None,
                verifying_key_hex: None,
                kyber_public_key_hex: None,
                last_seen: 1,
                auto_reconnect: true,
            });
        }

        clear_local_iroh_manual_disconnect_state(&peer_store, &ratchet_mgr, "did:qypha:peer").await;

        let store = peer_store.lock().await;
        assert!(store.get("did:qypha:peer").is_none());
    }
}

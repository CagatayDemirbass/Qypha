use super::group_mailbox::{emit_ui_event, GroupMailboxUiEvent};
use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
use super::*;

const LIBP2P_MANUAL_DISCONNECT_NOTICE_TIMEOUT_MS: u64 = 2_000;
const LIBP2P_TOR_MANUAL_DISCONNECT_NOTICE_TIMEOUT_MS: u64 = 6_000;

struct Libp2pNetworkHandle<'a>(&'a mut NetworkNode);

impl std::ops::Deref for Libp2pNetworkHandle<'_> {
    type Target = NetworkNode;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for Libp2pNetworkHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

fn libp2p_manual_disconnect_notice_timeout_ms(transport_mode: &TransportMode) -> u64 {
    if matches!(transport_mode, TransportMode::Tor) {
        LIBP2P_TOR_MANUAL_DISCONNECT_NOTICE_TIMEOUT_MS
    } else {
        LIBP2P_MANUAL_DISCONNECT_NOTICE_TIMEOUT_MS
    }
}

fn queue_manual_disconnect_notice(
    pending_disconnect_notices: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        PendingDisconnectNotice,
    >,
    request_id: libp2p::request_response::OutboundRequestId,
    peer_id: libp2p::PeerId,
    transport_mode: &TransportMode,
) {
    pending_disconnect_notices.insert(
        request_id,
        PendingDisconnectNotice {
            peer_id,
            deadline: tokio::time::Instant::now()
                + tokio::time::Duration::from_millis(libp2p_manual_disconnect_notice_timeout_ms(
                    transport_mode,
                )),
        },
    );
}

fn clear_pending_tor_dial_seeds_for_did(
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
    did: &str,
) {
    pending_tor_dial_seeds.retain(|_, seed| seed.did != did);
}

async fn clear_local_libp2p_manual_disconnect_state(
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

async fn apply_local_libp2p_manual_disconnect_state(
    pending_tor_reconnects: &mut HashMap<String, PendingTorReconnect>,
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
    direct_peer_dids_net: &Arc<DashMap<String, bool>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    ratchet_mgr_net: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
) {
    pending_tor_reconnects.remove(peer_did);
    clear_pending_tor_dial_seeds_for_did(pending_tor_dial_seeds, peer_did);
    direct_peer_dids_net.remove(peer_did);
    clear_local_libp2p_manual_disconnect_state(peer_store_net, ratchet_mgr_net, peer_did).await;
}

async fn apply_remote_libp2p_manual_disconnect_state(
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    invite_proof_net: &Arc<DashMap<String, String>>,
    handshake_sent: &mut HashSet<libp2p::PeerId>,
    pending_tor_reconnects: &mut HashMap<String, PendingTorReconnect>,
    pending_tor_dial_seeds: &mut HashMap<u16, KnownPeer>,
    direct_peer_dids_net: &Arc<DashMap<String, bool>>,
    manual_disconnect_dids_net: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    ratchet_mgr_net: &Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    peer_did: &str,
) -> Vec<libp2p::PeerId> {
    {
        let mut manual = manual_disconnect_dids_net.lock().await;
        manual.insert(peer_did.to_string());
    }
    pending_tor_reconnects.remove(peer_did);
    clear_pending_tor_dial_seeds_for_did(pending_tor_dial_seeds, peer_did);
    direct_peer_dids_net.remove(peer_did);
    clear_local_libp2p_manual_disconnect_state(peer_store_net, ratchet_mgr_net, peer_did).await;

    let live_peer_ids = live_peer_ids_for_did(peers_net, peer_did);
    for live_peer_id in &live_peer_ids {
        let _ =
            remove_connected_peer_state(peers_net, invite_proof_net, handshake_sent, live_peer_id)
                .await;
    }

    live_peer_ids
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
pub(crate) async fn handle_libp2p_peer_command(
    cmd: NetworkCommand,
    state: &mut Libp2pCommandHandlerState<'_>,
    shared: &Libp2pCommandHandlerShared<'_>,
) {
    let mut network = Libp2pNetworkHandle(state.network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_chunk_transfers = &mut *state.pending_chunk_transfers;
    let pending_disconnect_notices = &mut *state.pending_disconnect_notices;
    let pending_tor_reconnects = &mut *state.pending_tor_reconnects;
    let pending_tor_dial_seeds = &mut *state.pending_tor_dial_seeds;
    let cmd_tx_net = shared.cmd_tx_net;
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
    let ip_hidden_net = shared.ip_hidden_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let receive_dir_config_net = shared.receive_dir_config_net;
    let log_mode_net = shared.log_mode_net;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    let ram_only_chunk_staging = shared.ram_only_chunk_staging;
    match cmd {
        NetworkCommand::ListPeers => {
            let peer_list =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);
            emit_headless_direct_peers(shared.agent_data_dir, &peer_list);
            if peers_net.is_empty() {
                println!("   {}", "No peers connected.".dimmed());
            } else {
                if peer_list.is_empty() {
                    println!("   {}", "No direct peers connected.".dimmed());
                    return;
                }
                println!("   {}", "Connected peers:".yellow().bold());
                for (i, p) in peer_list.iter().enumerate() {
                    let enc_status = if p.x25519_public_key.is_some() {
                        "E2EE ready".green()
                    } else {
                        "no enc key".yellow()
                    };
                    let enc_status = enc_status.to_string();
                    let idx = format!("[{}]", i + 1).cyan().bold();
                    // Short PeerId: first 8 chars after "12D3KooW" prefix
                    let pid_str = p.peer_id.to_string();
                    let short_pid = if pid_str.len() > 16 {
                        format!("{}..{}", &pid_str[..12], &pid_str[pid_str.len() - 4..])
                    } else {
                        pid_str.clone()
                    };
                    let contact_did = crate::agent::contact_identity::displayed_peer_contact_did(
                        shared.agent_data_dir,
                        &p.did,
                        p.verifying_key,
                    )
                    .unwrap_or_else(|| "not shared yet".to_string());
                    if p.role == "unknown" {
                        println!(
                            "   {} {} (connecting...) — {} — {}",
                            idx,
                            short_pid.dimmed(),
                            contact_did.green(),
                            enc_status
                        );
                    } else {
                        println!(
                            "   {} {} ({}) — {} — {}",
                            idx,
                            p.name.cyan(),
                            short_pid.dimmed(),
                            contact_did.green(),
                            enc_status,
                        );
                    }
                }
                println!("   {}", "Use: /transfer <file> <number>".dimmed());
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

        // ── /peers -v: verbose peer list with full PeerId ──
        NetworkCommand::ListPeersVerbose => {
            if peers_net.is_empty() {
                println!("   {}", "No peers connected.".dimmed());
            } else {
                let peer_list =
                    super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);
                emit_headless_direct_peers(shared.agent_data_dir, &peer_list);

                if peer_list.is_empty() {
                    println!("   {}", "No direct peers connected.".dimmed());
                    return;
                }
                println!("   {}", "Connected peers (verbose):".yellow().bold());
                for (i, p) in peer_list.iter().enumerate() {
                    let enc_status = if p.x25519_public_key.is_some() {
                        "E2EE ready".green()
                    } else {
                        "no enc key".yellow()
                    };
                    let idx = format!("[{}]", i + 1).cyan().bold();
                    println!("   {} {} — {}", idx, p.name.cyan(), enc_status,);
                    if let Some(contact_did) =
                        crate::agent::contact_identity::displayed_peer_contact_did(
                            shared.agent_data_dir,
                            &p.did,
                            p.verifying_key,
                        )
                    {
                        println!("       Contact DID: {}", contact_did.green());
                    } else {
                        println!("       Contact DID: {}", "not shared yet".yellow());
                    }
                    if headless_enabled() {
                        println!("       Internal DID: {}", p.did.dimmed());
                    }
                    println!("       Peer ID: {}", p.peer_id.to_string().dimmed());
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

        // ── /whoami: show identity ─────────────────────────
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
                peer_id: our_peer_id.to_string(),
                transport: match config_net.network.transport_mode {
                    TransportMode::Tcp => "LAN".to_string(),
                    TransportMode::Tor => "Tor".to_string(),
                    TransportMode::Internet => "Internet".to_string(),
                },
                iroh_id: None,
                onion: network
                    .onion_address
                    .as_ref()
                    .map(|value| format!("{}.onion", value)),
                ip: matches!(config_net.network.transport_mode, TransportMode::Internet).then(
                    || {
                        if ip_hidden_net.load(Ordering::Relaxed) {
                            "hidden".to_string()
                        } else {
                            "visible".to_string()
                        }
                    },
                ),
                relay_routes: None,
                direct_peers: direct_peer_count,
                groups: active_group_count,
            });
            println!(
                "   {} {}",
                "Name:".yellow().bold(),
                config_net.agent.name.cyan()
            );
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
                our_peer_id.to_string().dimmed()
            );
            let transport_str = match config_net.network.transport_mode {
                TransportMode::Tcp => "LAN",
                TransportMode::Tor => "Tor",
                TransportMode::Internet => "Internet",
            };
            println!("   {} {}", "Transport:".dimmed(), transport_str);
            println!(
                "   {} {}",
                "E2EE:".dimmed(),
                "active (Double Ratchet + AEGIS-256)".green()
            );
            if let Some(ref onion) = network.onion_address {
                println!(
                    "   {} {}",
                    "Onion:".dimmed(),
                    format!("{}.onion", onion).magenta()
                );
            }
            if matches!(config_net.network.transport_mode, TransportMode::Internet) {
                let privacy = if ip_hidden_net.load(Ordering::Relaxed) {
                    "hidden".green()
                } else {
                    "visible".yellow()
                };
                println!("   {} {}", "IP:".dimmed(), privacy);
            }
            println!("   {} {}", "Direct peers:".dimmed(), direct_peer_count);
            println!("   {} {}", "Groups:".dimmed(), active_group_count);
        }

        // ── /invite: generate invite code ────────────────────
        NetworkCommand::ShowOnion => match &network.onion_address {
            Some(onion) => {
                println!(
                    "   {} {}",
                    "Your .onion address:".yellow().bold(),
                    format!("{}.onion", onion).magenta().bold()
                );
            }
            None => {
                println!(
                    "   {} Not running in Tor mode.",
                    "No .onion address:".yellow()
                );
                println!("   {} --transport tor", "Start with:".dimmed());
            }
        },

        // ── Tor re-dial result (from background task) ──
        NetworkCommand::DisconnectPeerIntent {
            peer_id,
            peer_did,
            peer_name,
        } => {
            {
                let mut manual = manual_disconnect_dids_net.lock().await;
                manual.insert(peer_did.clone());
            }
            apply_local_libp2p_manual_disconnect_state(
                pending_tor_reconnects,
                pending_tor_dial_seeds,
                direct_peer_dids_net,
                peer_store_net,
                ratchet_mgr_net,
                &peer_did,
            )
            .await;
            let notice = build_disconnect_notice_request(
                &sign_key,
                &config_net,
                DisconnectNoticeKind::ManualDisconnect,
            );
            let request_id = network
                .swarm
                .behaviour_mut()
                .messaging
                .send_request(&peer_id, notice);
            queue_manual_disconnect_notice(
                pending_disconnect_notices,
                request_id,
                peer_id,
                &config_net.network.transport_mode,
            );
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
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
        }
        NetworkCommand::DisconnectPeer { peer_id } => {
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            if network.swarm.is_connected(&peer_id)
                && network.swarm.disconnect_peer_id(peer_id).is_err()
            {
                tracing::warn!("disconnect_peer_id failed");
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
            apply_local_libp2p_manual_disconnect_state(
                pending_tor_reconnects,
                pending_tor_dial_seeds,
                direct_peer_dids_net,
                peer_store_net,
                ratchet_mgr_net,
                &peer_did,
            )
            .await;

            let live_peer_ids = live_peer_ids_for_did(peers_net, &peer_did);
            let notice = build_disconnect_notice_request(
                &sign_key,
                &config_net,
                DisconnectNoticeKind::ManualDisconnect,
            );
            for live_peer_id in live_peer_ids {
                if network.swarm.is_connected(&live_peer_id) {
                    let request_id = network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&live_peer_id, notice.clone());
                    queue_manual_disconnect_notice(
                        pending_disconnect_notices,
                        request_id,
                        live_peer_id,
                        &config_net.network.transport_mode,
                    );
                }
                let _ = remove_connected_peer_state(
                    &peers_net,
                    &invite_proof_net,
                    handshake_sent,
                    &live_peer_id,
                )
                .await;
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
        NetworkCommand::DisconnectPeerWithNotice {
            peer_id,
            notice_kind,
        } => {
            let notice = build_disconnect_notice_request(&sign_key, &config_net, notice_kind);
            let request_id = network
                .swarm
                .behaviour_mut()
                .messaging
                .send_request(&peer_id, notice);
            let _ = remove_connected_peer_state(
                &peers_net,
                &invite_proof_net,
                handshake_sent,
                &peer_id,
            )
            .await;
            if matches!(notice_kind, DisconnectNoticeKind::ManualDisconnect) {
                queue_manual_disconnect_notice(
                    pending_disconnect_notices,
                    request_id,
                    peer_id,
                    &config_net.network.transport_mode,
                );
            } else {
                let cmd_tx = cmd_tx_net.clone();
                let grace_ms =
                    libp2p_manual_disconnect_notice_timeout_ms(&config_net.network.transport_mode);
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(grace_ms)).await;
                    let _ = cmd_tx
                        .send(NetworkCommand::DisconnectPeer { peer_id })
                        .await;
                });
            }
        }
        NetworkCommand::RemotePeerOffline { .. } => {
            tracing::debug!("Ignoring iroh-only remote offline notice in libp2p peer handler");
        }
        NetworkCommand::RemotePeerManualDisconnect {
            peer_id,
            peer_did,
            peer_name,
        } => {
            let mut peer_ids_to_disconnect = apply_remote_libp2p_manual_disconnect_state(
                peers_net,
                invite_proof_net,
                handshake_sent,
                pending_tor_reconnects,
                pending_tor_dial_seeds,
                direct_peer_dids_net,
                manual_disconnect_dids_net,
                peer_store_net,
                ratchet_mgr_net,
                &peer_did,
            )
            .await;
            if peer_ids_to_disconnect.is_empty() {
                peer_ids_to_disconnect.push(peer_id);
            }
            for live_peer_id in peer_ids_to_disconnect {
                if network.swarm.is_connected(&live_peer_id) {
                    let _ = network.swarm.disconnect_peer_id(live_peer_id);
                }
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
                "remote manual disconnect removed Tor peer and reconnect state"
            );
        }
        NetworkCommand::TorBackgroundDial { did, bridge_port } => {
            let addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bridge_port)
                .parse()
                .expect("valid multiaddr");
            let dial_seed = {
                let ps = peer_store_net.lock().await;
                ps.get(&did).cloned()
            };
            match network.swarm.dial(addr) {
                Ok(()) => {
                    if let Some(seed) = dial_seed {
                        pending_tor_dial_seeds.insert(bridge_port, seed);
                    }
                    clear_tor_reconnect_inflight(pending_tor_reconnects, &did);
                    tracing::debug!(did = %did, "background Tor reconnect dial started");
                }
                Err(error) => {
                    pending_tor_dial_seeds.remove(&bridge_port);
                    clear_tor_reconnect_inflight(pending_tor_reconnects, &did);
                    tracing::debug!(did = %did, %error, "background Tor reconnect dial failed");
                }
            }
        }
        NetworkCommand::TorBackgroundDialFailed { did } => {
            clear_tor_reconnect_inflight(pending_tor_reconnects, &did);
            tracing::debug!(did = %did, "background Tor reconnect bridge reset");
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

        // Sync marker: echo back so the REPL can wait for output
        NetworkCommand::OutputDone(done) => {
            let _ = done.send(());
        }
        _ => unreachable!("unexpected command routed to handle_libp2p_peer_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_manual_disconnect_clears_tor_reconnect_and_persisted_state() {
        let peer_did = "did:qypha:peer";
        let direct_peer_dids = Arc::new(DashMap::new());
        direct_peer_dids.insert(peer_did.to_string(), true);
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: Some(hex::encode([1u8; 32])),
                verifying_key_hex: Some(hex::encode([3u8; 32])),
                kyber_public_key_hex: Some(hex::encode([2u8; 32])),
                last_seen: 1,
                auto_reconnect: true,
            });
        }
        let ratchet_mgr = Arc::new(tokio::sync::Mutex::new(
            crate::crypto::double_ratchet::RatchetManager::new(None, None),
        ));
        {
            let mut rmgr = ratchet_mgr.lock().await;
            let remote = crate::crypto::double_ratchet::RatchetKeyPair::generate();
            rmgr.get_or_init(peer_did, &[9u8; 32], &remote.public, true, Some([7u8; 32]));
            assert!(rmgr.has_session(peer_did));
        }
        let mut pending_tor_reconnects = HashMap::from([(
            peer_did.to_string(),
            PendingTorReconnect {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: "peeronion".to_string(),
                onion_port: 9090,
                next_attempt_at: tokio::time::Instant::now(),
                attempts: 1,
                inflight: true,
            },
        )]);
        let mut pending_tor_dial_seeds = HashMap::from([(
            12345u16,
            KnownPeer {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                peer_id: libp2p::PeerId::random().to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: Some(hex::encode([1u8; 32])),
                verifying_key_hex: Some(hex::encode([3u8; 32])),
                kyber_public_key_hex: Some(hex::encode([2u8; 32])),
                last_seen: 1,
                auto_reconnect: true,
            },
        )]);

        apply_local_libp2p_manual_disconnect_state(
            &mut pending_tor_reconnects,
            &mut pending_tor_dial_seeds,
            &direct_peer_dids,
            &peer_store,
            &ratchet_mgr,
            peer_did,
        )
        .await;

        assert!(!pending_tor_reconnects.contains_key(peer_did));
        assert!(pending_tor_dial_seeds.is_empty());
        assert!(!direct_peer_dids.contains_key(peer_did));
        assert!(peer_store.lock().await.get(peer_did).is_none());
        assert!(!ratchet_mgr.lock().await.has_session(peer_did));
    }

    #[tokio::test]
    async fn remote_manual_disconnect_clears_tor_reconnect_and_peer_state() {
        let peer_did = "did:qypha:peer";
        let peer_id = libp2p::PeerId::random();
        let peers = Arc::new(DashMap::new());
        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                peer_id,
                did: peer_did.to_string(),
                name: "peer".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                x25519_public_key: Some([1u8; 32]),
                kyber_public_key: Some(vec![2u8; 32]),
                verifying_key: Some([3u8; 32]),
                aegis_supported: true,
                ratchet_dh_public: Some([4u8; 32]),
            },
        );
        let invite_proofs = Arc::new(DashMap::new());
        invite_proofs.insert(peer_id.to_string(), "invite-proof".to_string());
        let direct_peer_dids = Arc::new(DashMap::new());
        direct_peer_dids.insert(peer_did.to_string(), true);
        let manual_disconnects = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                peer_id: peer_id.to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: Some(hex::encode([1u8; 32])),
                verifying_key_hex: Some(hex::encode([3u8; 32])),
                kyber_public_key_hex: Some(hex::encode([2u8; 32])),
                last_seen: 1,
                auto_reconnect: true,
            });
        }
        let ratchet_mgr = Arc::new(tokio::sync::Mutex::new(
            crate::crypto::double_ratchet::RatchetManager::new(None, None),
        ));
        let mut handshake_sent = HashSet::from([peer_id]);
        let mut pending_tor_reconnects = HashMap::from([(
            peer_did.to_string(),
            PendingTorReconnect {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                peer_id: peer_id.to_string(),
                onion_address: "peeronion".to_string(),
                onion_port: 9090,
                next_attempt_at: tokio::time::Instant::now(),
                attempts: 1,
                inflight: true,
            },
        )]);
        let mut pending_tor_dial_seeds = HashMap::from([(
            12345u16,
            KnownPeer {
                did: peer_did.to_string(),
                name: "peer".to_string(),
                role: DEFAULT_AGENT_ROLE.to_string(),
                peer_id: peer_id.to_string(),
                onion_address: Some("peeronion".to_string()),
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: Some(hex::encode([1u8; 32])),
                verifying_key_hex: Some(hex::encode([3u8; 32])),
                kyber_public_key_hex: Some(hex::encode([2u8; 32])),
                last_seen: 1,
                auto_reconnect: true,
            },
        )]);

        let removed_live_peer_ids = apply_remote_libp2p_manual_disconnect_state(
            &peers,
            &invite_proofs,
            &mut handshake_sent,
            &mut pending_tor_reconnects,
            &mut pending_tor_dial_seeds,
            &direct_peer_dids,
            &manual_disconnects,
            &peer_store,
            &ratchet_mgr,
            peer_did,
        )
        .await;

        assert_eq!(removed_live_peer_ids, vec![peer_id]);
        assert!(!peers.contains_key(&peer_id.to_string()));
        assert!(!invite_proofs.contains_key(&peer_id.to_string()));
        assert!(!handshake_sent.contains(&peer_id));
        assert!(!pending_tor_reconnects.contains_key(peer_did));
        assert!(pending_tor_dial_seeds.is_empty());
        assert!(!direct_peer_dids.contains_key(peer_did));
        assert!(peer_store.lock().await.get(peer_did).is_none());
        assert!(manual_disconnects.lock().await.contains(peer_did));
    }
}

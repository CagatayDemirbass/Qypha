use super::iroh_command_handlers::{IrohCommandHandlerShared, IrohCommandHandlerState};
use super::transfer_shared::build_transfer_status_request;
use super::*;
use crate::agent::daemon::group_mailbox::decode_group_chunk_capability;
use crate::network::protocol::{GroupFastFileOfferPayload, GroupFileManifestPayload};

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

fn resolve_direct_iroh_transfer_peer(
    peers_net: &Arc<DashMap<String, PeerInfo>>,
    direct_peer_dids_net: &Arc<DashMap<String, bool>>,
    peer_selector: &str,
) -> Option<PeerInfo> {
    let peer_list = super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);
    if let Ok(idx) = peer_selector.parse::<usize>() {
        if idx >= 1 && idx <= peer_list.len() {
            return Some(peer_list[idx - 1].clone());
        }
        return None;
    }

    peer_list
        .iter()
        .find(|p| {
            p.name.eq_ignore_ascii_case(peer_selector)
                || p.peer_id.to_string() == peer_selector
                || p.did == peer_selector
        })
        .cloned()
}

async fn send_iroh_file_to_peer(
    iroh_network: &mut IrohTransport,
    pending_iroh_chunk_transfers: &mut HashMap<String, PendingIrohChunkTransfer>,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    audit_net: &Arc<tokio::sync::Mutex<AuditLog>>,
    rbac_net: &Arc<tokio::sync::RwLock<RbacEngine>>,
    no_persistent_artifact_store: bool,
    path: String,
    peer_info: PeerInfo,
) -> bool {
    if pending_iroh_chunk_transfers.contains_key(&peer_info.peer_id.to_string()) {
        println!(
            "   {} transfer to {} is already in progress.",
            "Busy:".yellow().bold(),
            peer_info.name.cyan()
        );
        return false;
    }

    let allowed = {
        let r = rbac_net.read().await;
        r.can_transfer_to(&config_net.agent.did, &peer_info.did)
    };
    if !allowed {
        println!(
            "   {} transfer to {} denied by RBAC policy",
            "POLICY REJECT:".red().bold(),
            peer_info.name.cyan()
        );
        return false;
    }

    let Some(x25519_pk) = peer_info.x25519_public_key else {
        println!(
            "   {} Peer has no X25519 key — not fully handshaked yet.",
            "Warning:".yellow()
        );
        return false;
    };
    let Some(kyber_pk) = peer_info.kyber_public_key.clone() else {
        println!(
            "   {} peer {} has no Kyber key — PQC required, transfer blocked",
            "SECURITY REJECT:".red().bold(),
            peer_info.name.cyan()
        );
        return false;
    };

    let source = std::path::Path::new(&path);
    if !source.exists() {
        println!("   {} Path does not exist: {}", "Error:".red(), path);
        return false;
    }
    let total_size: u64 = if source.is_file() {
        source.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        walkdir::WalkDir::new(source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
            .sum()
    };

    let threshold = config_net.transfer.large_file_threshold;
    let size_mb = total_size as f64 / (1024.0 * 1024.0);
    if total_size <= threshold as u64 {
        println!(
            "   {} {} ({:.1} MB) -> {} ...",
            "Encrypting:".yellow(),
            path,
            size_mb,
            peer_info.name.cyan()
        );
        let build_fn = if no_persistent_artifact_store {
            transfer::build_encrypted_transfer_zero_trace
        } else {
            transfer::build_encrypted_transfer
        };
        match build_fn(
            keypair_net,
            &x25519_pk,
            Some(kyber_pk.as_slice()),
            &peer_info.did,
            &path,
            "confidential",
        ) {
            Err(e) => {
                println!("   {} {}", "Encrypt failed:".red(), e);
                false
            }
            Ok(transfer_payload) => {
                match transfer::wrap_as_request(keypair_net, transfer_payload) {
                    Err(e) => {
                        println!("   {} {}", "Wrap failed:".red(), e);
                        false
                    }
                    Ok(request) => {
                        if iroh_network
                            .send_request(&peer_info.peer_id, &request)
                            .await
                            .is_ok()
                        {
                            println!(
                                "   {} {} ({:.1} MB) -> {} [E2EE + signed]",
                                "Sent:".green().bold(),
                                path,
                                size_mb,
                                peer_info.name.cyan(),
                            );
                            {
                                let mut a = audit_net.lock().await;
                                a.record(
                                    "FILE_SEND",
                                    &config_net.agent.did,
                                    &format!(
                                        "path={} to={} size={} transport=iroh",
                                        path, peer_info.did, total_size
                                    ),
                                );
                            }
                            emit_transfer_event(
                                "outgoing_pending",
                                "out",
                                Some(&peer_info.did),
                                Some(&peer_info.name),
                                None,
                                Some(&path),
                                Some("awaiting_receiver_decision"),
                            );
                            true
                        } else {
                            println!("   {} transport send failed", "Error:".red());
                            false
                        }
                    }
                }
            }
        }
    } else {
        let chunk_size = IROH_DIRECT_CHUNK_SIZE_BYTES;
        println!(
            "   {} {} ({:.1} MB) -> {} [chunked, {} MB/chunk]",
            "Packing:".yellow(),
            path,
            size_mb,
            peer_info.name.cyan(),
            chunk_size / (1024 * 1024),
        );
        emit_transfer_event(
            "outgoing_packing",
            "out",
            Some(&peer_info.did),
            Some(&peer_info.name),
            None,
            Some(&path),
            Some("packing_transfer_payload"),
        );
        let source_owned = source.to_path_buf();
        let pack_result =
            tokio::task::spawn_blocking(move || chunked_transfer::pack_to_temp_file(&source_owned))
                .await
                .map_err(|e| anyhow::anyhow!("Pack task panicked: {}", e))
                .and_then(|r| r);
        match pack_result {
            Err(e) => {
                println!("   {} {}", "Pack failed:".red(), e);
                false
            }
            Ok(temp_path) => {
                let packed_size = std::fs::metadata(&temp_path).map(|m| m.len()).unwrap_or(0);
                let packed_mb = packed_size as f64 / (1024.0 * 1024.0);
                println!(
                    "   {} {:.1} MB -> {:.1} MB packed",
                    "Packed:".green(),
                    size_mb,
                    packed_mb
                );
                emit_transfer_event(
                    "outgoing_preparing",
                    "out",
                    Some(&peer_info.did),
                    Some(&peer_info.name),
                    None,
                    Some(&path),
                    Some("preparing_transfer_session"),
                );
                let filename = source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("payload.bin")
                    .to_string();
                let kp_clone = keypair_net.clone();
                let did_clone = peer_info.did.clone();
                let filename_clone = filename.clone();
                let temp_path_clone = temp_path.clone();
                let session_result = tokio::task::spawn_blocking(move || {
                    chunked_transfer::prepare_session_streaming(
                        &kp_clone,
                        &did_clone,
                        &filename_clone,
                        "confidential",
                        &temp_path_clone,
                        chunk_size,
                    )
                })
                .await
                .map_err(|e| anyhow::anyhow!("Session task panicked: {}", e))
                .and_then(|r| r);
                match session_result {
                    Err(e) => {
                        println!("   {} {}", "Session prep failed:".red(), e);
                        secure_wipe_file_async(temp_path).await;
                        false
                    }
                    Ok(session) => {
                        let session_for_cache = session.clone();
                        let proof_cache_result = tokio::task::spawn_blocking(move || {
                            chunked_transfer::build_serialized_merkle_proof_cache(
                                &session_for_cache,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("Merkle proof task panicked: {}", e))
                        .and_then(|r| r);
                        let merkle_proof_cache = match proof_cache_result {
                            Err(e) => {
                                println!("   {} {}", "Merkle prep failed:".red(), e);
                                secure_wipe_file_async(temp_path).await;
                                return false;
                            }
                            Ok(cache) => cache,
                        };
                        let (init_payload, _) =
                            chunked_transfer::build_sealed_init_payload(&session, keypair_net);
                        match bincode::serialize(&init_payload) {
                            Err(e) => {
                                println!("   {} {}", "Init encode failed:".red(), e);
                                secure_wipe_file_async(temp_path).await;
                                false
                            }
                            Ok(init_bytes) => {
                                match chunked_transfer::wrap_chunk_request(
                                    keypair_net,
                                    MessageKind::ChunkTransferInit,
                                    init_bytes,
                                    config_net.security.message_ttl_ms,
                                ) {
                                    Err(e) => {
                                        println!("   {} {}", "Init wrap failed:".red(), e);
                                        secure_wipe_file_async(temp_path).await;
                                        false
                                    }
                                    Ok(init_request) => {
                                        if iroh_network
                                            .send_request(&peer_info.peer_id, &init_request)
                                            .await
                                            .is_err()
                                        {
                                            println!("   {} init send failed", "Error:".red());
                                            secure_wipe_file_async(temp_path).await;
                                            return false;
                                        }
                                        println!(
                                            "   Init sent: session {} ({} chunks, sealed v2, disk-stream)",
                                            session.session_id.dimmed(),
                                            session.total_chunks
                                        );
                                        println!(
                                            "   {} waiting for receiver /accept before sending chunks",
                                            "Pending:".yellow().bold()
                                        );
                                        emit_transfer_event(
                                            "outgoing_pending",
                                            "out",
                                            Some(&peer_info.did),
                                            Some(&peer_info.name),
                                            Some(&session.session_id),
                                            Some(&path),
                                            Some("awaiting_receiver_decision"),
                                        );

                                        if let Some(mut replaced) = pending_iroh_chunk_transfers
                                            .insert(
                                                peer_info.peer_id.to_string(),
                                                PendingIrohChunkTransfer {
                                                    peer_id: peer_info.peer_id,
                                                    peer_name: peer_info.name.clone(),
                                                    peer_did: peer_info.did.clone(),
                                                    session,
                                                    merkle_proof_cache,
                                                    chunk_source: ChunkSource::TempFile(temp_path),
                                                    next_chunk: 0,
                                                    chunk_size,
                                                    x25519_pk,
                                                    kyber_pk,
                                                    ttl: config_net.security.message_ttl_ms,
                                                    path,
                                                    packed_mb,
                                                    packed_size,
                                                    awaiting_receiver_accept: true,
                                                    awaiting_started_at: tokio::time::Instant::now(
                                                    ),
                                                    approval_poll_after: None,
                                                    retry_after: None,
                                                    reconnect_wait_secs: 0,
                                                    needs_reinit: false,
                                                },
                                            )
                                        {
                                            replaced.chunk_source.secure_cleanup_async().await;
                                        }
                                        true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[allow(unused_variables)]
pub(crate) async fn handle_iroh_transfer_command(
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
    let used_invites_net = shared.used_invites_net;
    let used_invites_path_net = shared.used_invites_path_net;
    let group_mailboxes_net = shared.group_mailboxes_net;
    let mailbox_transport_net = shared.mailbox_transport_net;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let iroh_config = shared.iroh_config;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    match cmd {
        NetworkCommand::SendFile {
            path,
            peer_selector,
        } => {
            let Some(peer_info) =
                resolve_direct_iroh_transfer_peer(peers_net, direct_peer_dids_net, &peer_selector)
            else {
                println!(
                    "   {} peer '{}' not found. Use /peers to see numbered list.",
                    "Error:".red(),
                    peer_selector
                );
                return;
            };
            send_iroh_file_to_peer(
                &mut iroh_network,
                pending_iroh_chunk_transfers,
                config_net,
                keypair_net,
                audit_net,
                rbac_net,
                no_persistent_artifact_store,
                path,
                peer_info,
            )
            .await;
        }
        NetworkCommand::SendGroupFile { group_id, path } => {
            let session = {
                let registry = group_mailboxes_net.lock().await;
                registry.get_cloned(&group_id)
            };
            let Some(session) = session else {
                println!(
                    "   {} mailbox group {} is not joined. Use /groups to inspect active mailbox groups.",
                    "Error:".red().bold(),
                    group_id.cyan()
                );
                return;
            };
            let fast_endpoint_addr = iroh_network.fast_transfer_endpoint_addr_for_grant();
            let (mailbox_message, mut prepared_fast_transfer) =
                match build_file_manifest_message_with_prepared_fast_transfer(
                    mailbox_transport_net,
                    &session,
                    keypair_net,
                    &path,
                    config_net.security.message_ttl_ms,
                    fast_endpoint_addr.is_some(),
                )
                .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        println!("   {} {}", "Group mailbox transfer rejected:".red(), e);
                        return;
                    }
                };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(receipt) => {
                    let maybe_manifest =
                        decode_group_mailbox_message_payload(&session, &mailbox_message)
                            .ok()
                            .and_then(|plaintext| {
                                serde_json::from_slice::<GroupFileManifestPayload>(&plaintext).ok()
                            });
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
                        if let (Some(manifest), Some(prepared_fast_transfer)) =
                            (maybe_manifest.as_ref(), prepared_fast_transfer.take())
                        {
                            let endpoint_addr_json = fast_endpoint_addr
                                .as_ref()
                                .and_then(|endpoint| serde_json::to_string(endpoint).ok())
                                .unwrap_or_default();
                            let endpoint_verifying_key_hex =
                                hex::encode(keypair_net.verifying_key.as_bytes());
                            let _ = stage_sender_fast_file_transfer_from_prepared(
                                &mut registry,
                                &session,
                                manifest,
                                prepared_fast_transfer,
                                endpoint_addr_json,
                                endpoint_verifying_key_hex,
                            );
                        }
                    }
                    if let Some(prepared_fast_transfer) = prepared_fast_transfer.take() {
                        secure_wipe_file_async(prepared_fast_transfer.packed_path).await;
                    }
                    if let Some(manifest) = maybe_manifest.as_ref() {
                        if let (Some(transfer_id), Some(expires_at)) = (
                            manifest.fast_transfer_id.as_ref(),
                            manifest.fast_transfer_expires_at,
                        ) {
                            let staged = {
                                let registry = group_mailboxes_net.lock().await;
                                registry.staged_fast_file_transfer_cloned(transfer_id)
                            };
                            if let Some(staged) = staged {
                                let offer = GroupFastFileOfferPayload {
                                    transfer_id: transfer_id.clone(),
                                    manifest_id: manifest.manifest_id.clone(),
                                    filename: staged.filename.clone(),
                                    size_bytes: staged.size_bytes,
                                    plaintext_sha256: staged.plaintext_sha256.clone(),
                                    merkle_root: staged.merkle_root,
                                    sender_verifying_key_hex: hex::encode(
                                        keypair_net.verifying_key.as_bytes(),
                                    ),
                                    relay_only: staged.relay_only,
                                    created_at: chrono::Utc::now().timestamp() as u64,
                                    expires_at,
                                };
                                if let Ok(sender_profile) =
                                    crate::agent::daemon::group_mailbox::local_member_profile(
                                        &session,
                                    )
                                {
                                    if let Ok(offer_message) = build_fast_file_offer_message(
                                        &session,
                                        &keypair_net.signing_key,
                                        &sender_profile,
                                        &offer,
                                        config_net.security.message_ttl_ms,
                                    ) {
                                        if post_group_mailbox_message(
                                            mailbox_transport_net,
                                            &session,
                                            &offer_message,
                                        )
                                        .await
                                        .is_ok()
                                        {
                                            let mut registry = group_mailboxes_net.lock().await;
                                            registry.mark_local_post(
                                                &session.group_id,
                                                &offer_message.message_id,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    println!(
                        "   {} queued for {} via Tor mailbox [{}]",
                        "Transfer".green(),
                        describe_group(&session).cyan(),
                        receipt.message_id.dimmed()
                    );
                    let mut a = audit_net.lock().await;
                    a.record(
                        "GROUP_MAILBOX_FILE_SEND",
                        &config_net.agent.did,
                        &format!(
                            "group_id={} path={} transport=tor_mailbox",
                            session.group_id, path
                        ),
                    );
                }
                Err(e) => {
                    println!("   {} {}", "Mailbox transfer failed:".red().bold(), e);
                }
            }
        }
        NetworkCommand::SendGroupFastFileAccept {
            group_id,
            transfer_id,
        } => {
            let session = {
                let registry = group_mailboxes_net.lock().await;
                registry.get_cloned(&group_id)
            };
            let Some(session) = session else {
                tracing::warn!(
                    group_id = %group_id,
                    transfer_id = %transfer_id,
                    "Fast group file accept dropped because mailbox group is no longer joined"
                );
                return;
            };
            let mailbox_message = match build_fast_file_accept_message(
                &session,
                keypair_net,
                &transfer_id,
                config_net.security.message_ttl_ms,
            ) {
                Ok(mailbox_message) => mailbox_message,
                Err(error) => {
                    tracing::warn!(
                        group_id = %session.group_id,
                        transfer_id = %transfer_id,
                        %error,
                        "Failed to build fast group file accept message"
                    );
                    return;
                }
            };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(_) => {
                    let mut registry = group_mailboxes_net.lock().await;
                    registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
                }
                Err(error) => {
                    tracing::warn!(
                        group_id = %session.group_id,
                        transfer_id = %transfer_id,
                        %error,
                        "Failed to post fast group file accept message"
                    );
                }
            }
        }
        NetworkCommand::RebindTorTransferPeer { .. } => {
            // Tor/libp2p-only transfer rebind path.
        }
        NetworkCommand::SendTransferAccept {
            peer_id,
            session_id,
            received_chunks,
        } => {
            match build_transfer_accept_request(
                &keypair_net,
                config_net.security.message_ttl_ms,
                session_id.clone(),
                received_chunks,
            ) {
                Err(e) => tracing::warn!(
                    peer = %peer_id,
                    session = %session_id,
                    %e,
                    "Failed to build TransferResume acceptance (iroh)"
                ),
                Ok(req) => {
                    let _ = iroh_network.send_request(&peer_id, &req).await;
                }
            }
        }
        NetworkCommand::SendTransferStatus {
            peer_id,
            session_id,
            request_message_id,
            filename,
            status,
            detail,
        } => {
            match build_transfer_status_request(
                &keypair_net,
                config_net.security.message_ttl_ms,
                session_id,
                request_message_id,
                filename,
                status,
                detail,
            ) {
                Err(e) => tracing::warn!(
                    peer = %peer_id,
                    %e,
                    "Failed to build TransferStatus payload (iroh)"
                ),
                Ok(req) => {
                    let _ = iroh_network.send_request(&peer_id, &req).await;
                }
            }
        }
        NetworkCommand::SendTransferReject {
            peer_id,
            session_id,
            request_message_id,
            reason,
        } => {
            match build_transfer_reject_request(
                &keypair_net,
                config_net.security.message_ttl_ms,
                session_id,
                request_message_id,
                reason,
            ) {
                Err(e) => tracing::warn!(
                    peer = %peer_id,
                    %e,
                    "Failed to build TransferReject payload (iroh)"
                ),
                Ok(req) => {
                    let _ = iroh_network.send_request(&peer_id, &req).await;
                }
            }
        }
        NetworkCommand::TransferRejectedByPeer {
            peer_id,
            session_id,
            reason,
        } => {
            let peer_key = peer_id.to_string();
            let removed = pending_iroh_chunk_transfers.remove(&peer_key);
            if let Some(mut pct) = removed {
                let session_matches =
                    transfer_session_matches(session_id.as_deref(), &pct.session.session_id);
                if session_matches {
                    if reason == "session_unknown" {
                        if iroh_transfer_restart_already_pending(&pct) {
                            pending_iroh_chunk_transfers.insert(peer_key, pct);
                            return;
                        }
                        reset_iroh_transfer_for_reapproval(&mut pct);
                        pct.retry_after = Some(tokio::time::Instant::now());
                        pct.reconnect_wait_secs = 0;
                        print_async_notice(
                            &config_net.agent.name,
                            format!(
                                "   {} {} lost transfer session{} — resending init",
                                "Transfer restart:".yellow().bold(),
                                pct.peer_name.cyan(),
                                if pct.path.is_empty() {
                                    String::new()
                                } else {
                                    format!(" • {}", pct.path)
                                }
                            ),
                        );
                        emit_transfer_event(
                            "outgoing_restart_required",
                            "out",
                            Some(&pct.peer_did),
                            Some(&pct.peer_name),
                            Some(&pct.session.session_id),
                            Some(&pct.path),
                            Some("receiver_session_unknown"),
                        );
                        pending_iroh_chunk_transfers.insert(peer_key, pct);
                        return;
                    }
                    let peer_name = peers_net
                        .get(&peer_key)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| pct.peer_name.clone());
                    println!(
                        "   {} {} rejected transfer{}{}",
                        "Rejected:".yellow().bold(),
                        peer_name.cyan(),
                        if reason.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", reason)
                        },
                        if pct.path.is_empty() {
                            String::new()
                        } else {
                            format!(" • {}", pct.path)
                        }
                    );
                    emit_transfer_event(
                        "outgoing_rejected",
                        "out",
                        Some(&pct.peer_did),
                        Some(&peer_name),
                        Some(&pct.session.session_id),
                        Some(&pct.path),
                        Some(&reason),
                    );
                    pct.chunk_source.secure_cleanup_async().await;
                } else {
                    pending_iroh_chunk_transfers.insert(peer_key, pct);
                }
            }
        }
        _ => unreachable!("unexpected command routed to handle_iroh_transfer_command"),
    }
}

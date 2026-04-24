use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
use super::transfer_shared::build_transfer_status_request;
use super::*;

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

const TOR_TRANSFER_REBIND_SETTLE_MS: u64 = 250;

fn rebind_pending_tor_chunk_transfer_peer(
    pending_chunk_transfers: &mut HashMap<String, PendingChunkTransfer>,
    peer_did: &str,
    new_peer_id: libp2p::PeerId,
    new_peer_name: &str,
) -> bool {
    let new_key = new_peer_id.to_string();
    let now = tokio::time::Instant::now();
    let settle_at = Some(now + tokio::time::Duration::from_millis(TOR_TRANSFER_REBIND_SETTLE_MS));

    if let Some(pct) = pending_chunk_transfers.get_mut(&new_key) {
        if pct.peer_did != peer_did {
            return false;
        }
        pct.peer_id = new_peer_id;
        pct.peer_name = new_peer_name.to_string();
        pct.inflight_request = None;
        pct.retry_count = 0;
        pct.reconnect_wait_secs = 0;
        pct.reconnecting = false;
        pct.bridge_warming = false;
        pct.backoff_until = settle_at;
        pct.chunk_jitter_until = None;
        pct.last_bridge_at = now;
        return true;
    }

    let old_key = pending_chunk_transfers
        .iter()
        .find(|(_, pct)| pct.peer_did == peer_did)
        .map(|(key, _)| key.clone());
    let Some(old_key) = old_key else {
        return false;
    };

    let Some(mut pct) = pending_chunk_transfers.remove(&old_key) else {
        return false;
    };
    pct.peer_id = new_peer_id;
    pct.peer_name = new_peer_name.to_string();
    pct.inflight_request = None;
    pct.retry_count = 0;
    pct.reconnect_wait_secs = 0;
    pct.reconnecting = false;
    pct.bridge_warming = false;
    pct.backoff_until = settle_at;
    pct.chunk_jitter_until = None;
    pct.last_bridge_at = now;
    pending_chunk_transfers.insert(new_key, pct);
    true
}

pub(crate) fn reset_tor_transfer_for_reapproval(pending: &mut PendingChunkTransfer) {
    pending.awaiting_receiver_accept = true;
    pending.awaiting_started_at = tokio::time::Instant::now();
    pending.needs_reinit = true;
    pending.inflight_request = None;
    pending.retry_count = 0;
    pending.backoff_until = Some(tokio::time::Instant::now());
    pending.reconnect_wait_secs = 0;
    pending.reconnecting = false;
    pending.bridge_warming = false;
    pending.chunk_jitter_until = None;
}

pub(crate) fn tor_transfer_restart_already_pending(pending: &PendingChunkTransfer) -> bool {
    pending.awaiting_receiver_accept && pending.needs_reinit
}

pub(crate) fn apply_tor_transfer_resume_snapshot(
    session: &mut chunked_transfer::TransferSession,
    received_chunks: &[usize],
) -> usize {
    for chunk in &mut session.chunks {
        chunk.sent = false;
        chunk.acknowledged = false;
    }
    for &index in received_chunks {
        if let Some(chunk) = session.chunks.get_mut(index) {
            chunk.sent = true;
            chunk.acknowledged = true;
        }
    }
    session
        .chunks
        .iter()
        .find(|chunk| !chunk.acknowledged)
        .map(|chunk| chunk.index)
        .unwrap_or(session.total_chunks)
}

async fn send_libp2p_file_to_peer(
    network: &mut NetworkNode,
    pending_chunk_transfers: &mut HashMap<String, PendingChunkTransfer>,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    audit_net: &Arc<tokio::sync::Mutex<AuditLog>>,
    rbac_net: &Arc<tokio::sync::RwLock<RbacEngine>>,
    peer_store_net: &Arc<tokio::sync::Mutex<PeerStore>>,
    no_resume_session_persistence: bool,
    no_persistent_artifact_store: bool,
    ram_only_chunk_staging: bool,
    path: String,
    peer_info: PeerInfo,
) -> bool {
    if pending_chunk_transfers.contains_key(&peer_info.peer_id.to_string()) {
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
            "   {} {} ({:.1} MB) → {} ...",
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
                        network
                            .swarm
                            .behaviour_mut()
                            .messaging
                            .send_request(&peer_info.peer_id, request);
                        println!(
                            "   {} {} ({:.1} MB) → {} [E2EE + signed]",
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
                                &format!("path={} to={} size={}", path, peer_info.did, total_size),
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
                    }
                }
            }
        }
    } else {
        let chunk_size = if matches!(config_net.network.transport_mode, TransportMode::Tor) {
            TOR_CHUNK_SIZE_BYTES
        } else {
            config_net.transfer.chunk_size_bytes
        };

        let filename = source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let session_dir = runtime_temp_path("qypha-sessions");
        let mut resumed_session: Option<(chunked_transfer::TransferSession, std::path::PathBuf)> =
            None;
        if !no_resume_session_persistence && session_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&session_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("json") {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            if let Ok(saved) =
                                serde_json::from_str::<chunked_transfer::TransferSession>(&content)
                            {
                                if saved.filename == filename
                                    && saved.recipient_did == peer_info.did
                                    && saved.status == chunked_transfer::TransferStatus::InProgress
                                {
                                    let temp_dir = runtime_temp_path("qypha-transfer");
                                    if let Ok(tdir_entries) = std::fs::read_dir(&temp_dir) {
                                        for te in tdir_entries.flatten() {
                                            let tp = te.path();
                                            if let Ok(meta) = std::fs::metadata(&tp) {
                                                if meta.len() == saved.total_size {
                                                    let ack_count = saved
                                                        .chunks
                                                        .iter()
                                                        .filter(|c| c.acknowledged)
                                                        .count();
                                                    if ack_count > 0 {
                                                        println!(
                                                            "   {} found saved session — resuming from chunk {}/{}",
                                                            "Resume:".cyan().bold(),
                                                            ack_count + 1,
                                                            saved.total_chunks,
                                                        );
                                                        resumed_session = Some((saved, tp));
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    if resumed_session.is_some() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some((saved_session, saved_temp_path)) = resumed_session {
            let ack_count = saved_session
                .chunks
                .iter()
                .filter(|c| c.acknowledged)
                .count();
            let packed_size = std::fs::metadata(&saved_temp_path)
                .map(|m| m.len())
                .unwrap_or(0);
            let packed_mb = packed_size as f64 / (1024.0 * 1024.0);
            let ttl = config_net.security.message_ttl_ms;

            let (init_payload, _) =
                chunked_transfer::build_sealed_init_payload(&saved_session, keypair_net);
            let init_ok = match bincode::serialize(&init_payload) {
                Err(_) => false,
                Ok(init_bytes) => match chunked_transfer::wrap_chunk_request(
                    keypair_net,
                    MessageKind::ChunkTransferInit,
                    init_bytes,
                    ttl,
                ) {
                    Err(_) => false,
                    Ok(init_request) => {
                        network
                            .swarm
                            .behaviour_mut()
                            .messaging
                            .send_request(&peer_info.peer_id, init_request);
                        println!(
                            "   {} session {} (resuming {}/{} chunks)",
                            "Init sent:".green(),
                            &saved_session.session_id[..16],
                            ack_count,
                            saved_session.total_chunks,
                        );
                        println!(
                            "   {} waiting for receiver /accept before sending chunks",
                            "Pending:".yellow().bold()
                        );
                        true
                    }
                },
            };

            if init_ok {
                let resume_from = saved_session
                    .chunks
                    .iter()
                    .position(|c| !c.acknowledged)
                    .unwrap_or(0);

                if let Some(mut replaced) = pending_chunk_transfers.insert(
                    peer_info.peer_id.to_string(),
                    PendingChunkTransfer {
                        peer_id: peer_info.peer_id,
                        peer_name: peer_info.name.clone(),
                        peer_did: peer_info.did.clone(),
                        session: saved_session,
                        chunk_source: ChunkSource::TempFile(saved_temp_path),
                        next_chunk: resume_from,
                        chunk_size,
                        x25519_pk,
                        kyber_pk: Some(kyber_pk.clone()),
                        ttl,
                        path,
                        packed_mb,
                        packed_size,
                        inflight_request: None,
                        retry_count: 0,
                        backoff_until: None,
                        reconnect_wait_secs: 0,
                        reconnecting: false,
                        last_bridge_at: tokio::time::Instant::now(),
                        bridge_warming: false,
                        peer_onion: {
                            let ps = peer_store_net.lock().await;
                            ps.all_peers()
                                .into_iter()
                                .find(|kp| kp.peer_id == peer_info.peer_id.to_string())
                                .and_then(|kp| kp.onion_address.clone())
                        },
                        peer_onion_port: 9090,
                        chunk_jitter_until: None,
                        awaiting_receiver_accept: true,
                        awaiting_started_at: tokio::time::Instant::now(),
                        needs_reinit: false,
                    },
                ) {
                    replaced.chunk_source.secure_cleanup();
                }
                true
            } else {
                false
            }
        } else {
            println!(
                "   {} {} ({:.1} MB) -> {} [chunked, {} MB/chunk]",
                "Packing:".yellow().bold(),
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

            if ram_only_chunk_staging {
                let source_owned = source.to_path_buf();
                let pack_result =
                    tokio::task::spawn_blocking(move || transfer::pack_path(&source_owned))
                        .await
                        .map_err(|e| anyhow::anyhow!("Pack task panicked: {}", e))
                        .and_then(|r| r);

                match pack_result {
                    Err(e) => {
                        println!("   {} {}", "Pack failed:".red(), e);
                        false
                    }
                    Ok(packed_data) => {
                        let packed_size = packed_data.len() as u64;
                        let packed_mb = packed_size as f64 / (1024.0 * 1024.0);
                        println!(
                            "   {} {:.1} MB → {:.1} MB packed (RAM-only)",
                            "Packed:".green(),
                            size_mb,
                            packed_mb,
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

                        let (session, chunks) = match chunked_transfer::prepare_session(
                            keypair_net,
                            &peer_info.did,
                            &filename,
                            "confidential",
                            &packed_data,
                            chunk_size,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("   {} {}", "Session prepare failed:".red(), e);
                                return false;
                            }
                        };

                        let ttl = config_net.security.message_ttl_ms;
                        let (init_payload, _) =
                            chunked_transfer::build_sealed_init_payload(&session, keypair_net);
                        let init_ok = match bincode::serialize(&init_payload) {
                            Err(e) => {
                                println!("   {} {}", "Init serialize failed:".red(), e);
                                false
                            }
                            Ok(init_bytes) => match chunked_transfer::wrap_chunk_request(
                                keypair_net,
                                MessageKind::ChunkTransferInit,
                                init_bytes,
                                ttl,
                            ) {
                                Err(e) => {
                                    println!("   {} {}", "Init wrap failed:".red(), e);
                                    false
                                }
                                Ok(init_request) => {
                                    network
                                        .swarm
                                        .behaviour_mut()
                                        .messaging
                                        .send_request(&peer_info.peer_id, init_request);
                                    println!(
                                        "   {} session {} ({} chunks, sealed v2, RAM-only)",
                                        "Init sent:".green(),
                                        &session.session_id[..16],
                                        session.total_chunks,
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
                                    true
                                }
                            },
                        };

                        if init_ok {
                            if let Some(mut replaced) = pending_chunk_transfers.insert(
                                peer_info.peer_id.to_string(),
                                PendingChunkTransfer {
                                    peer_id: peer_info.peer_id,
                                    peer_name: peer_info.name.clone(),
                                    peer_did: peer_info.did.clone(),
                                    session,
                                    chunk_source: ChunkSource::InMemory(chunks),
                                    next_chunk: 0,
                                    chunk_size,
                                    x25519_pk,
                                    kyber_pk: Some(kyber_pk.clone()),
                                    ttl,
                                    path,
                                    packed_mb,
                                    packed_size,
                                    inflight_request: None,
                                    retry_count: 0,
                                    backoff_until: None,
                                    reconnect_wait_secs: 0,
                                    reconnecting: false,
                                    last_bridge_at: tokio::time::Instant::now(),
                                    bridge_warming: false,
                                    peer_onion: {
                                        let ps = peer_store_net.lock().await;
                                        ps.all_peers()
                                            .into_iter()
                                            .find(|kp| kp.peer_id == peer_info.peer_id.to_string())
                                            .and_then(|kp| kp.onion_address.clone())
                                    },
                                    peer_onion_port: 9090,
                                    chunk_jitter_until: None,
                                    awaiting_receiver_accept: true,
                                    awaiting_started_at: tokio::time::Instant::now(),
                                    needs_reinit: false,
                                },
                            ) {
                                replaced.chunk_source.secure_cleanup();
                            }
                            true
                        } else {
                            false
                        }
                    }
                }
            } else {
                let source_owned = source.to_path_buf();
                let pack_result = tokio::task::spawn_blocking(move || {
                    chunked_transfer::pack_to_temp_file(&source_owned)
                })
                .await
                .map_err(|e| anyhow::anyhow!("Pack task panicked: {}", e))
                .and_then(|r| r);
                match pack_result {
                    Err(e) => {
                        println!("   {} {}", "Pack failed:".red(), e);
                        false
                    }
                    Ok(temp_path) => {
                        let packed_size =
                            std::fs::metadata(&temp_path).map(|m| m.len()).unwrap_or(0);
                        let packed_mb = packed_size as f64 / (1024.0 * 1024.0);
                        let packed_note = if no_resume_session_persistence {
                            " (metadata-free temp staging)"
                        } else {
                            ""
                        };
                        println!(
                            "   {} {:.1} MB → {:.1} MB compressed{}",
                            "Packed:".green(),
                            size_mb,
                            packed_mb,
                            packed_note,
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

                        let kp_clone = keypair_net.clone();
                        let did_clone = peer_info.did.clone();
                        let fn_clone = filename.clone();
                        let tp_clone = temp_path.clone();
                        let session_result = tokio::task::spawn_blocking(move || {
                            chunked_transfer::prepare_session_streaming(
                                &kp_clone,
                                &did_clone,
                                &fn_clone,
                                "confidential",
                                &tp_clone,
                                chunk_size,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("Session task panicked: {}", e))
                        .and_then(|r| r);
                        match session_result {
                            Err(e) => {
                                println!("   {} {}", "Session prepare failed:".red(), e);
                                secure_wipe_file(&temp_path);
                                false
                            }
                            Ok(session) => {
                                let ttl = config_net.security.message_ttl_ms;
                                let (init_payload, _) = chunked_transfer::build_sealed_init_payload(
                                    &session,
                                    keypair_net,
                                );
                                let init_ok = match bincode::serialize(&init_payload) {
                                    Err(e) => {
                                        println!("   {} {}", "Init serialize failed:".red(), e);
                                        false
                                    }
                                    Ok(init_bytes) => match chunked_transfer::wrap_chunk_request(
                                        keypair_net,
                                        MessageKind::ChunkTransferInit,
                                        init_bytes,
                                        ttl,
                                    ) {
                                        Err(e) => {
                                            println!("   {} {}", "Init wrap failed:".red(), e);
                                            false
                                        }
                                        Ok(init_request) => {
                                            network
                                                .swarm
                                                .behaviour_mut()
                                                .messaging
                                                .send_request(&peer_info.peer_id, init_request);
                                            let init_mode = if no_resume_session_persistence {
                                                "sealed v2, metadata-free temp staging"
                                            } else {
                                                "sealed v2"
                                            };
                                            println!(
                                                "   {} session {} ({} chunks, {})",
                                                "Init sent:".green(),
                                                &session.session_id[..16],
                                                session.total_chunks,
                                                init_mode,
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
                                            true
                                        }
                                    },
                                };

                                if init_ok {
                                    if let Some(mut replaced) = pending_chunk_transfers.insert(
                                        peer_info.peer_id.to_string(),
                                        PendingChunkTransfer {
                                            peer_id: peer_info.peer_id,
                                            peer_name: peer_info.name.clone(),
                                            peer_did: peer_info.did.clone(),
                                            session,
                                            chunk_source: ChunkSource::TempFile(temp_path),
                                            next_chunk: 0,
                                            chunk_size,
                                            x25519_pk,
                                            kyber_pk: Some(kyber_pk.clone()),
                                            ttl,
                                            path,
                                            packed_mb,
                                            packed_size,
                                            inflight_request: None,
                                            retry_count: 0,
                                            backoff_until: None,
                                            reconnect_wait_secs: 0,
                                            reconnecting: false,
                                            last_bridge_at: tokio::time::Instant::now(),
                                            bridge_warming: false,
                                            peer_onion: {
                                                let ps = peer_store_net.lock().await;
                                                ps.all_peers()
                                                    .into_iter()
                                                    .find(|kp| {
                                                        kp.peer_id == peer_info.peer_id.to_string()
                                                    })
                                                    .and_then(|kp| kp.onion_address.clone())
                                            },
                                            peer_onion_port: 9090,
                                            chunk_jitter_until: None,
                                            awaiting_receiver_accept: true,
                                            awaiting_started_at: tokio::time::Instant::now(),
                                            needs_reinit: false,
                                        },
                                    ) {
                                        replaced.chunk_source.secure_cleanup();
                                    }
                                    true
                                } else {
                                    secure_wipe_file(&temp_path);
                                    false
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
pub(crate) async fn handle_libp2p_transfer_command(
    cmd: NetworkCommand,
    state: &mut Libp2pCommandHandlerState<'_>,
    shared: &Libp2pCommandHandlerShared<'_>,
) {
    let mut network = Libp2pNetworkHandle(state.network);
    let handshake_sent = &mut *state.handshake_sent;
    let pending_chunk_transfers = &mut *state.pending_chunk_transfers;
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
    let log_mode_net = shared.log_mode_net;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    let ram_only_chunk_staging = shared.ram_only_chunk_staging;
    match cmd {
        NetworkCommand::SendFile {
            path,
            peer_selector,
        } => {
            let peer_list =
                super::selectors::sorted_direct_peer_list(peers_net, direct_peer_dids_net);

            // Resolve by: [1] numeric index, [2] name (case-insensitive), [3] PeerId string, [4] DID
            let resolved: Option<PeerInfo> = if let Ok(idx) = peer_selector.parse::<usize>() {
                if idx >= 1 && idx <= peer_list.len() {
                    Some(peer_list[idx - 1].clone())
                } else {
                    None
                }
            } else {
                peer_list
                    .iter()
                    .find(|p| {
                        p.name.eq_ignore_ascii_case(&peer_selector)
                            || p.peer_id.to_string() == peer_selector
                            || p.did == peer_selector
                    })
                    .cloned()
            };

            match resolved {
                None => {
                    println!(
                        "   {} peer '{}' not found. Use /peers to see numbered list.",
                        "Error:".red(),
                        peer_selector
                    );
                }
                Some(peer_info) => {
                    if pending_chunk_transfers.contains_key(&peer_info.peer_id.to_string()) {
                        println!(
                            "   {} transfer to {} is already in progress.",
                            "Busy:".yellow().bold(),
                            peer_info.name.cyan()
                        );
                        return;
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
                        return;
                    }

                    match peer_info.x25519_public_key {
                        None => {
                            println!(
                                "   {} Peer has no X25519 key — not fully handshaked yet.",
                                "Warning:".yellow()
                            );
                        }
                        Some(x25519_pk) => {
                            let kyber_pk = match peer_info.kyber_public_key.clone() {
                                Some(pk) => pk,
                                None => {
                                    println!(
                                                        "   {} peer {} has no Kyber key — PQC required, transfer blocked",
                                                        "SECURITY REJECT:".red().bold(),
                                                        peer_info.name.cyan()
                                                    );
                                    return;
                                }
                            };
                            // Check file size to decide: monolithic vs chunked
                            let source = std::path::Path::new(&path);
                            if !source.exists() {
                                println!("   {} Path does not exist: {}", "Error:".red(), path);
                            } else {
                                // Get total size (file or directory)
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
                                    // ── Small file: monolithic transfer ─────
                                    println!(
                                        "   {} {} ({:.1} MB) → {} ...",
                                        "Encrypting:".yellow(),
                                        path,
                                        size_mb,
                                        peer_info.name.cyan()
                                    );

                                    // Tor/Ghost: skip artifact store (no plaintext disk staging)
                                    let build_fn = if no_persistent_artifact_store {
                                        transfer::build_encrypted_transfer_zero_trace
                                    } else {
                                        transfer::build_encrypted_transfer
                                    };
                                    match build_fn(
                                        &keypair_net,
                                        &x25519_pk,
                                        Some(kyber_pk.as_slice()),
                                        &peer_info.did,
                                        &path,
                                        "confidential",
                                    ) {
                                        Err(e) => {
                                            println!("   {} {}", "Encrypt failed:".red(), e);
                                        }
                                        Ok(transfer_payload) => {
                                            match transfer::wrap_as_request(
                                                &keypair_net,
                                                transfer_payload,
                                            ) {
                                                Err(e) => {
                                                    println!("   {} {}", "Wrap failed:".red(), e)
                                                }
                                                Ok(request) => {
                                                    // Send directly — circuit relay is transparent at transport layer
                                                    network
                                                        .swarm
                                                        .behaviour_mut()
                                                        .messaging
                                                        .send_request(&peer_info.peer_id, request);
                                                    let via = "";
                                                    println!(
                                                                        "   {} {} ({:.1} MB) → {} [E2EE + signed{}]",
                                                                        "Sent:".green().bold(),
                                                                        path,
                                                                        size_mb,
                                                                        peer_info.name.cyan(),
                                                                        via,
                                                                    );
                                                    {
                                                        let mut a = audit_net.lock().await;
                                                        a.record(
                                                            "FILE_SEND",
                                                            &config_net.agent.did,
                                                            &format!(
                                                                "path={} to={} size={}",
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
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // ── Large file: streaming chunked transfer ──
                                    // Tor uses fixed 4 MB chunks for reliability over slower circuits.
                                    // Other non-iroh transports continue using configured chunk size.
                                    // Ack-before-next pattern means only 1 substream open
                                    // at a time, so unlimited chunks is safe.
                                    let chunk_size = if matches!(
                                        config_net.network.transport_mode,
                                        TransportMode::Tor
                                    ) {
                                        TOR_CHUNK_SIZE_BYTES
                                    } else {
                                        config_net.transfer.chunk_size_bytes
                                    };

                                    let filename = source
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();

                                    // ── Resume detection: check for saved session ──
                                    // SECURITY: no-disk transfer mode disables resume persistence.
                                    let session_dir = runtime_temp_path("qypha-sessions");
                                    let mut resumed_session: Option<(
                                        chunked_transfer::TransferSession,
                                        std::path::PathBuf,
                                    )> = None;
                                    if !no_resume_session_persistence && session_dir.exists() {
                                        if let Ok(entries) = std::fs::read_dir(&session_dir) {
                                            for entry in entries.flatten() {
                                                let p = entry.path();
                                                if p.extension().and_then(|e| e.to_str())
                                                    == Some("json")
                                                {
                                                    if let Ok(content) = std::fs::read_to_string(&p)
                                                    {
                                                        if let Ok(saved) = serde_json::from_str::<
                                                            chunked_transfer::TransferSession,
                                                        >(
                                                            &content
                                                        ) {
                                                            // Match by filename + recipient + similar size
                                                            if saved.filename == filename
                                                                                && saved.recipient_did == peer_info.did
                                                                                && saved.status == chunked_transfer::TransferStatus::InProgress
                                                                            {
                                                                                // Find the temp packed file with matching size
                                                                                let temp_dir =
                                                                                    runtime_temp_path("qypha-transfer");
                                                                                if let Ok(tdir_entries) = std::fs::read_dir(&temp_dir) {
                                                                                    for te in tdir_entries.flatten() {
                                                                                        let tp = te.path();
                                                                                        if let Ok(meta) = std::fs::metadata(&tp) {
                                                                                            if meta.len() == saved.total_size {
                                                                                                let ack_count = saved.chunks.iter()
                                                                                                    .filter(|c| c.acknowledged)
                                                                                                    .count();
                                                                                                if ack_count > 0 {
                                                                                                    println!(
                                                                                                        "   {} found saved session — resuming from chunk {}/{}",
                                                                                                        "Resume:".cyan().bold(),
                                                                                                        ack_count + 1,
                                                                                                        saved.total_chunks,
                                                                                                    );
                                                                                                    resumed_session = Some((saved, tp));
                                                                                                }
                                                                                                break;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                if resumed_session.is_some() { break; }
                                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if let Some((saved_session, saved_temp_path)) = resumed_session
                                    {
                                        // ── RESUME path: skip already-sent chunks ──
                                        let ack_count = saved_session
                                            .chunks
                                            .iter()
                                            .filter(|c| c.acknowledged)
                                            .count();
                                        let packed_size = std::fs::metadata(&saved_temp_path)
                                            .map(|m| m.len())
                                            .unwrap_or(0);
                                        let packed_mb = packed_size as f64 / (1024.0 * 1024.0);
                                        let ttl = config_net.security.message_ttl_ms;

                                        // Re-send init so receiver knows about this session (sealed v2)
                                        let (init_payload, _) =
                                            chunked_transfer::build_sealed_init_payload(
                                                &saved_session,
                                                &keypair_net,
                                            );
                                        let init_ok = match bincode::serialize(&init_payload) {
                                            Err(_) => false,
                                            Ok(init_bytes) => {
                                                match chunked_transfer::wrap_chunk_request(
                                                    &keypair_net,
                                                    MessageKind::ChunkTransferInit,
                                                    init_bytes,
                                                    ttl,
                                                ) {
                                                    Err(_) => false,
                                                    Ok(init_request) => {
                                                        network
                                                            .swarm
                                                            .behaviour_mut()
                                                            .messaging
                                                            .send_request(
                                                                &peer_info.peer_id,
                                                                init_request,
                                                            );
                                                        println!(
                                                                            "   {} session {} (resuming {}/{} chunks)",
                                                                            "Init sent:".green(),
                                                                            &saved_session.session_id[..16],
                                                                            ack_count,
                                                                            saved_session.total_chunks,
                                                                        );
                                                        println!(
                                                                            "   {} waiting for receiver /accept before sending chunks",
                                                                            "Pending:".yellow().bold()
                                                                        );
                                                        true
                                                    }
                                                }
                                            }
                                        };

                                        if init_ok {
                                            // Find first un-acknowledged chunk
                                            let resume_from = saved_session
                                                .chunks
                                                .iter()
                                                .position(|c| !c.acknowledged)
                                                .unwrap_or(0);

                                            if let Some(mut replaced) = pending_chunk_transfers
                                                .insert(
                                                    peer_info.peer_id.to_string(),
                                                    PendingChunkTransfer {
                                                        peer_id: peer_info.peer_id,
                                                        peer_name: peer_info.name.clone(),
                                                        peer_did: peer_info.did.clone(),
                                                        session: saved_session,
                                                        chunk_source: ChunkSource::TempFile(
                                                            saved_temp_path,
                                                        ),
                                                        next_chunk: resume_from,
                                                        chunk_size,
                                                        x25519_pk,
                                                        kyber_pk: Some(kyber_pk.clone()),
                                                        ttl,
                                                        path,
                                                        packed_mb,
                                                        packed_size,
                                                        inflight_request: None,
                                                        retry_count: 0,
                                                        backoff_until: None,
                                                        reconnect_wait_secs: 0,
                                                        reconnecting: false,
                                                        last_bridge_at: tokio::time::Instant::now(),
                                                        bridge_warming: false,
                                                        peer_onion: {
                                                            let ps = peer_store_net.lock().await;
                                                            ps.all_peers()
                                                                .into_iter()
                                                                .find(|kp| {
                                                                    kp.peer_id
                                                                        == peer_info
                                                                            .peer_id
                                                                            .to_string()
                                                                })
                                                                .and_then(|kp| {
                                                                    kp.onion_address.clone()
                                                                })
                                                        },
                                                        peer_onion_port: 9090,
                                                        chunk_jitter_until: None,
                                                        awaiting_receiver_accept: true,
                                                        awaiting_started_at:
                                                            tokio::time::Instant::now(),
                                                        needs_reinit: false,
                                                    },
                                                )
                                            {
                                                replaced.chunk_source.secure_cleanup();
                                            }
                                        }
                                    } else {
                                        // ── FRESH transfer: pack + prepare + send ──
                                        println!(
                                            "   {} {} ({:.1} MB) -> {} [chunked, {} MB/chunk]",
                                            "Packing:".yellow().bold(),
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

                                        if ram_only_chunk_staging {
                                            // Ghost: keep packed data only in RAM (no plaintext temp files).
                                            let source_owned = source.to_path_buf();
                                            let pack_result =
                                                tokio::task::spawn_blocking(move || {
                                                    transfer::pack_path(&source_owned)
                                                })
                                                .await
                                                .map_err(|e| {
                                                    anyhow::anyhow!("Pack task panicked: {}", e)
                                                })
                                                .and_then(|r| r);

                                            match pack_result {
                                                Err(e) => {
                                                    println!("   {} {}", "Pack failed:".red(), e);
                                                }
                                                Ok(packed_data) => {
                                                    let packed_size = packed_data.len() as u64;
                                                    let packed_mb =
                                                        packed_size as f64 / (1024.0 * 1024.0);
                                                    println!(
                                                                        "   {} {:.1} MB → {:.1} MB packed (RAM-only)",
                                                                        "Packed:".green(),
                                                                        size_mb,
                                                                        packed_mb,
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

                                                    let (session, chunks) =
                                                        match chunked_transfer::prepare_session(
                                                            &keypair_net,
                                                            &peer_info.did,
                                                            &filename,
                                                            "confidential",
                                                            &packed_data,
                                                            chunk_size,
                                                        ) {
                                                            Ok(v) => v,
                                                            Err(e) => {
                                                                println!(
                                                                    "   {} {}",
                                                                    "Session prepare failed:".red(),
                                                                    e
                                                                );
                                                                return;
                                                            }
                                                        };

                                                    let ttl = config_net.security.message_ttl_ms;
                                                    let (init_payload, _sealed_meta) =
                                                        chunked_transfer::build_sealed_init_payload(
                                                            &session,
                                                            &keypair_net,
                                                        );
                                                    let init_ok = match bincode::serialize(&init_payload) {
                                                                        Err(e) => {
                                                                            println!("   {} {}", "Init serialize failed:".red(), e);
                                                                            false
                                                                        }
                                                                        Ok(init_bytes) => {
                                                                            match chunked_transfer::wrap_chunk_request(
                                                                                &keypair_net,
                                                                                MessageKind::ChunkTransferInit,
                                                                                init_bytes,
                                                                                ttl,
                                                                            ) {
                                                                                Err(e) => {
                                                                                    println!("   {} {}", "Init wrap failed:".red(), e);
                                                                                    false
                                                                                }
                                                                                Ok(init_request) => {
                                                                                    network.swarm.behaviour_mut().messaging
                                                                                        .send_request(&peer_info.peer_id, init_request);
                                                                                    println!(
                                                                                        "   {} session {} ({} chunks, sealed v2, RAM-only)",
                                                                                        "Init sent:".green(),
                                                                                        &session.session_id[..16],
                                                                                        session.total_chunks,
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
                                                                                    true
                                                                                }
                                                                            }
                                                                        }
                                                                    };

                                                    if init_ok {
                                                        if let Some(mut replaced) =
                                                            pending_chunk_transfers.insert(
                                                                peer_info.peer_id.to_string(),
                                                                PendingChunkTransfer {
                                                                    peer_id: peer_info.peer_id,
                                                                    peer_name: peer_info
                                                                        .name
                                                                        .clone(),
                                                                    peer_did: peer_info.did.clone(),
                                                                    session,
                                                                    chunk_source:
                                                                        ChunkSource::InMemory(
                                                                            chunks,
                                                                        ),
                                                                    next_chunk: 0,
                                                                    chunk_size,
                                                                    x25519_pk,
                                                                    kyber_pk: Some(
                                                                        kyber_pk.clone(),
                                                                    ),
                                                                    ttl,
                                                                    path,
                                                                    packed_mb,
                                                                    packed_size,
                                                                    inflight_request: None,
                                                                    retry_count: 0,
                                                                    backoff_until: None,
                                                                    reconnect_wait_secs: 0,
                                                                    reconnecting: false,
                                                                    last_bridge_at:
                                                                        tokio::time::Instant::now(),
                                                                    bridge_warming: false,
                                                                    peer_onion: {
                                                                        let ps = peer_store_net
                                                                            .lock()
                                                                            .await;
                                                                        ps.all_peers()
                                                                            .into_iter()
                                                                            .find(|kp| {
                                                                                kp.peer_id
                                                                                    == peer_info
                                                                                        .peer_id
                                                                                        .to_string()
                                                                            })
                                                                            .and_then(|kp| {
                                                                                kp.onion_address
                                                                                    .clone()
                                                                            })
                                                                    },
                                                                    peer_onion_port: 9090,
                                                                    chunk_jitter_until: None,
                                                                    awaiting_receiver_accept: true,
                                                                    awaiting_started_at:
                                                                        tokio::time::Instant::now(),
                                                                    needs_reinit: false,
                                                                },
                                                            )
                                                        {
                                                            replaced.chunk_source.secure_cleanup();
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            // Step 1: Pack into temp file (non-blocking via spawn_blocking)
                                            let source_owned = source.to_path_buf();
                                            let pack_result =
                                                tokio::task::spawn_blocking(move || {
                                                    chunked_transfer::pack_to_temp_file(
                                                        &source_owned,
                                                    )
                                                })
                                                .await
                                                .map_err(|e| {
                                                    anyhow::anyhow!("Pack task panicked: {}", e)
                                                })
                                                .and_then(|r| r);
                                            match pack_result {
                                                Err(e) => {
                                                    println!("   {} {}", "Pack failed:".red(), e);
                                                }
                                                Ok(temp_path) => {
                                                    let packed_size = std::fs::metadata(&temp_path)
                                                        .map(|m| m.len())
                                                        .unwrap_or(0);
                                                    let packed_mb =
                                                        packed_size as f64 / (1024.0 * 1024.0);
                                                    let packed_note =
                                                        if no_resume_session_persistence {
                                                            " (metadata-free temp staging)"
                                                        } else {
                                                            ""
                                                        };
                                                    println!(
                                                        "   {} {:.1} MB → {:.1} MB compressed{}",
                                                        "Packed:".green(),
                                                        size_mb,
                                                        packed_mb,
                                                        packed_note,
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

                                                    // Step 2: Prepare session (non-blocking — hashes computed in blocking thread)
                                                    let kp_clone = keypair_net.clone();
                                                    let did_clone = peer_info.did.clone();
                                                    let fn_clone = filename.clone();
                                                    let tp_clone = temp_path.clone();
                                                    let session_result = tokio::task::spawn_blocking(move || {
                                                                        chunked_transfer::prepare_session_streaming(
                                                                            &kp_clone,
                                                                            &did_clone,
                                                                            &fn_clone,
                                                                            "confidential",
                                                                            &tp_clone,
                                                                            chunk_size,
                                                                        )
                                                                    }).await.map_err(|e| anyhow::anyhow!("Session task panicked: {}", e))
                                                                      .and_then(|r| r);
                                                    match session_result {
                                                        Err(e) => {
                                                            println!(
                                                                "   {} {}",
                                                                "Session prepare failed:".red(),
                                                                e
                                                            );
                                                            secure_wipe_file(&temp_path);
                                                        }
                                                        Ok(session) => {
                                                            let ttl =
                                                                config_net.security.message_ttl_ms;

                                                            // Step 3: Send ChunkTransferInit (sealed — metadata hidden)
                                                            let (init_payload, _sealed_meta) = chunked_transfer::build_sealed_init_payload(&session, &keypair_net);
                                                            let init_ok = match bincode::serialize(&init_payload) {
                                                                                Err(e) => {
                                                                                    println!("   {} {}", "Init serialize failed:".red(), e);
                                                                                    false
                                                                                }
                                                                                Ok(init_bytes) => {
                                                                                    match chunked_transfer::wrap_chunk_request(
                                                                                        &keypair_net,
                                                                                        MessageKind::ChunkTransferInit,
                                                                                        init_bytes,
                                                                                        ttl,
                                                                                    ) {
                                                                                        Err(e) => {
                                                                                            println!("   {} {}", "Init wrap failed:".red(), e);
                                                                                            false
                                                                                        }
                                                                                        Ok(init_request) => {
                                                                                            network.swarm.behaviour_mut().messaging
                                                                                                .send_request(&peer_info.peer_id, init_request);
                                                                                            let init_mode = if no_resume_session_persistence {
                                                                                                "sealed v2, metadata-free temp staging"
                                                                                            } else {
                                                                                                "sealed v2"
                                                                                            };
                                                                                            println!(
                                                                                                "   {} session {} ({} chunks, {})",
                                                                                                "Init sent:".green(),
                                                                                                &session.session_id[..16],
                                                                                                session.total_chunks,
                                                                                                init_mode,
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
                                                                                            true
                                                                                        }
                                                                                    }
                                                                                }
                                                                            };

                                                            // Step 4: Queue chunks for flow-controlled sending
                                                            if init_ok {
                                                                if let Some(mut replaced) = pending_chunk_transfers.insert(
                                                                                    peer_info.peer_id.to_string(),
                                                                                    PendingChunkTransfer {
                                                                                    peer_id: peer_info.peer_id,
                                                                                    peer_name: peer_info.name.clone(),
                                                                                    peer_did: peer_info.did.clone(),
                                                                                    session,
                                                                                    chunk_source: ChunkSource::TempFile(temp_path),
                                                                                    next_chunk: 0,
                                                                                    chunk_size,
                                                                                    x25519_pk,
                                                                                    kyber_pk: Some(kyber_pk.clone()),
                                                                                    ttl,
                                                                                    path,
                                                                                    packed_mb,
                                                                                    packed_size,
                                                                                    inflight_request: None,
                                                                                    retry_count: 0,
                                                                                    backoff_until: None,
                                                                                    reconnect_wait_secs: 0,
                                                                                    reconnecting: false,
                                                                                    last_bridge_at: tokio::time::Instant::now(),
                                                                                    bridge_warming: false,
                                                                                    peer_onion: {
                                                                                        let ps = peer_store_net.lock().await;
                                                                                        ps.all_peers().into_iter()
                                                                                            .find(|kp| kp.peer_id == peer_info.peer_id.to_string())
                                                                                            .and_then(|kp| kp.onion_address.clone())
                                                                                    },
                                                                                    peer_onion_port: 9090,
                                                                                    chunk_jitter_until: None,
                                                                                    awaiting_receiver_accept: true,
                                                                                    awaiting_started_at: tokio::time::Instant::now(),
                                                                                    needs_reinit: false,
                                                                                },
                                                                                ) {
                                                                                    replaced.chunk_source.secure_cleanup();
                                                                                }
                                                            } else {
                                                                secure_wipe_file(&temp_path);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } // end fresh vs resume
                                }
                            }
                        }
                    }
                }
            }
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
            let mailbox_message = match build_file_manifest_message(
                mailbox_transport_net,
                &session,
                keypair_net,
                &path,
                config_net.security.message_ttl_ms,
                false,
            )
            .await
            {
                Ok(mailbox_message) => mailbox_message,
                Err(e) => {
                    println!("   {} {}", "Group mailbox transfer rejected:".red(), e);
                    return;
                }
            };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(receipt) => {
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
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

        // ── /peers: list connected peers (numbered) ──────
        NetworkCommand::TorRedial {
            peer_id,
            peer_did,
            bridge_port,
        } => {
            let addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bridge_port)
                .parse()
                .expect("valid multiaddr");
            match network.swarm.dial(addr) {
                Ok(()) => {
                    if let Some(pct) = pending_chunk_transfers.get_mut(&peer_id.to_string()) {
                        let was_reconnecting = pct.reconnecting;
                        pct.bridge_warming = false;
                        pct.last_bridge_at = tokio::time::Instant::now();
                        if was_reconnecting {
                            // Keep the transfer paused until the fresh peer handshake arrives
                            // and rebinds the transfer to the new live peer slot.
                            pct.backoff_until = Some(
                                tokio::time::Instant::now() + tokio::time::Duration::from_secs(1),
                            );
                            tracing::debug!(
                                peer = %crate::agent::contact_identity::displayed_did(&peer_did),
                                "New Tor circuit ready — awaiting authenticated reconnect before resuming transfer"
                            );
                        } else {
                            // Proactive warm standby — no pause needed
                            tracing::info!("Warm standby bridge ready — seamless circuit rotation");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%e, "Bridge dial failed");
                    if let Some(pct) = pending_chunk_transfers.get_mut(&peer_id.to_string()) {
                        pct.reconnecting = false;
                        pct.bridge_warming = false;
                    }
                }
            }
        }
        NetworkCommand::TorRedialFailed { peer_id, peer_did } => {
            if let Some(pct) = pending_chunk_transfers.get_mut(&peer_id.to_string()) {
                if pct.reconnecting {
                    tracing::debug!(
                        peer = %crate::agent::contact_identity::displayed_did(&peer_did),
                        "Immediate Tor transfer reconnect exhausted bridge attempts; background retry remains queued"
                    );
                }
                pct.bridge_warming = false;
                pct.backoff_until =
                    Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5));
            }
        }
        NetworkCommand::RebindTorTransferPeer {
            peer_id,
            peer_did,
            peer_name,
        } => {
            let was_reconnecting = pending_chunk_transfers
                .values()
                .find(|pending| pending.peer_did == peer_did)
                .is_some_and(|pending| pending.reconnecting);
            let rebound = rebind_pending_tor_chunk_transfer_peer(
                pending_chunk_transfers,
                &peer_did,
                peer_id,
                &peer_name,
            );
            tracing::debug!(
                peer = %peer_name,
                did = %crate::agent::contact_identity::displayed_did(&peer_did),
                rebound,
                "rebound pending Tor transfer to live peer slot after reconnect"
            );
            if rebound && was_reconnecting {
                print_async_notice(
                    &config_net.agent.name,
                    format!(
                        "   {} {} reconnected, resuming...",
                        "OK".green().bold(),
                        peer_name.cyan(),
                    ),
                );
            }
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
                    "Failed to build TransferResume acceptance"
                ),
                Ok(req) => {
                    network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&peer_id, req);
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
                    "Failed to build TransferStatus payload"
                ),
                Ok(req) => {
                    network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&peer_id, req);
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
                reason.clone(),
            ) {
                Err(e) => tracing::warn!(
                    peer = %peer_id,
                    %e,
                    "Failed to build TransferReject payload"
                ),
                Ok(req) => {
                    network
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_request(&peer_id, req);
                }
            }
        }
        NetworkCommand::TransferRejectedByPeer {
            peer_id,
            session_id,
            reason,
        } => {
            let peer_key = peer_id.to_string();
            let removed = pending_chunk_transfers.remove(&peer_key);
            if let Some(mut pct) = removed {
                let session_matches =
                    transfer_session_matches(session_id.as_deref(), &pct.session.session_id);
                if session_matches {
                    if reason == "session_unknown" {
                        if tor_transfer_restart_already_pending(&pct) {
                            pending_chunk_transfers.insert(peer_key, pct);
                            return;
                        }
                        reset_tor_transfer_for_reapproval(&mut pct);
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
                        pending_chunk_transfers.insert(peer_key, pct);
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
                    pct.chunk_source.secure_cleanup();
                    if !no_resume_session_persistence {
                        let session_dir = runtime_temp_path("qypha-sessions");
                        let session_file =
                            session_dir.join(format!("{}.session.json", pct.session.session_id));
                        secure_wipe_file(&session_file);
                    }
                } else {
                    pending_chunk_transfers.insert(peer_key, pct);
                }
            }
        }
        _ => unreachable!("unexpected command routed to handle_libp2p_transfer_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pending_chunk_transfer(
        peer_id: libp2p::PeerId,
        peer_did: &str,
        peer_name: &str,
    ) -> PendingChunkTransfer {
        let sender = AgentKeyPair::generate("sender", "agent");
        let (session, chunks) = chunked_transfer::prepare_session(
            &sender,
            peer_did,
            "payload.bin",
            "confidential",
            b"hello world over tor transfer",
            4,
        )
        .expect("sample transfer session");
        PendingChunkTransfer {
            peer_id,
            peer_name: peer_name.to_string(),
            peer_did: peer_did.to_string(),
            session,
            chunk_source: ChunkSource::InMemory(chunks),
            next_chunk: 2,
            chunk_size: 4,
            x25519_pk: [7u8; 32],
            kyber_pk: Some(vec![8u8; 32]),
            ttl: 0,
            path: "/tmp/payload.bin".to_string(),
            packed_mb: 0.0,
            packed_size: 27,
            inflight_request: None,
            retry_count: 3,
            backoff_until: Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(30)),
            reconnect_wait_secs: 45,
            reconnecting: true,
            last_bridge_at: tokio::time::Instant::now() - tokio::time::Duration::from_secs(60),
            bridge_warming: true,
            peer_onion: Some("peerexample123.onion".to_string()),
            peer_onion_port: 9090,
            chunk_jitter_until: Some(
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(5),
            ),
            awaiting_receiver_accept: false,
            awaiting_started_at: tokio::time::Instant::now(),
            needs_reinit: false,
        }
    }

    #[test]
    fn tor_transfer_rebind_updates_peer_identity_and_resets_reconnect_state() {
        let old_peer_id = libp2p::PeerId::random();
        let new_peer_id = libp2p::PeerId::random();
        let peer_did = "did:nxf:tor-peer";
        let mut pending = HashMap::new();
        pending.insert(
            old_peer_id.to_string(),
            sample_pending_chunk_transfer(old_peer_id, peer_did, "old-name"),
        );

        assert!(rebind_pending_tor_chunk_transfer_peer(
            &mut pending,
            peer_did,
            new_peer_id,
            "new-name",
        ));
        assert!(!pending.contains_key(&old_peer_id.to_string()));

        let rebound = pending
            .get(&new_peer_id.to_string())
            .expect("rebound transfer should exist");
        assert_eq!(rebound.peer_id, new_peer_id);
        assert_eq!(rebound.peer_name, "new-name");
        assert!(!rebound.reconnecting);
        assert!(!rebound.bridge_warming);
        assert_eq!(rebound.retry_count, 0);
        assert_eq!(rebound.reconnect_wait_secs, 0);
        assert!(rebound.backoff_until.is_some());
        assert!(rebound.chunk_jitter_until.is_none());
    }

    #[test]
    fn reset_tor_transfer_for_reapproval_marks_reinit_pending() {
        let peer_id = libp2p::PeerId::random();
        let mut pending = sample_pending_chunk_transfer(peer_id, "did:nxf:tor-peer", "peer");
        pending.awaiting_receiver_accept = false;
        pending.needs_reinit = false;
        pending.chunk_jitter_until =
            Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5));

        reset_tor_transfer_for_reapproval(&mut pending);

        assert!(pending.awaiting_receiver_accept);
        assert!(pending.needs_reinit);
        assert!(pending.inflight_request.is_none());
        assert_eq!(pending.retry_count, 0);
        assert_eq!(pending.reconnect_wait_secs, 0);
        assert!(!pending.reconnecting);
        assert!(!pending.bridge_warming);
        assert!(pending.chunk_jitter_until.is_none());
        assert!(tor_transfer_restart_already_pending(&pending));
    }

    #[test]
    fn apply_tor_transfer_resume_snapshot_rewinds_to_receiver_progress() {
        let peer_id = libp2p::PeerId::random();
        let mut pending = sample_pending_chunk_transfer(peer_id, "did:nxf:tor-peer", "peer");
        pending.next_chunk = pending.session.total_chunks;
        for chunk in &mut pending.session.chunks {
            chunk.sent = true;
            chunk.acknowledged = true;
        }

        let next_chunk = apply_tor_transfer_resume_snapshot(&mut pending.session, &[0, 1]);

        assert_eq!(next_chunk, 2);
        assert!(pending.session.chunks[0].acknowledged);
        assert!(pending.session.chunks[1].acknowledged);
        assert!(!pending.session.chunks[2].acknowledged);

        let restart_from_zero = apply_tor_transfer_resume_snapshot(&mut pending.session, &[]);
        assert_eq!(restart_from_zero, 0);
        assert!(pending
            .session
            .chunks
            .iter()
            .all(|chunk| !chunk.acknowledged));
    }
}

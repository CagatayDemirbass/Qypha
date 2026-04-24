use super::*;
use rand::seq::SliceRandom;

pub(crate) async fn poll_group_mailboxes_impl<T: MailboxTransport + ?Sized>(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    handshake_request_gate: &Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    transport: &T,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    actor_did: &str,
    agent_name: &str,
    keypair: &AgentKeyPair,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
    agent_data_dir: &Path,
    force_refresh: bool,
) {
    let now_ms = current_unix_ts_ms();
    let mut sessions = {
        let registry = registry.lock().await;
        registry.sessions.values().cloned().collect::<Vec<_>>()
    };
    if !force_refresh && sessions.len() > 1 {
        sessions.shuffle(&mut rand::thread_rng());
    }
    let dummy_poll_enabled = !force_refresh && matches!(log_mode, LogMode::Safe | LogMode::Ghost);
    let mut dummy_candidates = Vec::new();

    for session in sessions {
        let poll_due = {
            let mut registry = registry.lock().await;
            if force_refresh {
                registry.take_manual_mailbox_refresh_slot(&session.group_id, now_ms)
            } else {
                registry.mailbox_transport_due(&session.group_id, now_ms)
            }
        };
        if !poll_due {
            if dummy_poll_enabled {
                dummy_candidates.push(session);
            }
            continue;
        }
        let request = MailboxPollRequest {
            cursor: session.poll_cursor.clone(),
            limit: 64,
        };
        let result = match transport
            .poll_messages(
                &session.mailbox_descriptor,
                &session.mailbox_capability,
                &request,
            )
            .await
        {
            Ok(result) => {
                let recovered_after_failures = {
                    let mut registry = registry.lock().await;
                    registry.note_mailbox_transport_success(&session.group_id)
                };
                if let Some(failures) = recovered_after_failures {
                    let group_label = session.group_name.as_deref().unwrap_or(&session.group_id);
                    print_mailbox_recovered_notice(group_label);
                    if failures >= MAILBOX_TRANSPORT_DEGRADED_FAILURE_THRESHOLD {
                        let group_log_id = log_group_id(log_mode, &session.group_id);
                        let diag = mailbox_poll_log_context(
                            log_mode,
                            &session.mailbox_descriptor,
                            agent_data_dir,
                        )
                        .await;
                        tracing::debug!(
                            group_id = %group_log_id,
                            mailbox_epoch = session.mailbox_epoch,
                            join_locked = session.join_locked,
                            anonymous_group = session.anonymous_group,
                            recovered_after_failures = failures,
                            poll_limit = request.limit,
                            poll_cursor = %session
                                .poll_cursor
                                .as_deref()
                                .map(|cursor| log_mailbox_cursor(log_mode, cursor))
                                .unwrap_or_else(|| "none".to_string()),
                            mailbox_namespace = %diag.namespace,
                            mailbox_endpoint = %diag.endpoint,
                            mailbox_endpoint_kind = %diag.endpoint_kind,
                            mailbox_endpoint_host = %diag.endpoint_host,
                            mailbox_endpoint_port = diag.endpoint_port,
                            mailbox_endpoint_port_known = diag.endpoint_port_known,
                            local_embedded_service_group_id = %diag
                                .local_embedded_service_group_id
                                .unwrap_or_else(|| "none".to_string()),
                            local_embedded_service_status = %diag.local_embedded_service_status,
                            "Mailbox poll recovered"
                        );
                    }
                }
                result
            }
            Err(e) => {
                let failure = {
                    let mut registry = registry.lock().await;
                    registry.note_mailbox_transport_failure(
                        &session.group_id,
                        session.mailbox_descriptor.poll_interval_ms,
                        now_ms,
                    )
                };
                if failure.failures == 1 {
                    let group_label = session.group_name.as_deref().unwrap_or(&session.group_id);
                    print_mailbox_background_retry_notice(group_label);
                } else if failure.should_log {
                    let group_log_id = log_group_id(log_mode, &session.group_id);
                    let diag = mailbox_poll_log_context(
                        log_mode,
                        &session.mailbox_descriptor,
                        agent_data_dir,
                    )
                    .await;
                    tracing::debug!(
                        group_id = %group_log_id,
                        mailbox_epoch = session.mailbox_epoch,
                        join_locked = session.join_locked,
                        anonymous_group = session.anonymous_group,
                        retry_in_ms = failure.next_retry_after_ms,
                        consecutive_failures = failure.failures,
                        degraded = failure.degraded,
                        poll_limit = request.limit,
                        poll_cursor = %session
                            .poll_cursor
                            .as_deref()
                            .map(|cursor| log_mailbox_cursor(log_mode, cursor))
                            .unwrap_or_else(|| "none".to_string()),
                        mailbox_namespace = %diag.namespace,
                        mailbox_endpoint = %diag.endpoint,
                        mailbox_endpoint_kind = %diag.endpoint_kind,
                        mailbox_endpoint_host = %diag.endpoint_host,
                        mailbox_endpoint_port = diag.endpoint_port,
                        mailbox_endpoint_port_known = diag.endpoint_port_known,
                        local_embedded_service_group_id = %diag
                            .local_embedded_service_group_id
                            .unwrap_or_else(|| "none".to_string()),
                        local_embedded_service_status = %diag.local_embedded_service_status,
                        error_chain = %format_error_chain(&e),
                        %e,
                        "Mailbox poll failed"
                    );
                }
                continue;
            }
        };

        let mut session_rotated = false;
        let mut group_removed = false;
        let mut batch_fully_acked = result.items.is_empty();
        let mut saw_real_traffic = false;
        if !result.items.is_empty() {
            let mut ack_ids = Vec::with_capacity(result.items.len());
            let batch_len = result.items.len();
            let mut processed_items = 0usize;
            for item in result.items {
                processed_items = processed_items.saturating_add(1);
                let suppress_local_echo = {
                    let mut registry = registry.lock().await;
                    registry.consume_local_post_marker(&session.group_id, &item.message.message_id)
                };
                if suppress_local_echo {
                    ack_ids.push(item.envelope_id);
                    continue;
                }
                if let Err(error) = message_is_live(&item.message, current_unix_ts()) {
                    let group_log_id = log_group_id(log_mode, &session.group_id);
                    let message_log_id = log_message_id(log_mode, &item.message.message_id);
                    tracing::warn!(
                        group_id = %group_log_id,
                        message_id = %message_log_id,
                        %error,
                        "Rejected stale mailbox message"
                    );
                    ack_ids.push(item.envelope_id);
                    continue;
                }
                let first_seen = {
                    let mut registry = registry.lock().await;
                    registry.mark_message_seen(
                        &session.group_id,
                        &item.message.message_id,
                        item.message.created_at,
                    )
                };
                if !first_seen {
                    let group_log_id = log_group_id(log_mode, &session.group_id);
                    let message_log_id = log_message_id(log_mode, &item.message.message_id);
                    tracing::warn!(
                        group_id = %group_log_id,
                        message_id = %message_log_id,
                        "Rejected replayed mailbox message"
                    );
                    ack_ids.push(item.envelope_id);
                    continue;
                }

                let decoded = match decode_group_mailbox_message_with_context(
                    &crypto_context_for_session(&session),
                    &item.message,
                ) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        let group_log_id = log_group_id(log_mode, &session.group_id);
                        let message_log_id = log_message_id(log_mode, &item.message.message_id);
                        tracing::warn!(
                            group_id = %group_log_id,
                            message_id = %message_log_id,
                            %e,
                            "Mailbox payload decode failed"
                        );
                        continue;
                    }
                };

                let Some(decoded_kind) = decoded.kind else {
                    ack_ids.push(item.envelope_id);
                    continue;
                };
                if let Some(sender) = decoded.authenticated_sender.as_ref() {
                    if let Err(error) = verify_authenticated_group_sender_authorized(
                        &session,
                        &decoded_kind,
                        sender,
                    ) {
                        let group_log_id = log_group_id(log_mode, &session.group_id);
                        let message_log_id = log_message_id(log_mode, &item.message.message_id);
                        tracing::warn!(
                            group_id = %group_log_id,
                            message_id = %message_log_id,
                            sender_member_id = %sender.member_id,
                            sender_verifying_key_hex = %sender.verifying_key_hex,
                            %error,
                            "Authenticated group sender authorization failed"
                        );
                        ack_ids.push(item.envelope_id);
                        continue;
                    }
                }
                saw_real_traffic = true;

                match decoded_kind {
                    GroupMailboxMessageKind::Chat => {
                        let chat: GroupChatPayload = match serde_json::from_slice(&decoded.payload)
                        {
                            Ok(chat) => chat,
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(group_id = %group_log_id, %e, "Chat payload decode failed");
                                continue;
                            }
                        };
                        let (sender, sender_display_name) = if session.anonymous_group {
                            ("anonymous member".to_string(), None)
                        } else {
                            match item.message.sender_member_id.as_deref() {
                                Some(member_id) => {
                                    let display_name = session
                                        .known_members
                                        .get(member_id)
                                        .map(|profile| profile.display_name.trim().to_string())
                                        .filter(|label| !label.is_empty());
                                    let sender = display_group_member_label(
                                        display_name.as_deref(),
                                        member_id,
                                    );
                                    (sender, display_name)
                                }
                                None => ("unknown member".to_string(), None),
                            }
                        };
                        emit_ui_event(&GroupMailboxUiEvent {
                            kind: "chat".to_string(),
                            group_id: session.group_id.clone(),
                            group_name: session.group_name.clone(),
                            anonymous_group: session.anonymous_group,
                            manifest_id: None,
                            sender_member_id: item.message.sender_member_id.clone(),
                            message: Some(chat.body.clone()),
                            filename: None,
                            size_bytes: None,
                            member_id: None,
                            member_display_name: sender_display_name,
                            invite_code: None,
                            mailbox_epoch: Some(session.mailbox_epoch),
                            kicked_member_id: None,
                            ts_ms: ui_event_ts_ms_from_message(&item.message),
                        });
                        print_async_notice(
                            agent_name,
                            format!(
                                "   {} {} {}",
                                format!("[{}]", describe_group(&session)).cyan().bold(),
                                sender.dimmed(),
                                chat.body
                            ),
                        );
                        let mut audit = audit.lock().await;
                        audit.record(
                            "GROUP_MAILBOX_CHAT_RECV",
                            actor_did,
                            &format!("group_id={} kind=chat", session.group_id),
                        );
                        ack_ids.push(item.envelope_id);
                    }
                    GroupMailboxMessageKind::FileManifest => {
                        let manifest: GroupFileManifestPayload = match serde_json::from_slice(
                            &decoded.payload,
                        ) {
                            Ok(manifest) => manifest,
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(group_id = %group_log_id, %e, "File manifest decode failed");
                                continue;
                            }
                        };
                        let sender_label = if session.anonymous_group {
                            "anonymous member".to_string()
                        } else {
                            item.message
                                .sender_member_id
                                .as_deref()
                                .and_then(|member_id| session.known_members.get(member_id))
                                .map(|profile| profile.display_name.trim().to_string())
                                .filter(|label| !label.is_empty())
                                .or_else(|| item.message.sender_member_id.clone())
                                .unwrap_or_else(|| "unknown member".to_string())
                        };
                        emit_ui_event(&GroupMailboxUiEvent {
                            kind: "file_manifest".to_string(),
                            group_id: session.group_id.clone(),
                            group_name: session.group_name.clone(),
                            anonymous_group: session.anonymous_group,
                            manifest_id: Some(manifest.manifest_id.clone()),
                            sender_member_id: item.message.sender_member_id.clone(),
                            message: None,
                            filename: Some(manifest.filename.clone()),
                            size_bytes: Some(manifest.size_bytes),
                            member_id: None,
                            member_display_name: Some(sender_label.clone()),
                            invite_code: None,
                            mailbox_epoch: Some(session.mailbox_epoch),
                            kicked_member_id: None,
                            ts_ms: ui_event_ts_ms_from_message(&item.message),
                        });
                        print_async_notice(
                            agent_name,
                            format!(
                                "   {} {} shared {} in {} ({})",
                                "Group file:".yellow().bold(),
                                sender_label.cyan(),
                                manifest.filename.green(),
                                describe_group(&session).cyan(),
                                format_group_file_size(manifest.size_bytes)
                            ),
                        );
                        match {
                            let mut registry = registry.lock().await;
                            queue_pending_group_file_offer(
                                &mut registry,
                                &session,
                                &manifest,
                                item.message.sender_member_id.clone(),
                            )
                        } {
                            Ok(true) => {
                                let approval_message = format!(
                                    "approval required • from {} • {} • /accept {} or /reject {}",
                                    sender_label,
                                    format_group_file_size(manifest.size_bytes),
                                    manifest.manifest_id,
                                    manifest.manifest_id
                                );
                                emit_ui_event(&GroupMailboxUiEvent {
                                    kind: "file_offer_pending".to_string(),
                                    group_id: session.group_id.clone(),
                                    group_name: session.group_name.clone(),
                                    anonymous_group: session.anonymous_group,
                                    manifest_id: Some(manifest.manifest_id.clone()),
                                    sender_member_id: item.message.sender_member_id.clone(),
                                    message: Some(approval_message.clone()),
                                    filename: Some(manifest.filename.clone()),
                                    size_bytes: Some(manifest.size_bytes),
                                    member_id: None,
                                    member_display_name: Some(sender_label.clone()),
                                    invite_code: None,
                                    mailbox_epoch: Some(session.mailbox_epoch),
                                    kicked_member_id: None,
                                    ts_ms: ui_event_ts_ms_from_message(&item.message),
                                });
                                print_async_notice(
                                    agent_name,
                                    format!(
                                        "   {} {} from {} requires approval. Run {} or {}",
                                        "Approval:".yellow().bold(),
                                        manifest.filename.cyan(),
                                        sender_label.cyan(),
                                        format!("/accept {}", manifest.manifest_id).white().bold(),
                                        format!("/reject {}", manifest.manifest_id).white().bold()
                                    ),
                                );
                                ack_ids.push(item.envelope_id);
                            }
                            Ok(false) => {
                                ack_ids.push(item.envelope_id);
                            }
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let manifest_log_id =
                                    log_manifest_id(log_mode, &manifest.manifest_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    manifest_id = %manifest_log_id,
                                    %error,
                                    "Failed to queue pending group file offer"
                                );
                                continue;
                            }
                        }
                        let mut audit = audit.lock().await;
                        audit.record(
                            "GROUP_MAILBOX_FILE_RECV",
                            actor_did,
                            &format!(
                                "group_id={} filename={} bytes={}",
                                session.group_id, manifest.filename, manifest.size_bytes
                            ),
                        );
                    }
                    GroupMailboxMessageKind::FileChunkData
                    | GroupMailboxMessageKind::FileChunkComplete => {
                        continue;
                    }
                    GroupMailboxMessageKind::FastFileOffer => {
                        let offer: GroupFastFileOfferPayload =
                            match serde_json::from_slice(&decoded.payload) {
                                Ok(offer) => offer,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Fast file offer decode failed"
                                    );
                                    continue;
                                }
                            };
                        {
                            let mut locked = registry.lock().await;
                            let _ =
                                locked.store_pending_fast_file_offer(GroupPendingFastFileOffer {
                                    transfer_id: offer.transfer_id.clone(),
                                    manifest_id: offer.manifest_id.clone(),
                                    group_id: session.group_id.clone(),
                                    group_name: session.group_name.clone(),
                                    anonymous_group: session.anonymous_group,
                                    sender_member_id: item.message.sender_member_id.clone(),
                                    offer,
                                });
                        }
                        ack_ids.push(item.envelope_id);
                    }
                    GroupMailboxMessageKind::FastFileAccept => {
                        let accept: GroupFastFileAcceptPayload =
                            match serde_json::from_slice(&decoded.payload) {
                                Ok(accept) => accept,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Fast file accept decode failed"
                                    );
                                    continue;
                                }
                            };
                        let recipient_member_id = match decrypt_fast_file_accept_payload(
                            &accept,
                            item.message.sender_member_id.as_deref(),
                            &session.group_id,
                        ) {
                            Ok(recipient_member_id) => recipient_member_id,
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    transfer_id = %accept.transfer_id,
                                    %error,
                                    "Fast file accept rejected"
                                );
                                continue;
                            }
                        };
                        let staged = {
                            let locked = registry.lock().await;
                            locked.staged_fast_file_transfer_cloned(&accept.transfer_id)
                        };
                        let Some(staged) = staged else {
                            ack_ids.push(item.envelope_id);
                            continue;
                        };
                        if staged.expires_at <= current_unix_ts() {
                            let mut locked = registry.lock().await;
                            let _ = locked.clear_fast_file_transfer(&accept.transfer_id);
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        if session.local_member_id.as_deref()
                            != Some(staged.sender_member_id.as_str())
                        {
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        let sender_profile = match local_member_profile(&session) {
                            Ok(profile) => profile,
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    transfer_id = %accept.transfer_id,
                                    %error,
                                    "Fast file grant skipped because local sender profile is unavailable"
                                );
                                ack_ids.push(item.envelope_id);
                                continue;
                            }
                        };
                        let Some(target_profile) =
                            session.known_members.get(&recipient_member_id).cloned()
                        else {
                            let group_log_id = log_group_id(log_mode, &session.group_id);
                            tracing::warn!(
                                group_id = %group_log_id,
                                transfer_id = %accept.transfer_id,
                                recipient_member_id = %recipient_member_id,
                                "Fast file grant skipped because recipient profile is unknown"
                            );
                            ack_ids.push(item.envelope_id);
                            continue;
                        };
                        let (grant_message, grant_payload, grant_secret) =
                            match build_fast_file_grant_message(
                                &session,
                                &keypair.signing_key,
                                &sender_profile,
                                &target_profile,
                                &staged,
                                session.mailbox_descriptor.poll_interval_ms.max(30_000),
                            ) {
                                Ok(grant) => grant,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        transfer_id = %accept.transfer_id,
                                        %error,
                                        "Failed to build fast file grant"
                                    );
                                    ack_ids.push(item.envelope_id);
                                    continue;
                                }
                            };
                        match post_group_mailbox_message(transport, &session, &grant_message).await
                        {
                            Ok(_) => {
                                let mut locked = registry.lock().await;
                                locked
                                    .mark_local_post(&session.group_id, &grant_message.message_id);
                                locked.track_fast_file_grant(GroupFastFileGrantState {
                                    transfer_id: grant_secret.transfer_id.clone(),
                                    grant_id: Some(grant_payload.grant_id.clone()),
                                    group_id: grant_secret.group_id.clone(),
                                    recipient_member_id: grant_secret.recipient_did.clone(),
                                    relay_only: grant_secret.relay_only,
                                    expires_at: grant_secret.expires_at,
                                    envelope: GroupFastFileGrantEnvelope::Grant(grant_payload),
                                    secret: Some(grant_secret),
                                });
                                ack_ids.push(item.envelope_id);
                            }
                            Err(error) => {
                                let failure = {
                                    let mut locked = registry.lock().await;
                                    locked.note_mailbox_transport_failure(
                                        &session.group_id,
                                        session.mailbox_descriptor.poll_interval_ms,
                                        now_ms,
                                    )
                                };
                                if failure.should_log {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        transfer_id = %accept.transfer_id,
                                        retry_in_ms = failure.next_retry_after_ms,
                                        consecutive_failures = failure.failures,
                                        %error,
                                        "Fast file grant post failed"
                                    );
                                }
                                ack_ids.push(item.envelope_id);
                            }
                        }
                    }
                    GroupMailboxMessageKind::FastFileGrant => {
                        let grant: GroupFastFileGrantPayload =
                            match bincode::deserialize(&decoded.payload) {
                                Ok(grant) => grant,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Fast file grant decode failed"
                                    );
                                    ack_ids.push(item.envelope_id);
                                    continue;
                                }
                            };
                        let local_member_id = match session.local_member_id.as_deref() {
                            Some(local_member_id) => local_member_id,
                            None => {
                                ack_ids.push(item.envelope_id);
                                continue;
                            }
                        };
                        if grant.recipient_member_id != local_member_id {
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        let secret = match decrypt_fast_file_grant_payload(
                            &grant,
                            keypair,
                            item.message.sender_member_id.as_deref(),
                            local_member_id,
                            &session.group_id,
                        ) {
                            Ok((_, secret)) => secret,
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    transfer_id = %grant.transfer_id,
                                    %error,
                                    "Fast file grant rejected"
                                );
                                ack_ids.push(item.envelope_id);
                                continue;
                            }
                        };
                        {
                            let mut locked = registry.lock().await;
                            locked.track_fast_file_grant(GroupFastFileGrantState {
                                transfer_id: secret.transfer_id.clone(),
                                grant_id: Some(grant.grant_id.clone()),
                                group_id: secret.group_id.clone(),
                                recipient_member_id: secret.recipient_did.clone(),
                                relay_only: secret.relay_only,
                                expires_at: secret.expires_at,
                                envelope: GroupFastFileGrantEnvelope::Grant(grant),
                                secret: Some(secret),
                            });
                        }
                        ack_ids.push(item.envelope_id);
                    }
                    GroupMailboxMessageKind::FastFileStatus => {
                        let status: GroupFastFileStatusPayload =
                            match serde_json::from_slice(&decoded.payload) {
                                Ok(status) => status,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Fast file status decode failed"
                                    );
                                    continue;
                                }
                            };
                        if matches!(
                            status.status,
                            crate::network::protocol::GroupFastFileStatusKind::Expired
                        ) {
                            let mut locked = registry.lock().await;
                            let _ = locked.clear_fast_file_transfer(&status.transfer_id);
                        } else if matches!(
                            status.status,
                            crate::network::protocol::GroupFastFileStatusKind::Completed
                                | crate::network::protocol::GroupFastFileStatusKind::Aborted
                        ) {
                            let mut locked = registry.lock().await;
                            let _ = locked.clear_fast_file_grant_for_recipient(
                                &status.transfer_id,
                                &status.recipient_member_id,
                            );
                        }
                        ack_ids.push(item.envelope_id);
                    }
                    GroupMailboxMessageKind::MembershipNotice => {
                        let notice: MembershipNoticePayload = match serde_json::from_slice(
                            &decoded.payload,
                        ) {
                            Ok(notice) => notice,
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(group_id = %group_log_id, %e, "Membership notice decode failed");
                                continue;
                            }
                        };
                        let (profile, notice_state) = match verify_membership_notice_payload(
                            &notice,
                            item.message.sender_member_id.as_deref(),
                        ) {
                            Ok(verified) => verified,
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let message_log_id =
                                    log_message_id(log_mode, &item.message.message_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    message_id = %message_log_id,
                                    %e,
                                    "Membership notice verification failed"
                                );
                                continue;
                            }
                        };
                        let was_known = {
                            let registry = registry.lock().await;
                            registry
                                .known_member_profile(&session.group_id, &profile.member_id)
                                .is_some()
                        };
                        match notice_state {
                            MembershipNoticeState::Joined => {
                                {
                                    let mut registry = registry.lock().await;
                                    if let Err(error) = registry
                                        .observe_member_profile(&session.group_id, profile.clone())
                                    {
                                        let group_log_id =
                                            log_group_id(log_mode, &session.group_id);
                                        tracing::warn!(
                                            group_id = %group_log_id,
                                            %error,
                                            "Failed to persist mailbox member profile"
                                        );
                                    }
                                }
                                if !was_known {
                                    emit_ui_event(&GroupMailboxUiEvent {
                                        kind: "membership_notice".to_string(),
                                        group_id: session.group_id.clone(),
                                        group_name: session.group_name.clone(),
                                        anonymous_group: session.anonymous_group,
                                        manifest_id: None,
                                        sender_member_id: Some(profile.member_id.clone()),
                                        message: None,
                                        filename: None,
                                        size_bytes: None,
                                        member_id: Some(profile.member_id.clone()),
                                        member_display_name: Some(profile.display_name.clone()),
                                        invite_code: None,
                                        mailbox_epoch: Some(session.mailbox_epoch),
                                        kicked_member_id: None,
                                        ts_ms: ui_event_ts_ms_from_message(&item.message),
                                    });
                                    if session.local_member_id.as_deref()
                                        != Some(profile.member_id.as_str())
                                    {
                                        print_async_notice(
                                            agent_name,
                                            format!(
                                                "   {} {} joined as {}",
                                                format!("[{}]", describe_group(&session))
                                                    .cyan()
                                                    .bold(),
                                                profile.display_name.green(),
                                                crate::agent::contact_identity::displayed_did(
                                                    &profile.member_id,
                                                )
                                                .dimmed()
                                            ),
                                        );
                                    }
                                }
                                if !was_known {
                                    if let Ok(local_profile) = local_member_profile(&session) {
                                        if local_profile.member_id != profile.member_id {
                                            if let Err(error) =
                                                announce_local_identified_membership(
                                                    registry,
                                                    transport,
                                                    &keypair.signing_key,
                                                    &local_profile,
                                                    &session.group_id,
                                                )
                                                .await
                                            {
                                                let group_log_id =
                                                    log_group_id(log_mode, &session.group_id);
                                                let member_log_id =
                                                    log_member_id(log_mode, &profile.member_id);
                                                tracing::warn!(
                                                    group_id = %group_log_id,
                                                    member_id = %member_log_id,
                                                    %error,
                                                    "Failed to reciprocate membership notice"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            MembershipNoticeState::Left => {
                                if session.local_member_id.as_deref()
                                    == Some(profile.member_id.as_str())
                                {
                                    ack_ids.push(item.envelope_id);
                                    continue;
                                }
                                let removed = {
                                    let mut registry = registry.lock().await;
                                    match registry.remove_member_profile(
                                        &session.group_id,
                                        &profile.member_id,
                                    ) {
                                        Ok(removed) => removed,
                                        Err(error) => {
                                            let group_log_id =
                                                log_group_id(log_mode, &session.group_id);
                                            tracing::warn!(
                                                group_id = %group_log_id,
                                                %error,
                                                "Failed to persist mailbox member departure"
                                            );
                                            false
                                        }
                                    }
                                };
                                if removed {
                                    print_async_notice(
                                        agent_name,
                                        format!(
                                            "   {} {} left ({})",
                                            format!("[{}]", describe_group(&session)).cyan().bold(),
                                            profile.display_name.yellow(),
                                            profile.member_id.dimmed()
                                        ),
                                    );
                                }
                            }
                        }
                        let mut audit = audit.lock().await;
                        audit.record(
                            "GROUP_MAILBOX_MEMBER_NOTICE",
                            actor_did,
                            &format!(
                                "group_id={} member_id={} state={} new={}",
                                session.group_id,
                                profile.member_id,
                                membership_notice_state_label(notice_state),
                                !was_known
                            ),
                        );
                        ack_ids.push(item.envelope_id);
                    }
                    GroupMailboxMessageKind::KickNotice => {
                        if session.anonymous_group {
                            let group_log_id = log_group_id(log_mode, &session.group_id);
                            let message_log_id = log_message_id(log_mode, &item.message.message_id);
                            tracing::warn!(
                                group_id = %group_log_id,
                                message_id = %message_log_id,
                                "Rejected authenticated kick notice for anonymous mailbox group"
                            );
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        let Some(local_member_id) = session.local_member_id.as_deref() else {
                            ack_ids.push(item.envelope_id);
                            continue;
                        };
                        let notice: GroupKickNoticePayload =
                            match serde_json::from_slice(&decoded.payload) {
                                Ok(notice) => notice,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Group kick notice decode failed"
                                    );
                                    continue;
                                }
                            };
                        match verify_group_kick_notice_payload(
                            &notice,
                            item.message.sender_member_id.as_deref(),
                            &session.group_id,
                            session.owner_member_id.as_deref(),
                        ) {
                            Ok(owner_member_id) => {
                                if notice.kicked_member_id == local_member_id {
                                    emit_ui_event(&GroupMailboxUiEvent {
                                        kind: "group_removed".to_string(),
                                        group_id: session.group_id.clone(),
                                        group_name: session.group_name.clone(),
                                        anonymous_group: session.anonymous_group,
                                        manifest_id: None,
                                        sender_member_id: Some(owner_member_id.clone()),
                                        message: Some("removed from group by owner".to_string()),
                                        filename: None,
                                        size_bytes: None,
                                        member_id: Some(local_member_id.to_string()),
                                        member_display_name: None,
                                        invite_code: None,
                                        mailbox_epoch: Some(notice.mailbox_epoch),
                                        kicked_member_id: Some(notice.kicked_member_id.clone()),
                                        ts_ms: ui_event_ts_ms_from_message(&item.message),
                                    });
                                    print_async_notice(
                                        agent_name,
                                        format!(
                                            "   {} removed you from {} at epoch {}",
                                            owner_member_id.dimmed(),
                                            format!("[{}]", describe_group(&session)).cyan().bold(),
                                            notice.mailbox_epoch
                                        ),
                                    );
                                    {
                                        let mut registry = registry.lock().await;
                                        if let Err(error) = registry.remove_group(&session.group_id)
                                        {
                                            let group_log_id =
                                                log_group_id(log_mode, &session.group_id);
                                            tracing::warn!(
                                                group_id = %group_log_id,
                                                %error,
                                                "Failed to remove mailbox group after kick notice"
                                            );
                                            continue;
                                        }
                                    }
                                    let mut audit = audit.lock().await;
                                    audit.record(
                                        "GROUP_MAILBOX_KICK_NOTICE_RECV",
                                        actor_did,
                                        &format!(
                                            "group_id={} owner_member_id={} kicked_member_id={} epoch={}",
                                            session.group_id,
                                            owner_member_id,
                                            notice.kicked_member_id,
                                            notice.mailbox_epoch
                                        ),
                                    );
                                    ack_ids.push(item.envelope_id);
                                    group_removed = true;
                                    break;
                                }
                                ack_ids.push(item.envelope_id);
                            }
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let message_log_id =
                                    log_message_id(log_mode, &item.message.message_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    message_id = %message_log_id,
                                    %error,
                                    "Group kick notice verification failed"
                                );
                            }
                        }
                    }
                    GroupMailboxMessageKind::GroupDisband => {
                        if session.anonymous_group {
                            let group_log_id = log_group_id(log_mode, &session.group_id);
                            let message_log_id = log_message_id(log_mode, &item.message.message_id);
                            tracing::warn!(
                                group_id = %group_log_id,
                                message_id = %message_log_id,
                                "Rejected unauthenticated group disband notice for anonymous mailbox group"
                            );
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        let disband: GroupDisbandPayload =
                            match serde_json::from_slice(&decoded.payload) {
                                Ok(disband) => disband,
                                Err(error) => {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        %error,
                                        "Group disband decode failed"
                                    );
                                    continue;
                                }
                            };
                        match verify_group_disband_payload(
                            &disband,
                            item.message.sender_member_id.as_deref(),
                            &session.group_id,
                            session.owner_member_id.as_deref(),
                        ) {
                            Ok(owner_member_id) => {
                                emit_ui_event(&GroupMailboxUiEvent {
                                    kind: "group_disbanded".to_string(),
                                    group_id: session.group_id.clone(),
                                    group_name: session.group_name.clone(),
                                    anonymous_group: session.anonymous_group,
                                    manifest_id: None,
                                    sender_member_id: Some(owner_member_id.clone()),
                                    message: Some("group disbanded".to_string()),
                                    filename: None,
                                    size_bytes: None,
                                    member_id: None,
                                    member_display_name: None,
                                    invite_code: None,
                                    mailbox_epoch: Some(disband.mailbox_epoch),
                                    kicked_member_id: None,
                                    ts_ms: ui_event_ts_ms_from_message(&item.message),
                                });
                                print_async_notice(
                                    agent_name,
                                    format!(
                                        "   {} disbanded by owner ({})",
                                        format!("[{}]", describe_group(&session)).cyan().bold(),
                                        owner_member_id.dimmed()
                                    ),
                                );
                                {
                                    let mut registry = registry.lock().await;
                                    if let Err(error) =
                                        registry.remove_group_as_disbanded(&session.group_id)
                                    {
                                        let group_log_id =
                                            log_group_id(log_mode, &session.group_id);
                                        tracing::warn!(
                                            group_id = %group_log_id,
                                            %error,
                                            "Failed to remove disbanded mailbox group"
                                        );
                                        continue;
                                    }
                                }
                                let mut audit = audit.lock().await;
                                audit.record(
                                    "GROUP_MAILBOX_DISBAND_RECV",
                                    actor_did,
                                    &format!(
                                        "group_id={} owner_member_id={} epoch={}",
                                        session.group_id, owner_member_id, disband.mailbox_epoch
                                    ),
                                );
                                ack_ids.push(item.envelope_id);
                                group_removed = true;
                                break;
                            }
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let message_log_id =
                                    log_message_id(log_mode, &item.message.message_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    message_id = %message_log_id,
                                    %error,
                                    "Group disband verification failed"
                                );
                            }
                        }
                    }
                    GroupMailboxMessageKind::DirectHandshakeOffer => {
                        let Some(local_member_id) = session.local_member_id.as_deref() else {
                            continue;
                        };
                        let offer = match decode_direct_handshake_offer_payload_bytes(
                            &decoded.payload,
                        ) {
                            Ok(offer) => offer,
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(group_id = %group_log_id, %e, "Direct offer decode failed");
                                continue;
                            }
                        };
                        if offer.target_member_id != local_member_id {
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        match decrypt_direct_handshake_offer_payload(
                            &offer,
                            keypair,
                            item.message.sender_member_id.as_deref(),
                            local_member_id,
                        ) {
                            Ok((sender_member_id, invite_code)) => {
                                let received_at_ms =
                                    ui_event_ts_ms_from_message(&item.message).max(0) as u64;
                                let expires_at_ms =
                                    received_at_ms.saturating_add(item.message.ttl_ms);
                                let offer_decision = {
                                    let mut gate = handshake_request_gate.lock().await;
                                    gate.evaluate_incoming_offer(
                                        &sender_member_id,
                                        current_unix_ts_ms(),
                                    )
                                };
                                match offer_decision {
                                    HandshakeOfferDecision::Allow => {
                                        {
                                            let mut locked = registry.lock().await;
                                            if let Err(error) = queue_pending_group_handshake_offer(
                                                &mut locked,
                                                &session,
                                                &sender_member_id,
                                                &invite_code,
                                                received_at_ms,
                                                expires_at_ms,
                                            ) {
                                                let group_log_id =
                                                    log_group_id(log_mode, &session.group_id);
                                                let sender_log_id =
                                                    log_member_id(log_mode, &sender_member_id);
                                                tracing::warn!(
                                                    group_id = %group_log_id,
                                                    sender_member_id = %sender_log_id,
                                                    %error,
                                                    "Failed to persist pending direct handshake offer"
                                                );
                                            }
                                        }
                                        emit_ui_event(&GroupMailboxUiEvent {
                                            kind: "direct_handshake_offer".to_string(),
                                            group_id: session.group_id.clone(),
                                            group_name: session.group_name.clone(),
                                            anonymous_group: session.anonymous_group,
                                            manifest_id: None,
                                            sender_member_id: Some(sender_member_id.clone()),
                                            message: None,
                                            filename: None,
                                            size_bytes: None,
                                            member_id: None,
                                            member_display_name: None,
                                            invite_code: Some(invite_code.clone()),
                                            mailbox_epoch: Some(session.mailbox_epoch),
                                            kicked_member_id: None,
                                            ts_ms: ui_event_ts_ms_from_message(&item.message),
                                        });
                                        print_async_notice(
                                            agent_name,
                                            format!(
                                                "   {} {} requested direct trust. Run {} or {} or {}",
                                                format!("[{}]", describe_group(&session))
                                                    .cyan()
                                                    .bold(),
                                                crate::agent::contact_identity::displayed_did(
                                                    &sender_member_id,
                                                )
                                                .dimmed(),
                                                format!(
                                                    "/accept {}",
                                                    crate::agent::contact_identity::displayed_did(
                                                        &sender_member_id,
                                                    )
                                                )
                                                    .white()
                                                    .bold(),
                                                format!(
                                                    "/reject {}",
                                                    crate::agent::contact_identity::displayed_did(
                                                        &sender_member_id,
                                                    )
                                                )
                                                    .white()
                                                    .bold(),
                                                format!(
                                                    "/block {}",
                                                    crate::agent::contact_identity::displayed_did(
                                                        &sender_member_id,
                                                    )
                                                )
                                                    .white()
                                                    .bold()
                                            ),
                                        );
                                        let mut audit = audit.lock().await;
                                        audit.record(
                                            "GROUP_MAILBOX_DIRECT_OFFER",
                                            actor_did,
                                            &format!(
                                                "group_id={} from_member_id={}",
                                                session.group_id, sender_member_id
                                            ),
                                        );
                                        ack_ids.push(item.envelope_id);
                                    }
                                    HandshakeOfferDecision::BlockedGlobal => {
                                        let mut audit = audit.lock().await;
                                        audit.record(
                                            "GROUP_MAILBOX_DIRECT_OFFER_BLOCKED_ALL",
                                            actor_did,
                                            &format!(
                                                "group_id={} from_member_id={}",
                                                session.group_id, sender_member_id
                                            ),
                                        );
                                        ack_ids.push(item.envelope_id);
                                    }
                                    HandshakeOfferDecision::BlockedMember => {
                                        let mut audit = audit.lock().await;
                                        audit.record(
                                            "GROUP_MAILBOX_DIRECT_OFFER_BLOCKED_MEMBER",
                                            actor_did,
                                            &format!(
                                                "group_id={} from_member_id={}",
                                                session.group_id, sender_member_id
                                            ),
                                        );
                                        ack_ids.push(item.envelope_id);
                                    }
                                    HandshakeOfferDecision::RateLimited { retry_after_ms } => {
                                        let group_log_id =
                                            log_group_id(log_mode, &session.group_id);
                                        let sender_log_id =
                                            log_member_id(log_mode, &sender_member_id);
                                        tracing::info!(
                                            group_id = %group_log_id,
                                            sender_member_id = %sender_log_id,
                                            retry_after_ms,
                                            "Suppressed repeated direct handshake offer"
                                        );
                                        let mut audit = audit.lock().await;
                                        audit.record(
                                            "GROUP_MAILBOX_DIRECT_OFFER_RATE_LIMIT",
                                            actor_did,
                                            &format!(
                                                "group_id={} from_member_id={} retry_after_ms={}",
                                                session.group_id, sender_member_id, retry_after_ms
                                            ),
                                        );
                                        ack_ids.push(item.envelope_id);
                                    }
                                }
                            }
                            Err(e) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let message_log_id =
                                    log_message_id(log_mode, &item.message.message_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    message_id = %message_log_id,
                                    %e,
                                    "Direct handshake offer verification failed"
                                );
                            }
                        }
                    }
                    GroupMailboxMessageKind::MailboxRotation => {
                        let Some(local_member_id) = session.local_member_id.as_deref() else {
                            continue;
                        };
                        let rotation: MailboxRotationPayload = match serde_json::from_slice(
                            &decoded.payload,
                        ) {
                            Ok(rotation) => rotation,
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                tracing::warn!(group_id = %group_log_id, %error, "Mailbox rotation decode failed");
                                continue;
                            }
                        };
                        if rotation.target_member_id != local_member_id {
                            ack_ids.push(item.envelope_id);
                            continue;
                        }
                        match decrypt_mailbox_rotation_payload(
                            &rotation,
                            keypair,
                            item.message.sender_member_id.as_deref(),
                            local_member_id,
                            &session.group_id,
                        ) {
                            Ok((sender_member_id, kicked_member_id, secret)) => {
                                if session.owner_member_id.as_deref()
                                    != Some(sender_member_id.as_str())
                                {
                                    let group_log_id = log_group_id(log_mode, &session.group_id);
                                    let sender_log_id = log_member_id(log_mode, &sender_member_id);
                                    tracing::warn!(
                                        group_id = %group_log_id,
                                        sender_member_id = %sender_log_id,
                                        "Rejected mailbox rotation from non-owner"
                                    );
                                    continue;
                                }
                                match apply_mailbox_rotation(
                                    &session,
                                    &sender_member_id,
                                    &kicked_member_id,
                                    secret,
                                ) {
                                    Ok(rotated_session) => {
                                        let local_profile = local_member_profile(&rotated_session);
                                        {
                                            let mut registry = registry.lock().await;
                                            if let Err(error) =
                                                registry.insert_session(rotated_session.clone())
                                            {
                                                let group_log_id =
                                                    log_group_id(log_mode, &session.group_id);
                                                tracing::warn!(
                                                    group_id = %group_log_id,
                                                    %error,
                                                    "Failed to persist mailbox rotation"
                                                );
                                                continue;
                                            }
                                        }
                                        if let Ok(local_profile) = local_profile {
                                            if let Err(error) =
                                                announce_local_identified_membership(
                                                    registry,
                                                    transport,
                                                    &keypair.signing_key,
                                                    &local_profile,
                                                    &rotated_session.group_id,
                                                )
                                                .await
                                            {
                                                let group_log_id = log_group_id(
                                                    log_mode,
                                                    &rotated_session.group_id,
                                                );
                                                tracing::warn!(
                                                    group_id = %group_log_id,
                                                    %error,
                                                    "Failed to announce mailbox membership after rotation"
                                                );
                                            }
                                        }
                                        emit_ui_event(&GroupMailboxUiEvent {
                                            kind: if kicked_member_id.is_empty() {
                                                if rotated_session.join_locked {
                                                    "mailbox_locked".to_string()
                                                } else {
                                                    "mailbox_unlocked".to_string()
                                                }
                                            } else {
                                                "mailbox_rotation".to_string()
                                            },
                                            group_id: rotated_session.group_id.clone(),
                                            group_name: rotated_session.group_name.clone(),
                                            anonymous_group: rotated_session.anonymous_group,
                                            manifest_id: None,
                                            sender_member_id: Some(sender_member_id.clone()),
                                            message: None,
                                            filename: None,
                                            size_bytes: None,
                                            member_id: None,
                                            member_display_name: None,
                                            invite_code: None,
                                            mailbox_epoch: Some(rotated_session.mailbox_epoch),
                                            kicked_member_id: (!kicked_member_id.is_empty())
                                                .then_some(kicked_member_id.clone()),
                                            ts_ms: ui_event_ts_ms_from_message(&item.message),
                                        });
                                        if kicked_member_id.is_empty() {
                                            print_async_notice(
                                                agent_name,
                                                format!(
                                                    "   {} mailbox {} at epoch {}",
                                                    format!(
                                                        "[{}]",
                                                        describe_group(&rotated_session)
                                                    )
                                                    .cyan()
                                                    .bold(),
                                                    if rotated_session.join_locked {
                                                        "locked"
                                                    } else {
                                                        "unlocked"
                                                    },
                                                    rotated_session.mailbox_epoch
                                                ),
                                            );
                                        } else {
                                            print_async_notice(
                                                agent_name,
                                                format!(
                                                    "   {} rotated mailbox epoch {} and removed {}",
                                                    format!(
                                                        "[{}]",
                                                        describe_group(&rotated_session)
                                                    )
                                                    .cyan()
                                                    .bold(),
                                                    rotated_session.mailbox_epoch,
                                                    crate::agent::contact_identity::displayed_did(
                                                        &kicked_member_id,
                                                    )
                                                    .dimmed()
                                                ),
                                            );
                                        }
                                        let mut audit = audit.lock().await;
                                        audit.record(
                                            "GROUP_MAILBOX_ROTATE_RECV",
                                            actor_did,
                                            &format!(
                                                "group_id={} epoch={} kicked_member_id={} join_locked={}",
                                                rotated_session.group_id,
                                                rotated_session.mailbox_epoch,
                                                kicked_member_id,
                                                rotated_session.join_locked
                                            ),
                                        );
                                        ack_ids.push(item.envelope_id);
                                        session_rotated = true;
                                        break;
                                    }
                                    Err(error) => {
                                        let group_log_id =
                                            log_group_id(log_mode, &session.group_id);
                                        tracing::warn!(
                                            group_id = %group_log_id,
                                            %error,
                                            "Mailbox rotation apply failed"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                let group_log_id = log_group_id(log_mode, &session.group_id);
                                let message_log_id =
                                    log_message_id(log_mode, &item.message.message_id);
                                tracing::warn!(
                                    group_id = %group_log_id,
                                    message_id = %message_log_id,
                                    %error,
                                    "Mailbox rotation verification failed"
                                );
                            }
                        }
                    }
                    GroupMailboxMessageKind::AnonymousOpaque => {
                        ack_ids.push(item.envelope_id);
                    }
                }
            }

            // Mailbox cursors are client-driven; server-side ack requests are advisory only.
            let all_items_locally_acked = ack_ids.len() == batch_len;
            batch_fully_acked = all_items_locally_acked;
            let partial_ack_reason = if batch_fully_acked {
                None
            } else if session_rotated {
                Some(GroupMailboxPartialAckReason::RotationAppliedMidBatch)
            } else {
                Some(GroupMailboxPartialAckReason::ProcessingDeferred)
            };
            if !group_removed && !batch_fully_acked {
                let group_log_id = log_group_id(log_mode, &session.group_id);
                let diag =
                    mailbox_poll_log_context(log_mode, &session.mailbox_descriptor, agent_data_dir)
                        .await;
                let partial_ack_reason = partial_ack_reason
                    .unwrap_or(GroupMailboxPartialAckReason::ProcessingDeferred)
                    .as_str();
                if session_rotated {
                    tracing::info!(
                        group_id = %group_log_id,
                        mailbox_epoch = session.mailbox_epoch,
                        join_locked = session.join_locked,
                        acked = ack_ids.len(),
                        batch_len,
                        processed_items,
                        unprocessed_items = batch_len.saturating_sub(processed_items),
                        partial_ack_reason = %partial_ack_reason,
                        poll_cursor = %session
                            .poll_cursor
                            .as_deref()
                            .map(|cursor| log_mailbox_cursor(log_mode, cursor))
                            .unwrap_or_else(|| "none".to_string()),
                        mailbox_namespace = %diag.namespace,
                        mailbox_endpoint = %diag.endpoint,
                        mailbox_endpoint_kind = %diag.endpoint_kind,
                        mailbox_endpoint_host = %diag.endpoint_host,
                        mailbox_endpoint_port = diag.endpoint_port,
                        mailbox_endpoint_port_known = diag.endpoint_port_known,
                        local_embedded_service_group_id = %diag
                            .local_embedded_service_group_id
                            .unwrap_or_else(|| "none".to_string()),
                        local_embedded_service_status = %diag.local_embedded_service_status,
                        "Group mailbox batch intentionally pinned during session rotation"
                    );
                } else {
                    tracing::warn!(
                        group_id = %group_log_id,
                        mailbox_epoch = session.mailbox_epoch,
                        join_locked = session.join_locked,
                        anonymous_group = session.anonymous_group,
                        acked = ack_ids.len(),
                        batch_len,
                        processed_items,
                        unprocessed_items = batch_len.saturating_sub(processed_items),
                        partial_ack_reason = %partial_ack_reason,
                        poll_cursor = %session
                            .poll_cursor
                            .as_deref()
                            .map(|cursor| log_mailbox_cursor(log_mode, cursor))
                            .unwrap_or_else(|| "none".to_string()),
                        mailbox_namespace = %diag.namespace,
                        mailbox_endpoint = %diag.endpoint,
                        mailbox_endpoint_kind = %diag.endpoint_kind,
                        mailbox_endpoint_host = %diag.endpoint_host,
                        mailbox_endpoint_port = diag.endpoint_port,
                        mailbox_endpoint_port_known = diag.endpoint_port_known,
                        local_embedded_service_group_id = %diag
                            .local_embedded_service_group_id
                            .unwrap_or_else(|| "none".to_string()),
                        local_embedded_service_status = %diag.local_embedded_service_status,
                        "Group mailbox batch not fully processed; keeping cursor pinned"
                    );
                }
            }
        }

        if saw_real_traffic && !group_removed {
            let mut registry = registry.lock().await;
            registry.note_real_activity(&session.group_id);
        }

        if session_rotated || group_removed {
            continue;
        }

        {
            let mut registry = registry.lock().await;
            let next_cursor = if batch_fully_acked {
                result.next_cursor.clone()
            } else {
                session.poll_cursor.clone()
            };
            if let Err(error) = registry.update_poll_cursor(&session.group_id, next_cursor) {
                let group_log_id = log_group_id(log_mode, &session.group_id);
                tracing::warn!(
                    group_id = %group_log_id,
                    %error,
                    "Failed to persist mailbox poll cursor"
                );
            }
        }
    }

    if dummy_poll_enabled && !dummy_candidates.is_empty() {
        emit_privacy_dummy_mailbox_polls(
            transport,
            log_mode,
            dummy_candidates,
            MAILBOX_PRIVACY_DUMMY_POLLS_PER_TICK,
        )
        .await;
    }

    poll_group_chunk_downloads_once(
        registry,
        transport,
        audit,
        actor_did,
        receive_dir_config,
        log_mode,
    )
    .await;
}

async fn emit_privacy_dummy_mailbox_polls<T: MailboxTransport + ?Sized>(
    transport: &T,
    log_mode: &LogMode,
    mut sessions: Vec<GroupMailboxSession>,
    dummy_polls_per_tick: usize,
) {
    if dummy_polls_per_tick == 0 || sessions.is_empty() {
        return;
    }
    sessions.shuffle(&mut rand::thread_rng());
    for session in sessions.into_iter().take(dummy_polls_per_tick) {
        let request = MailboxPollRequest {
            cursor: Some(MAILBOX_CURSOR_TAIL.to_string()),
            limit: 1,
        };
        if let Err(error) = transport
            .poll_messages(
                &session.mailbox_descriptor,
                &session.mailbox_capability,
                &request,
            )
            .await
        {
            let group_log_id = log_group_id(log_mode, &session.group_id);
            tracing::debug!(
                group_id = %group_log_id,
                %error,
                "Privacy dummy mailbox poll failed"
            );
        }
    }
}

pub(crate) async fn poll_group_mailboxes_once_with_transport<T: MailboxTransport + ?Sized>(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    handshake_request_gate: &Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    transport: &T,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    actor_did: &str,
    agent_name: &str,
    keypair: &AgentKeyPair,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
    agent_data_dir: &Path,
) {
    poll_group_mailboxes_impl(
        registry,
        handshake_request_gate,
        transport,
        audit,
        actor_did,
        agent_name,
        keypair,
        receive_dir_config,
        log_mode,
        agent_data_dir,
        false,
    )
    .await;
}

pub(crate) async fn poll_group_mailboxes_once(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    handshake_request_gate: &Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    transport: &TorMailboxTransport,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    actor_did: &str,
    agent_name: &str,
    keypair: &AgentKeyPair,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
    agent_data_dir: &Path,
) {
    poll_group_mailboxes_once_with_transport(
        registry,
        handshake_request_gate,
        transport,
        audit,
        actor_did,
        agent_name,
        keypair,
        receive_dir_config,
        log_mode,
        agent_data_dir,
    )
    .await;
}

pub(crate) async fn poll_group_mailboxes_for_user_action(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    handshake_request_gate: &Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    transport: &TorMailboxTransport,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    actor_did: &str,
    agent_name: &str,
    keypair: &AgentKeyPair,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
    agent_data_dir: &Path,
) {
    poll_group_mailboxes_impl(
        registry,
        handshake_request_gate,
        transport,
        audit,
        actor_did,
        agent_name,
        keypair,
        receive_dir_config,
        log_mode,
        agent_data_dir,
        true,
    )
    .await;
}

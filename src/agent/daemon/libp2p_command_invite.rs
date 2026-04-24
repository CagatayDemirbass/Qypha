use super::libp2p_command_handlers::{Libp2pCommandHandlerShared, Libp2pCommandHandlerState};
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

fn print_group_plane_pending(action: &str) {
    println!(
        "   {} {} is only available in Ghost mode. This session is using the durable group plane; use /group_normal here or restart in Ghost mode for anonymous groups.",
        "Anonymous group unavailable:".yellow().bold(),
        action
    );
}

fn generate_libp2p_direct_invite_code(
    network: &NetworkNode,
    config_net: &AppConfig,
    keypair_net: &AgentKeyPair,
    ip_hidden: bool,
    our_peer_id: libp2p::PeerId,
) -> Result<String> {
    let tcp_addr_for_invite = if ip_hidden {
        None
    } else if matches!(
        config_net.network.transport_mode,
        TransportMode::Internet | TransportMode::Tcp
    ) {
        let ip = config_net
            .network
            .public_address
            .as_deref()
            .unwrap_or("127.0.0.1");
        if config_net.network.public_address.is_some() {
            Some(format!(
                "/ip4/{}/tcp/{}",
                ip, config_net.network.listen_port
            ))
        } else if let Some(detected) = crate::network::node::detect_local_ip() {
            Some(format!(
                "/ip4/{}/tcp/{}",
                detected, config_net.network.listen_port
            ))
        } else {
            Some(format!(
                "/ip4/127.0.0.1/tcp/{}",
                config_net.network.listen_port
            ))
        }
    } else {
        None
    };
    let invite = PeerInvite::generate(
        keypair_net,
        &our_peer_id.to_string(),
        network.onion_address.as_deref(),
        tcp_addr_for_invite.as_deref(),
        config_net.network.tor.onion_port,
        None,
    )?;
    invite.to_code()
}

#[allow(unused_variables)]
pub(crate) async fn handle_libp2p_invite_command(
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
    let used_invites_net = shared.used_invites_net;
    let used_invites_path_net = shared.used_invites_path_net;
    let used_invites_persist_key_net = shared.used_invites_persist_key_net;
    let group_mailboxes_net = shared.group_mailboxes_net;
    let mailbox_transport_net = shared.mailbox_transport_net;
    let group_invite_bundle_transport_net = shared.group_invite_bundle_transport_net;
    let public_group_invite_bundle_service_net = shared.public_group_invite_bundle_service_net;
    let agent_data_dir = shared.agent_data_dir;
    let direct_peer_dids_net = shared.direct_peer_dids_net;
    let invite_proof_net = shared.invite_proof_net;
    let manual_disconnect_dids_net = shared.manual_disconnect_dids_net;
    let ip_hidden_net = shared.ip_hidden_net;
    let ratchet_mgr_net = shared.ratchet_mgr_net;
    let pending_hybrid_ratchet_inits_net = shared.pending_hybrid_ratchet_inits_net;
    let ratchet_init_pub_hex_net = shared.ratchet_init_pub_hex_net;
    let log_mode_net = shared.log_mode_net;
    let our_peer_id = shared.our_peer_id;
    let no_resume_session_persistence = shared.no_resume_session_persistence;
    let no_persistent_artifact_store = shared.no_persistent_artifact_store;
    let ram_only_chunk_staging = shared.ram_only_chunk_staging;
    match cmd {
        NetworkCommand::GenerateInvite => {
            // For Internet/Tcp mode: include TCP address in invite unless IP is hidden.
            // For Tor mode: TCP address is omitted for privacy.
            let tcp_addr_for_invite = if ip_hidden_net.load(Ordering::Relaxed) {
                None
            } else if matches!(
                config_net.network.transport_mode,
                TransportMode::Internet | TransportMode::Tcp
            ) {
                let ip = config_net
                    .network
                    .public_address
                    .as_deref()
                    .unwrap_or_else(|| "127.0.0.1");
                if config_net.network.public_address.is_some() {
                    Some(format!(
                        "/ip4/{}/tcp/{}",
                        ip, config_net.network.listen_port
                    ))
                } else if let Some(detected) = crate::network::node::detect_local_ip() {
                    Some(format!(
                        "/ip4/{}/tcp/{}",
                        detected, config_net.network.listen_port
                    ))
                } else {
                    Some(format!(
                        "/ip4/127.0.0.1/tcp/{}",
                        config_net.network.listen_port
                    ))
                }
            } else {
                None
            };

            match PeerInvite::generate(
                &keypair_net,
                &our_peer_id.to_string(),
                network.onion_address.as_deref(),
                tcp_addr_for_invite.as_deref(),
                config_net.network.tor.onion_port,
                None,
            ) {
                Ok(invite) => match invite.to_code() {
                    Ok(code) => {
                        emit_headless_invite_success("direct", &code, None);
                        println!("\n   {}", "═══ Invite Code ═══".yellow().bold());
                        println!("   {}", code);
                        println!(
                            "   {}",
                            "Share this code with the peer you want to connect to.".dimmed()
                        );
                        println!("   {} /connect <code>", "They should run:".dimmed());
                        if let Some(ref tcp) = tcp_addr_for_invite {
                            println!("   {} {}", "TCP address:".dimmed(), tcp.cyan());
                        }
                        if ip_hidden_net.load(Ordering::Relaxed) {
                            println!(
                                "   {} IP hidden — peer will need your address separately",
                                "Note:".yellow()
                            );
                        }
                        println!("   {}", "═══════════════════".yellow().bold());

                        {
                            let mut a = audit_net.lock().await;
                            a.record(
                                "INVITE_GENERATED",
                                &config_net.agent.did,
                                &format!(
                                    "onion={} tcp={}",
                                    network.onion_address.as_deref().unwrap_or("none"),
                                    tcp_addr_for_invite.as_deref().unwrap_or("none"),
                                ),
                            );
                        }
                    }
                    Err(e) => {
                        emit_headless_invite_error(
                            "direct",
                            format!("Invite encode failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Invite encode failed:".red(), e);
                    }
                },
                Err(e) => {
                    emit_headless_invite_error(
                        "direct",
                        format!("Invite generation failed: {}", e),
                        None,
                    );
                    println!("   {} {}", "Invite generation failed:".red(), e);
                }
            }
        }

        NetworkCommand::CreateNormalGroup { group_name } => {
            let group_id = format!("grp_{}", uuid::Uuid::new_v4().simple());
            let resolved_mailbox =
                match resolve_mailbox_endpoint(config_net, agent_data_dir, &group_id).await {
                    Ok(resolved) => resolved,
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Mailbox provisioning failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Mailbox provisioning failed:".red().bold(), e);
                        return;
                    }
                };
            let mailbox_endpoint = resolved_mailbox.endpoint.clone();
            let descriptor = match build_mailbox_descriptor(
                &group_id,
                &mailbox_endpoint,
                config_net.network.mailbox.poll_interval_ms,
                config_net.network.mailbox.max_payload_bytes,
            ) {
                Ok(descriptor) => descriptor,
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Mailbox descriptor rejected: {}", e),
                        None,
                    );
                    println!("   {} {}", "Mailbox descriptor rejected:".red(), e);
                    return;
                }
            };
            let persistence = GroupMailboxRegistry::persistence_for_log_mode(log_mode_net.as_str());
            let local_profile = build_local_member_profile(keypair_net, &config_net.agent.name);
            match create_identified_group(
                sign_key,
                &config_net.agent.did,
                Some(group_name.as_str()),
                descriptor,
                persistence.clone(),
                local_profile.clone(),
            ) {
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Group create failed: {}", e),
                        None,
                    );
                    println!("   {} {}", "Group create failed:".red(), e);
                }
                Ok((session, invite)) => match invite.to_code() {
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Group invite encode failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Group invite encode failed:".red(), e);
                    }
                    Ok(code) => {
                        let group_label = describe_group(&session);
                        let group_id = session.group_id.clone();
                        {
                            let mut registry = group_mailboxes_net.lock().await;
                            if let Err(e) = registry.insert_session(session) {
                                emit_headless_invite_error(
                                    "group",
                                    format!("Group persistence failed: {}", e),
                                    None,
                                );
                                println!("   {} {}", "Group persistence failed:".red(), e);
                                return;
                            }
                        }
                        if let Err(e) = announce_local_identified_membership(
                            group_mailboxes_net,
                            mailbox_transport_net,
                            sign_key,
                            &local_profile,
                            &group_id,
                        )
                        .await
                        {
                            let failure = {
                                let mut registry = group_mailboxes_net.lock().await;
                                registry.get_cloned(&group_id).map(|session| {
                                    registry.note_mailbox_transport_failure(
                                        &group_id,
                                        session.mailbox_descriptor.poll_interval_ms,
                                        chrono::Utc::now().timestamp_millis().max(0) as u64,
                                    )
                                })
                            };
                            if let Some(failure) = failure {
                                println!(
                                    "   {} {} (retry in {} ms)",
                                    "Membership notice failed:".yellow().bold(),
                                    e,
                                    failure.next_retry_after_ms
                                );
                            } else {
                                println!(
                                    "   {} {}",
                                    "Membership notice failed:".yellow().bold(),
                                    e
                                );
                            }
                        } else {
                            let mut registry = group_mailboxes_net.lock().await;
                            registry.note_mailbox_transport_success(&group_id);
                        }
                        let group_summary = {
                            let registry = group_mailboxes_net.lock().await;
                            registry
                                .summaries()
                                .into_iter()
                                .find(|candidate| candidate.group_id == group_id)
                        };
                        emit_headless_invite_success("group", &code, group_summary.as_ref());
                        if resolved_mailbox.auto_provisioned {
                            println!(
                                "   {} {}",
                                "Mailbox relay:".yellow().bold(),
                                format!("auto-provisioned Tor relay at {}", mailbox_endpoint)
                                    .dimmed()
                            );
                        } else if resolved_mailbox.selected_from_pool {
                            println!(
                                "   {} {}",
                                "Mailbox relay:".yellow().bold(),
                                format!(
                                    "selected external relay from provider pool: {}",
                                    mailbox_endpoint
                                )
                                .dimmed()
                            );
                        }
                        println!("\n   {}", "═══ Group Invite ═══".yellow().bold());
                        println!("   {} {}", "Group:".dimmed(), group_label.cyan());
                        println!("   {} {}", "Group ID:".dimmed(), group_id.cyan());
                        println!(
                            "   {} {}",
                            "Local member id:".dimmed(),
                            crate::agent::contact_identity::displayed_did(&local_profile.member_id)
                                .dimmed()
                        );
                        println!("   {}", code.white().bold());
                        println!(
                            "   {} mailbox session is identified, Tor-backed, and does not create any peer route.",
                            "Group plane:".yellow().bold()
                        );
                        println!("   {}", "═════════════════════".yellow().bold());
                        let mut a = audit_net.lock().await;
                        a.record(
                            "GROUP_MAILBOX_CREATE",
                            &config_net.agent.did,
                            &format!(
                                "group_id={} anonymous=false transport=tor_mailbox",
                                group_id
                            ),
                        );
                    }
                },
            }
        }
        NetworkCommand::CreateAnonymousGroup { group_name } => {
            if !matches!(log_mode_net, LogMode::Ghost) {
                let label = group_name.unwrap_or_else(|| "<unnamed>".to_string());
                print_group_plane_pending(&format!("/group_anon {}", label.cyan()));
                emit_headless_invite_error(
                    "group",
                    "Anonymous group unavailable: /group_anon is only available in Ghost mode.",
                    None,
                );
                return;
            }
            let group_id = format!("grp_{}", uuid::Uuid::new_v4().simple());
            let resolved_mailbox =
                match resolve_ghost_anonymous_mailbox_endpoint(config_net, &group_id).await {
                    Ok(resolved) => resolved,
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Mailbox provisioning failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Mailbox provisioning failed:".red().bold(), e);
                        return;
                    }
                };
            let mailbox_endpoint = resolved_mailbox.endpoint.clone();
            let descriptor = match build_mailbox_descriptor(
                &group_id,
                &mailbox_endpoint,
                config_net.network.mailbox.poll_interval_ms,
                config_net.network.mailbox.max_payload_bytes,
            ) {
                Ok(descriptor) => descriptor,
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Mailbox descriptor rejected: {}", e),
                        None,
                    );
                    println!("   {} {}", "Mailbox descriptor rejected:".red(), e);
                    return;
                }
            };
            match create_ghost_anonymous_group_with_id_and_bundle(
                &group_id,
                group_name.as_deref(),
                descriptor,
            ) {
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Anonymous group create failed: {}", e),
                        None,
                    );
                    println!("   {} {}", "Anonymous group create failed:".red(), e);
                }
                Ok((session, invite, bundle)) => match invite.to_code() {
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Group invite encode failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Group invite encode failed:".red(), e);
                    }
                    Ok(code) => {
                        let owner_special_id = session
                            .owner_special_id
                            .clone()
                            .unwrap_or_else(|| "<unavailable>".to_string());
                        let group_label = describe_group(&session);
                        let group_id = session.group_id.clone();
                        if let Err(e) = publish_prebuilt_group_mailbox_invite_bundle(
                            config_net,
                            group_invite_bundle_transport_net,
                            public_group_invite_bundle_service_net.as_ref(),
                            &invite,
                            bundle,
                            None,
                        )
                        .await
                        {
                            emit_headless_invite_error(
                                "group",
                                format!("Anonymous group invite publish failed: {}", e),
                                None,
                            );
                            println!(
                                "   {} {}",
                                "Anonymous group invite publish failed:".red(),
                                e
                            );
                            return;
                        }
                        {
                            let mut registry = group_mailboxes_net.lock().await;
                            if let Err(e) = registry.insert_session(session) {
                                emit_headless_invite_error(
                                    "group",
                                    format!("Anonymous group persistence failed: {}", e),
                                    None,
                                );
                                println!(
                                    "   {} {}",
                                    "Anonymous group persistence failed:".red(),
                                    e
                                );
                                return;
                            }
                        }
                        let group_summary = {
                            let registry = group_mailboxes_net.lock().await;
                            registry
                                .summaries()
                                .into_iter()
                                .find(|candidate| candidate.group_id == group_id)
                        };
                        emit_headless_invite_success("group", &code, group_summary.as_ref());
                        if resolved_mailbox.auto_provisioned {
                            println!(
                                "   {} {}",
                                "Mailbox relay:".yellow().bold(),
                                format!(
                                    "ephemeral in-memory Tor relay at {} (no SQLite, no restore, no pre-join backlog)",
                                    mailbox_endpoint
                                )
                                .dimmed()
                            );
                        }
                        println!("\n   {}", "═══ Ghost Group Invite ═══".yellow().bold());
                        println!("   {} {}", "Group:".dimmed(), group_label.cyan());
                        println!("   {} {}", "Group ID:".dimmed(), group_id.cyan());
                        println!(
                            "   {} {}",
                            "Owner handle:".dimmed(),
                            owner_special_id.yellow()
                        );
                        println!("   {}", code.white().bold());
                        println!(
                            "   {} mailbox session is RAM-only, anonymous, and does not create any peer route.",
                            "Ghost:".yellow().bold()
                        );
                        println!("   {}", "══════════════════════════".yellow().bold());
                        let mut a = audit_net.lock().await;
                        a.record(
                            "GROUP_MAILBOX_CREATE",
                            &config_net.agent.did,
                            &format!("group_id={} anonymous=true transport=tor_mailbox", group_id),
                        );
                    }
                },
            }
        }
        NetworkCommand::GenerateGroupInvite { group_id } => {
            let session = {
                let registry = group_mailboxes_net.lock().await;
                registry.get_cloned(&group_id)
            };
            let Some(session) = session else {
                emit_headless_invite_error(
                    "group",
                    format!("Error: no mailbox group matches {}", group_id),
                    None,
                );
                println!(
                    "   {} no mailbox group matches {}",
                    "Error:".red().bold(),
                    group_id.cyan()
                );
                return;
            };
            if session.anonymous_group {
                emit_headless_invite_error(
                    "group",
                    format!(
                        "Error: {} is anonymous. Use /invite_anon for that group.",
                        group_id
                    ),
                    None,
                );
                println!(
                    "   {} {} is anonymous. Use /invite_anon for that group.",
                    "Error:".red().bold(),
                    group_id.cyan()
                );
                return;
            }
            if session.join_locked {
                emit_headless_invite_error(
                    "group",
                    format!(
                        "Error: {} is locked. Use /unlock_g before generating a new invite.",
                        describe_group(&session)
                    ),
                    None,
                );
                println!(
                    "   {} {} is locked. Use /unlock_g before generating a new invite.",
                    "Error:".red().bold(),
                    describe_group(&session).cyan()
                );
                return;
            }
            match regenerate_identified_group_invite(&session, sign_key, &config_net.agent.did) {
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Group invite failed: {}", e),
                        None,
                    );
                    println!("   {} {}", "Group invite failed:".red(), e);
                }
                Ok(invite) => match invite.to_code() {
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Group invite encode failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Group invite encode failed:".red(), e);
                    }
                    Ok(code) => {
                        if let Err(e) = publish_group_mailbox_invite_bundle(
                            config_net,
                            group_invite_bundle_transport_net,
                            public_group_invite_bundle_service_net.as_ref(),
                            sign_key,
                            &invite,
                            &session,
                        )
                        .await
                        {
                            emit_headless_invite_error(
                                "group",
                                format!("Group invite publish failed: {}", e),
                                None,
                            );
                            println!("   {} {}", "Group invite publish failed:".red(), e);
                            return;
                        }
                        let group_summary = {
                            let registry = group_mailboxes_net.lock().await;
                            registry
                                .summaries()
                                .into_iter()
                                .find(|candidate| candidate.group_id == session.group_id)
                        };
                        emit_headless_invite_success("group", &code, group_summary.as_ref());
                        println!("\n   {}", "═══ Group Invite ═══".yellow().bold());
                        println!(
                            "   {} {}",
                            "Group:".dimmed(),
                            describe_group(&session).cyan()
                        );
                        println!("   {} {}", "Group ID:".dimmed(), session.group_id.cyan());
                        println!("   {}", code.white().bold());
                        println!("   {}", "═════════════════════".yellow().bold());
                    }
                },
            }
        }
        NetworkCommand::GenerateAnonymousGroupInvite { group_special_id } => {
            let session = {
                let registry = group_mailboxes_net.lock().await;
                registry.get_by_owner_special_id_cloned(&group_special_id)
            };
            let Some(session) = session else {
                emit_headless_invite_error(
                    "group",
                    format!(
                        "Error: no anonymous mailbox group matches owner handle {}",
                        group_special_id
                    ),
                    None,
                );
                println!(
                    "   {} no anonymous mailbox group matches owner handle {}",
                    "Error:".red().bold(),
                    group_special_id.cyan()
                );
                return;
            };
            match regenerate_anonymous_group_invite_with_bundle(&session) {
                Err(e) => {
                    emit_headless_invite_error(
                        "group",
                        format!("Anonymous group invite failed: {}", e),
                        None,
                    );
                    println!("   {} {}", "Anonymous group invite failed:".red(), e);
                }
                Ok((rotated_session, invite, bundle)) => match invite.to_code() {
                    Err(e) => {
                        emit_headless_invite_error(
                            "group",
                            format!("Anonymous group invite encode failed: {}", e),
                            None,
                        );
                        println!("   {} {}", "Anonymous group invite encode failed:".red(), e)
                    }
                    Ok(code) => {
                        if let Err(e) = publish_prebuilt_group_mailbox_invite_bundle(
                            config_net,
                            group_invite_bundle_transport_net,
                            public_group_invite_bundle_service_net.as_ref(),
                            &invite,
                            bundle,
                            None,
                        )
                        .await
                        {
                            emit_headless_invite_error(
                                "group",
                                format!("Anonymous group invite publish failed: {}", e),
                                None,
                            );
                            println!(
                                "   {} {}",
                                "Anonymous group invite publish failed:".red(),
                                e
                            );
                            return;
                        }
                        {
                            let mut registry = group_mailboxes_net.lock().await;
                            if let Err(error) = registry.insert_session(rotated_session.clone()) {
                                emit_headless_invite_error(
                                    "group",
                                    format!(
                                        "Anonymous group invite refresh failed to store rotation: {}",
                                        error
                                    ),
                                    None,
                                );
                                println!(
                                    "   {} {}",
                                    "Anonymous group invite refresh failed:".red(),
                                    error
                                );
                                return;
                            }
                        }
                        let group_summary = {
                            let registry = group_mailboxes_net.lock().await;
                            registry
                                .summaries()
                                .into_iter()
                                .find(|candidate| candidate.group_id == rotated_session.group_id)
                        };
                        emit_headless_invite_success("group", &code, group_summary.as_ref());
                        println!("\n   {}", "═══ Anonymous Group Invite ═══".yellow().bold());
                        println!(
                            "   {} {}",
                            "Group:".dimmed(),
                            describe_group(&rotated_session).cyan()
                        );
                        println!(
                            "   {} {}",
                            "Group ID:".dimmed(),
                            rotated_session.group_id.cyan()
                        );
                        println!("   {}", code.white().bold());
                        println!("   {}", "══════════════════════════════".yellow().bold());
                    }
                },
            }
        }
        NetworkCommand::SendHandshakeInvite { member_id } => {
            let (session, target_profile) = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_identified_handshake_target(&member_id) {
                    Ok(found) => found,
                    Err(e) => {
                        println!("   {} {}", "Error:".red().bold(), e);
                        return;
                    }
                }
            };
            let sender_profile = {
                let registry = group_mailboxes_net.lock().await;
                registry.known_member_profile(&session.group_id, &config_net.agent.did)
            };
            let Some(sender_profile) = sender_profile else {
                println!(
                    "   {} local identified mailbox profile is missing for {}",
                    "Error:".red().bold(),
                    session.group_id.cyan()
                );
                return;
            };
            let direct_invite_code = match generate_libp2p_direct_invite_code(
                &network,
                config_net,
                keypair_net,
                ip_hidden_net.load(Ordering::Relaxed),
                our_peer_id,
            ) {
                Ok(code) => code,
                Err(e) => {
                    println!("   {} {}", "Direct invite generation failed:".red(), e);
                    return;
                }
            };
            let mailbox_message = match build_direct_handshake_offer_message(
                &session,
                sign_key,
                &sender_profile,
                &target_profile,
                &direct_invite_code,
                60_000,
            ) {
                Ok(message) => message,
                Err(e) => {
                    println!("   {} {}", "Direct handshake offer failed:".red(), e);
                    return;
                }
            };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(_) => {
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
                    }
                    println!(
                        "   {} sent mailbox direct-trust offer to {} via {}",
                        "Handshake offer:".green().bold(),
                        crate::agent::contact_identity::displayed_did(&target_profile.member_id)
                            .dimmed(),
                        describe_group(&session).cyan()
                    );
                    let mut a = audit_net.lock().await;
                    a.record(
                        "GROUP_MAILBOX_DIRECT_OFFER_SEND",
                        &config_net.agent.did,
                        &format!(
                            "group_id={} target_member_id={}",
                            session.group_id, target_profile.member_id
                        ),
                    );
                }
                Err(e) => println!("   {} {}", "Handshake offer failed:".red(), e),
            }
        }
        NetworkCommand::SendHandshakeInviteScoped {
            group_id,
            member_id,
        } => {
            let (session, target_profile) = {
                let registry = group_mailboxes_net.lock().await;
                match registry.resolve_identified_handshake_target_in_group(&group_id, &member_id) {
                    Ok(found) => found,
                    Err(e) => {
                        println!("   {} {}", "Error:".red().bold(), e);
                        return;
                    }
                }
            };
            let sender_profile = {
                let registry = group_mailboxes_net.lock().await;
                registry.known_member_profile(&session.group_id, &config_net.agent.did)
            };
            let Some(sender_profile) = sender_profile else {
                println!(
                    "   {} local identified mailbox profile is missing for {}",
                    "Error:".red().bold(),
                    session.group_id.cyan()
                );
                return;
            };
            let direct_invite_code = match generate_libp2p_direct_invite_code(
                &network,
                config_net,
                keypair_net,
                ip_hidden_net.load(Ordering::Relaxed),
                our_peer_id,
            ) {
                Ok(code) => code,
                Err(e) => {
                    println!("   {} {}", "Direct invite generation failed:".red(), e);
                    return;
                }
            };
            let mailbox_message = match build_direct_handshake_offer_message(
                &session,
                sign_key,
                &sender_profile,
                &target_profile,
                &direct_invite_code,
                60_000,
            ) {
                Ok(message) => message,
                Err(e) => {
                    println!("   {} {}", "Direct handshake offer failed:".red(), e);
                    return;
                }
            };
            match post_group_mailbox_message(mailbox_transport_net, &session, &mailbox_message)
                .await
            {
                Ok(_) => {
                    {
                        let mut registry = group_mailboxes_net.lock().await;
                        registry.mark_local_post(&session.group_id, &mailbox_message.message_id);
                    }
                    println!(
                        "   {} sent mailbox direct-trust offer to {} via {}",
                        "Handshake offer:".green().bold(),
                        crate::agent::contact_identity::displayed_did(&target_profile.member_id)
                            .dimmed(),
                        describe_group(&session).cyan()
                    );
                    let mut a = audit_net.lock().await;
                    a.record(
                        "GROUP_MAILBOX_DIRECT_OFFER_SEND",
                        &config_net.agent.did,
                        &format!(
                            "group_id={} target_member_id={}",
                            session.group_id, target_profile.member_id
                        ),
                    );
                }
                Err(e) => println!("   {} {}", "Handshake offer failed:".red(), e),
            }
        }

        // ── /connect: connect via invite code ────────────────
        NetworkCommand::ConnectInvite { code } => {
            match DecodedInvite::from_code(&code) {
                Err(e) => {
                    println!("   {} {}", "Invalid invite code:".red(), e);
                }
                Ok(DecodedInvite::GroupMailbox(invite)) => match invite.verify_with_expiry() {
                    Err(e) => println!("   {} {}", "Group invite rejected:".red(), e),
                    Ok(false) => {
                        println!("   {}", "Group invite signature invalid.".red());
                    }
                    Ok(true) => {
                        if let Err(e) =
                            mailbox_join_allowed_for_mode(log_mode_net.as_str(), &invite)
                        {
                            println!("   {} {}", "SECURITY REJECT:".red().bold(), e);
                            return;
                        }
                        let invite = match resolve_group_mailbox_invite(
                            config_net,
                            group_invite_bundle_transport_net,
                            &invite,
                        )
                        .await
                        {
                            Ok(invite) => invite,
                            Err(e) => {
                                println!("   {} {}", "Group invite rejected:".red(), e);
                                return;
                            }
                        };
                        let invite = match preflight_group_mailbox_join(
                            &invite,
                            mailbox_transport_net,
                        )
                        .await
                        {
                            Ok(invite) => invite,
                            Err(e) => {
                                println!("   {} {}", "Group invite rejected:".red(), e);
                                return;
                            }
                        };
                        let persistence =
                            GroupMailboxRegistry::persistence_for_log_mode(log_mode_net.as_str());
                        let local_member_id = if invite.anonymous_group {
                            None
                        } else {
                            Some(config_net.agent.did.clone())
                        };
                        {
                            let mut registry = group_mailboxes_net.lock().await;
                            if let Err(e) = registry.join_from_invite(
                                &invite,
                                persistence.clone(),
                                local_member_id,
                            ) {
                                println!("   {} {}", "Group persistence failed:".red(), e);
                                return;
                            }
                        }
                        if !invite.anonymous_group {
                            let local_profile =
                                build_local_member_profile(keypair_net, &config_net.agent.name);
                            if let Err(e) = announce_local_identified_membership(
                                group_mailboxes_net,
                                mailbox_transport_net,
                                sign_key,
                                &local_profile,
                                &invite.group_id,
                            )
                            .await
                            {
                                let failure = {
                                    let mut registry = group_mailboxes_net.lock().await;
                                    registry.get_cloned(&invite.group_id).map(|session| {
                                        registry.note_mailbox_transport_failure(
                                            &invite.group_id,
                                            session.mailbox_descriptor.poll_interval_ms,
                                            chrono::Utc::now().timestamp_millis().max(0) as u64,
                                        )
                                    })
                                };
                                if let Some(failure) = failure {
                                    println!(
                                        "   {} {} (retry in {} ms)",
                                        "Membership notice failed:".yellow().bold(),
                                        e,
                                        failure.next_retry_after_ms
                                    );
                                } else {
                                    println!(
                                        "   {} {}",
                                        "Membership notice failed:".yellow().bold(),
                                        e
                                    );
                                }
                            } else {
                                let mut registry = group_mailboxes_net.lock().await;
                                registry.note_mailbox_transport_success(&invite.group_id);
                            }
                        }
                        println!(
                            "   {} {} ({})",
                            "Group invite joined:".green().bold(),
                            invite
                                .group_name
                                .as_deref()
                                .unwrap_or("Unnamed Group")
                                .cyan(),
                            invite.group_id.dimmed()
                        );
                        println!(
                                "   {} mailbox-backed group session registered with {} persistence. No peer dial was attempted.",
                                "Mailbox:".yellow().bold(),
                                match persistence {
                                    GroupMailboxPersistence::MemoryOnly => "memory-only",
                                    GroupMailboxPersistence::EncryptedDisk => "encrypted-disk",
                                }
                            );
                        let mut a = audit_net.lock().await;
                        a.record(
                            "GROUP_MAILBOX_JOIN",
                            &config_net.agent.did,
                            &format!(
                                "group_id={} anonymous={}",
                                invite.group_id, invite.anonymous_group
                            ),
                        );
                    }
                },
                Ok(DecodedInvite::Peer(invite)) => {
                    if direct_invite_already_used(used_invites_net, &code).await {
                        println!(
                            "   {} this invite was already consumed (one-time use). Request a new /invite.",
                            "SECURITY REJECT:".red().bold()
                        );
                        return;
                    }
                    match invite.verify_with_expiry(None) {
                        Err(e) => {
                            println!("   {} {}", "SECURITY: Invite rejected:".red().bold(), e);
                        }
                        Ok(false) => {
                            println!(
                                "   {}",
                                "SECURITY: Invite signature INVALID! Rejecting."
                                    .red()
                                    .bold()
                            );
                        }
                        Ok(true) => {
                            let invite_did = match invite.canonical_did() {
                                Ok(did) => did,
                                Err(e) => {
                                    println!(
                                        "   {} invalid invite identity: {}",
                                        "SECURITY REJECT:".red().bold(),
                                        e
                                    );
                                    return;
                                }
                            };
                            {
                                let mut manual = manual_disconnect_dids_net.lock().await;
                                manual.remove(&invite_did);
                            }
                            let contact_did = invite.shareable_did();
                            println!(
                                "   {} {}",
                                "Invite verified:".green().bold(),
                                contact_did.cyan(),
                            );
                            let tor_only_mode =
                                matches!(config_net.network.transport_mode, TransportMode::Tor);
                            let invite_peer_id = match invite.peer_id.parse::<libp2p::PeerId>() {
                                Ok(pid) => pid,
                                Err(e) => {
                                    println!(
                                        "   {} invite peer_id invalid: {}",
                                        "SECURITY REJECT:".red().bold(),
                                        e
                                    );
                                    return;
                                }
                            };
                            let mut invite_connected = false;

                            // Connect based on available address
                            if let Some(ref onion) = invite.onion_address {
                                if let Some(ref tor_mgr) = network.tor_manager {
                                    println!(
                                        "   {} {}.onion via Tor...",
                                        "Connecting to".yellow(),
                                        onion_prefix(onion, 16)
                                    );

                                    // Create a circuit-isolated TCP bridge to the .onion address
                                    // Per-peer isolation prevents cross-peer correlation attacks.
                                    // Retry to tolerate fresh-onion publication lag right after startup.
                                    const MAX_TOR_CONNECT_ATTEMPTS: usize = 3;
                                    let mut bridge_result = None;
                                    for attempt in 1..=MAX_TOR_CONNECT_ATTEMPTS {
                                        match tor_bridge::create_tor_bridge_isolated(
                                            tor_mgr,
                                            onion,
                                            invite.onion_port,
                                            Some(&invite_did),
                                        )
                                        .await
                                        {
                                            Ok(port) => {
                                                bridge_result = Some(Ok(port));
                                                break;
                                            }
                                            Err(e) => {
                                                if attempt < MAX_TOR_CONNECT_ATTEMPTS {
                                                    println!(
                                                                        "   {} Tor bridge attempt {}/{} failed: {}. Retrying...",
                                                                        "Warn:".yellow(),
                                                                        attempt,
                                                                        MAX_TOR_CONNECT_ATTEMPTS,
                                                                        e
                                                                    );
                                                    tokio::time::sleep(
                                                        tokio::time::Duration::from_secs(
                                                            2 * attempt as u64,
                                                        ),
                                                    )
                                                    .await;
                                                } else {
                                                    bridge_result = Some(Err(e));
                                                }
                                            }
                                        }
                                    }

                                    match bridge_result.unwrap_or_else(|| {
                                        Err(anyhow::anyhow!("unknown Tor bridge error"))
                                    }) {
                                        Ok(bridge_port) => {
                                            let addr: libp2p::Multiaddr =
                                                format!("/ip4/127.0.0.1/tcp/{}", bridge_port)
                                                    .parse()
                                                    .expect("valid multiaddr");
                                            match network.swarm.dial(addr) {
                                                Ok(()) => {
                                                    println!(
                                                        "   {} bridge established, handshaking...",
                                                        "OK".green()
                                                    );
                                                    invite_connected = true;

                                                    // Pre-register the peer
                                                    let pid = invite_peer_id.clone();
                                                    peers_net.insert(
                                                        pid.to_string(),
                                                        PeerInfo {
                                                            peer_id: pid,
                                                            did: invite_did.clone(),
                                                            name: contact_did.clone(),
                                                            role: DEFAULT_AGENT_ROLE.to_string(),
                                                            onion_address: invite
                                                                .onion_address
                                                                .clone(),
                                                            tcp_address: if tor_only_mode {
                                                                None
                                                            } else {
                                                                invite.tcp_address.clone()
                                                            },
                                                            iroh_endpoint_addr: invite
                                                                .iroh_endpoint_addr
                                                                .clone(),
                                                            onion_port: invite.onion_port,
                                                            x25519_public_key: None,
                                                            kyber_public_key: None,
                                                            verifying_key: Some(
                                                                invite.verifying_key,
                                                            ),
                                                            aegis_supported: false,
                                                            ratchet_dh_public: None,
                                                        },
                                                    );
                                                }
                                                Err(e) => {
                                                    println!(
                                                        "   {} {}",
                                                        "Dial through bridge failed:".red(),
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!("   {} {}", "Tor bridge failed:".red(), e);
                                        }
                                    }
                                } else {
                                    println!(
                                        "   {} Tor not active. Start with --transport tor",
                                        "Error:".red()
                                    );
                                    return;
                                }
                            } else if tor_only_mode {
                                println!(
                                                    "   {} Tor mode refuses non-onion invite targets (no TCP fallback)",
                                                    "SECURITY:".red().bold()
                                                );
                                return;
                            } else if let Some(ref tcp) = invite.tcp_address {
                                match tcp.parse::<libp2p::Multiaddr>() {
                                    Ok(addr) => {
                                        println!(
                                            "   {} {} via TCP...",
                                            "Connecting to".yellow(),
                                            tcp
                                        );
                                        if let Err(e) = network.swarm.dial(addr) {
                                            println!("   {} {}", "Dial failed:".red(), e);
                                        } else {
                                            invite_connected = true;
                                            let pid = invite_peer_id.clone();
                                            peers_net.insert(
                                                pid.to_string(),
                                                PeerInfo {
                                                    peer_id: pid,
                                                    did: invite_did.clone(),
                                                    name: contact_did.clone(),
                                                    role: DEFAULT_AGENT_ROLE.to_string(),
                                                    onion_address: invite.onion_address.clone(),
                                                    tcp_address: invite.tcp_address.clone(),
                                                    iroh_endpoint_addr: invite
                                                        .iroh_endpoint_addr
                                                        .clone(),
                                                    onion_port: invite.onion_port,
                                                    x25519_public_key: None,
                                                    kyber_public_key: None,
                                                    verifying_key: Some(invite.verifying_key),
                                                    aegis_supported: false,
                                                    ratchet_dh_public: None,
                                                },
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        println!("   {} {}", "Invalid TCP address:".red(), e);
                                    }
                                }
                            } else {
                                println!(
                                    "   {} Invite has no .onion or TCP address.",
                                    "Error:".red()
                                );
                            }

                            if invite_connected {
                                invite_proof_net.insert(invite_peer_id.to_string(), code.clone());
                                // Force the next live session handshake to be invite-bound, but
                                // avoid a duplicate send later if the connection event already
                                // emitted the handshake using this freshly staged proof.
                                handshake_sent.remove(&invite_peer_id);
                            }

                            {
                                let mut a = audit_net.lock().await;
                                a.record(
                                    "INVITE_CONNECT",
                                    &config_net.agent.did,
                                    &format!(
                                        "peer={} onion={}",
                                        invite_did,
                                        invite.onion_address.as_deref().unwrap_or("none")
                                    ),
                                );
                            }
                            if invite_connected {
                                direct_peer_dids_net.insert(invite_did.clone(), true);
                                println!(
                                    "   {} {}",
                                    "Direct member linked:".dimmed(),
                                    contact_did.cyan()
                                );
                                if network.swarm.is_connected(&invite_peer_id)
                                    && !handshake_sent.contains(&invite_peer_id)
                                {
                                    let consumed_binding = invite_proof_net
                                        .remove(&invite_peer_id.to_string())
                                        .map(|(_, v)| v);
                                    let (invite_code, invite_bound_override) =
                                        stored_invite_binding_parts(consumed_binding.clone());
                                    let handshake_sent_now = send_handshake(
                                        &mut network,
                                        peers_net,
                                        pending_hybrid_ratchet_inits_net,
                                        &config_net,
                                        &keypair_net,
                                        &invite_peer_id,
                                        Some(&invite_did),
                                        &ratchet_init_pub_hex_net,
                                        invite_code,
                                        invite_bound_override,
                                        false,
                                    );
                                    advance_libp2p_invite_binding_after_handshake_send(
                                        invite_proof_net,
                                        &invite_peer_id,
                                        consumed_binding,
                                        handshake_sent_now,
                                    );
                                    if handshake_sent_now {
                                        handshake_sent.insert(invite_peer_id);
                                    }
                                }
                                persist_direct_invite_use(
                                    used_invites_net,
                                    used_invites_path_net.as_ref(),
                                    used_invites_persist_key_net.as_ref(),
                                    &code,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }

        // ── /onion: show .onion address ──────────────────────
        _ => unreachable!("unexpected command routed to handle_libp2p_invite_command"),
    }
}

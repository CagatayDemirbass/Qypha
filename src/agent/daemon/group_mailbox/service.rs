use super::*;

pub(crate) fn embedded_mailbox_services(
) -> &'static tokio::sync::Mutex<HashMap<PathBuf, EmbeddedMailboxServiceState>> {
    static SERVICES: OnceLock<tokio::sync::Mutex<HashMap<PathBuf, EmbeddedMailboxServiceState>>> =
        OnceLock::new();
    SERVICES.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

#[cfg(unix)]
fn with_mailbox_shutdown_stderr_suppressed<T>(f: impl FnOnce() -> T) -> T {
    use std::os::unix::io::AsRawFd;

    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null");
    let Ok(devnull) = devnull else {
        return f();
    };

    let saved_stderr = unsafe { libc::dup(2) };
    if saved_stderr < 0 {
        return f();
    }

    unsafe {
        libc::dup2(devnull.as_raw_fd(), 2);
    }
    let result = f();
    // Arti can emit the circuit-manager flush warning slightly after shutdown.
    std::thread::sleep(std::time::Duration::from_millis(150));
    unsafe {
        libc::dup2(saved_stderr, 2);
        libc::close(saved_stderr);
    }
    result
}

#[cfg(not(unix))]
fn with_mailbox_shutdown_stderr_suppressed<T>(f: impl FnOnce() -> T) -> T {
    f()
}

pub(crate) fn auto_mailbox_service_root(agent_data_dir: &Path, group_id: &str) -> PathBuf {
    agent_data_dir.join("mailbox_services").join(group_id)
}

pub(crate) fn ghost_ephemeral_mailbox_service_key(group_id: &str) -> PathBuf {
    runtime_temp_path("qypha-ghost-mailbox-services").join(group_id)
}

pub(crate) fn ghost_ephemeral_mailbox_root() -> PathBuf {
    runtime_temp_path("qypha-ghost-mailbox")
}

pub(crate) fn auto_mailbox_service_port_path(service_root: &Path) -> PathBuf {
    service_root.join("listen_port")
}

pub(crate) fn embedded_mailbox_service_exists(agent_data_dir: &Path, group_id: &str) -> bool {
    auto_mailbox_service_port_path(&auto_mailbox_service_root(agent_data_dir, group_id)).exists()
}

pub(crate) fn embedded_mailbox_service_endpoint(service_root: &Path) -> Option<String> {
    let hostname = std::fs::read_to_string(service_root.join("tor").join("hostname")).ok()?;
    let hostname = hostname.trim().trim_end_matches(".onion");
    let port = std::fs::read_to_string(auto_mailbox_service_port_path(service_root)).ok()?;
    let port = port.trim().parse::<u16>().ok()?;
    Some(format!("tor://{hostname}:{port}"))
}

pub(crate) fn local_embedded_mailbox_service_group_id_for_endpoint(
    agent_data_dir: &Path,
    endpoint: &str,
) -> Option<String> {
    let root = agent_data_dir.join("mailbox_services");
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        if embedded_mailbox_service_endpoint(&path).as_deref() == Some(endpoint) {
            return Some(entry.file_name().to_string_lossy().to_string());
        }
    }
    None
}

pub(crate) fn local_embedded_mailbox_group_ids_to_restore(
    agent_data_dir: &Path,
    sessions: &[GroupMailboxSession],
) -> Vec<String> {
    let mut group_ids = sessions
        .iter()
        .filter_map(|session| {
            if embedded_mailbox_service_exists(agent_data_dir, &session.group_id) {
                return Some(session.group_id.clone());
            }
            session
                .mailbox_descriptor
                .endpoint
                .as_deref()
                .and_then(|endpoint| {
                    local_embedded_mailbox_service_group_id_for_endpoint(agent_data_dir, endpoint)
                })
        })
        .collect::<Vec<_>>();
    group_ids.sort();
    group_ids.dedup();
    group_ids
}

pub(crate) fn load_or_create_auto_mailbox_service_port(service_root: &Path) -> Result<u16> {
    std::fs::create_dir_all(service_root)?;
    let port_path = auto_mailbox_service_port_path(service_root);
    if port_path.exists() {
        let encoded = std::fs::read_to_string(&port_path)
            .with_context(|| format!("Failed to read {}", port_path.display()))?;
        let port = encoded
            .trim()
            .parse::<u16>()
            .with_context(|| format!("Invalid mailbox listen port in {}", port_path.display()))?;
        if port == 0 {
            bail!(
                "Mailbox listen port in {} must be non-zero",
                port_path.display()
            );
        }
        return Ok(port);
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .context("Failed to reserve a local port for embedded mailbox relay")?;
    let port = listener
        .local_addr()
        .context("Failed to inspect reserved mailbox relay port")?
        .port();
    drop(listener);

    std::fs::write(&port_path, format!("{port}\n"))
        .with_context(|| format!("Failed to persist {}", port_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&port_path, std::fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(port)
}

pub(crate) async fn ensure_embedded_mailbox_service(
    config: &AppConfig,
    agent_data_dir: &Path,
    group_id: &str,
) -> Result<String> {
    let service_root = auto_mailbox_service_root(agent_data_dir, group_id);
    let mut services = embedded_mailbox_services().lock().await;
    if let Some(existing) = services.get(&service_root) {
        if !existing.handle.is_finished() {
            return Ok(existing.endpoint.clone());
        }
    }
    services.remove(&service_root);
    drop(services);

    let listen_port = load_or_create_auto_mailbox_service_port(&service_root)?;
    let relay_data_dir = service_root.join("relay");
    let tor_data_dir = service_root.join("tor");
    let handle = start_mailbox_service_background(
        &relay_data_dir,
        listen_port,
        Some(&tor_data_dir),
        config.network.tor.circuit_timeout_secs,
        config.network.mailbox.max_payload_bytes,
        crate::network::mailbox_service::MailboxRelayPolicy::default(),
    )
    .await
    .with_context(|| {
        format!(
            "Failed to auto-provision embedded Tor mailbox relay for agent {} group {}",
            config.agent.name, group_id
        )
    })?;
    let endpoint = handle.endpoint().to_string();

    let mut services = embedded_mailbox_services().lock().await;
    services.insert(
        service_root,
        EmbeddedMailboxServiceState {
            endpoint: endpoint.clone(),
            handle,
            ephemeral_root: None,
        },
    );
    Ok(endpoint)
}

pub(crate) async fn restore_local_embedded_mailbox_service(
    config: &AppConfig,
    agent_data_dir: &Path,
    group_id: &str,
) -> Result<String> {
    ensure_embedded_mailbox_service(config, agent_data_dir, group_id).await
}

pub(crate) async fn shutdown_group_mailbox_service(
    agent_data_dir: &Path,
    session: &GroupMailboxSession,
) -> Result<bool> {
    let mut services = embedded_mailbox_services().lock().await;
    if session.anonymous_group && matches!(session.persistence, GroupMailboxPersistence::MemoryOnly)
    {
        let service_key = ghost_ephemeral_mailbox_service_key(&session.group_id);
        if let Some(service) = services.remove(&service_key) {
            with_mailbox_shutdown_stderr_suppressed(|| {
                service.handle.shutdown();
            });
            return Ok(true);
        }
        return Ok(false);
    }

    let primary_root = auto_mailbox_service_root(agent_data_dir, &session.group_id);
    let service_key = if services.contains_key(&primary_root) {
        Some(primary_root.clone())
    } else {
        session
            .mailbox_descriptor
            .endpoint
            .as_deref()
            .and_then(|endpoint| {
                services.iter().find_map(|(path, service)| {
                    (service.endpoint == endpoint).then(|| path.clone())
                })
            })
    };

    let Some(service_key) = service_key else {
        return Ok(false);
    };
    let service = services.remove(&service_key);
    drop(services);
    let should_wipe = service_key.starts_with(agent_data_dir.join("mailbox_services"));

    with_mailbox_shutdown_stderr_suppressed(|| {
        if let Some(service) = service {
            service.handle.shutdown();
        }

        if should_wipe {
            secure_wipe_dir(&service_key);
        }
    });
    Ok(true)
}

pub(crate) fn schedule_group_mailbox_service_shutdown(
    agent_data_dir: PathBuf,
    session: GroupMailboxSession,
    delay_ms: u64,
) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        if let Err(error) = shutdown_group_mailbox_service(&agent_data_dir, &session).await {
            tracing::warn!(
                group_id = %session.group_id,
                %error,
                "Deferred mailbox service shutdown failed"
            );
        }
    });
}

pub(crate) fn schedule_group_disband_mailbox_shutdown(
    agent_data_dir: PathBuf,
    session: GroupMailboxSession,
) {
    schedule_group_mailbox_service_shutdown(
        agent_data_dir,
        session,
        GROUP_DISBAND_RELAY_GRACE_PERIOD_MS,
    );
}

pub(crate) async fn probe_group_mailbox_health(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &TorMailboxTransport,
    group_id: &str,
    attempts: usize,
) -> std::result::Result<(), (anyhow::Error, MailboxTransportFailureOutcome)> {
    let session = {
        let registry = registry.lock().await;
        registry
            .get_cloned(group_id)
            .ok_or_else(|| anyhow::anyhow!("Mailbox group {} not found", group_id))
            .map_err(|error| {
                (
                    error,
                    MailboxTransportFailureOutcome {
                        failures: 0,
                        next_retry_after_ms: 0,
                        should_log: true,
                        degraded: false,
                    },
                )
            })?
    };
    let attempts = attempts.max(1);
    let request = MailboxPollRequest {
        cursor: Some(MAILBOX_CURSOR_TAIL.to_string()),
        limit: 1,
    };
    let mut last_error = None;
    for attempt in 0..attempts {
        match transport
            .poll_messages(
                &session.mailbox_descriptor,
                &session.mailbox_capability,
                &request,
            )
            .await
        {
            Ok(_) => {
                let mut registry = registry.lock().await;
                registry.note_mailbox_transport_success(group_id);
                return Ok(());
            }
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
                }
            }
        }
    }

    let failure = {
        let mut registry = registry.lock().await;
        registry.note_mailbox_transport_failure(
            group_id,
            session.mailbox_descriptor.poll_interval_ms,
            current_unix_ts_ms(),
        )
    };
    Err((
        last_error.unwrap_or_else(|| anyhow::anyhow!("Mailbox health probe failed")),
        failure,
    ))
}

pub(crate) fn ghost_anonymous_mailbox_retention_ms(config: &AppConfig) -> u64 {
    config
        .network
        .mailbox
        .poll_interval_ms
        .max(1)
        .saturating_mul(3)
        .clamp(
            GHOST_ANON_EPHEMERAL_MIN_RETENTION_MS,
            GHOST_ANON_EPHEMERAL_MAX_RETENTION_MS,
        )
}

pub(crate) async fn ensure_ghost_anonymous_mailbox_service(
    config: &AppConfig,
    group_id: &str,
) -> Result<String> {
    let service_key = ghost_ephemeral_mailbox_service_key(group_id);
    let mut services = embedded_mailbox_services().lock().await;
    if let Some(existing) = services.get(&service_key) {
        if !existing.handle.is_finished() {
            return Ok(existing.endpoint.clone());
        }
    }
    services.remove(&service_key);
    drop(services);

    let mailbox_root = ghost_ephemeral_mailbox_root();
    std::fs::create_dir_all(&mailbox_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&mailbox_root, std::fs::Permissions::from_mode(0o700)).ok();
    }
    let root_guard = tempfile::Builder::new()
        .prefix(&format!("{}-", group_id))
        .tempdir_in(&mailbox_root)
        .context("Failed to allocate ephemeral ghost mailbox root")?;
    let tor_data_dir = root_guard.path().join("tor");
    let handle = start_memory_mailbox_service_background(
        0,
        &tor_data_dir,
        config.network.tor.circuit_timeout_secs,
        config.network.mailbox.max_payload_bytes,
        ghost_anonymous_mailbox_retention_ms(config),
        crate::network::mailbox_service::MailboxRelayPolicy::default(),
    )
    .await
    .with_context(|| {
        format!(
            "Failed to provision ephemeral ghost mailbox relay for agent {} group {}",
            config.agent.name, group_id
        )
    })?;
    let endpoint = handle.endpoint().to_string();

    let mut services = embedded_mailbox_services().lock().await;
    services.insert(
        service_key,
        EmbeddedMailboxServiceState {
            endpoint: endpoint.clone(),
            handle,
            ephemeral_root: Some(root_guard),
        },
    );
    Ok(endpoint)
}

pub(crate) async fn preflight_group_mailbox_join(
    invite: &crate::network::group_invite_bundle::ResolvedGroupMailboxInvite,
    transport: &TorMailboxTransport,
) -> Result<crate::network::group_invite_bundle::ResolvedGroupMailboxInvite> {
    if invite.join_locked {
        bail!(
            "Mailbox group {} is locked. Ask the owner to unlock the group and send a fresh invite.",
            invite.group_id
        );
    }
    if invite.anonymous_group {
        return Ok(invite.clone());
    }

    let invite_epoch = mailbox_namespace_epoch(&invite.mailbox_descriptor.namespace)?;
    let mut resolved_invite = invite.clone();
    let mut resolved_epoch = invite_epoch;
    let context = GroupMailboxCryptoContext {
        group_id: invite.group_id.clone(),
        anonymous_group: invite.anonymous_group,
        mailbox_capability: invite.mailbox_capability.clone(),
        content_crypto_state: invite.content_crypto_state.clone(),
        anonymous_writer_state: invite.anonymous_writer_state.clone(),
    };
    let mut cursor = None;
    let mut scanned = 0usize;

    loop {
        let result = transport
            .poll_messages(
                &invite.mailbox_descriptor,
                &invite.mailbox_capability,
                &MailboxPollRequest {
                    cursor: cursor.clone(),
                    limit: GROUP_MAILBOX_JOIN_PREFLIGHT_POLL_LIMIT,
                },
            )
            .await?;

        if result.items.is_empty() {
            break;
        }

        let next_cursor = result.next_cursor.clone();
        for item in result.items {
            scanned = scanned.saturating_add(1);
            if scanned > GROUP_MAILBOX_JOIN_PREFLIGHT_MAX_ITEMS {
                return Ok(resolved_invite);
            }
            if item.message.group_id != invite.group_id || item.message.anonymous_group {
                continue;
            }
            let decoded = match decode_group_mailbox_message_with_context(&context, &item.message) {
                Ok(decoded) => decoded,
                Err(_) => continue,
            };
            match &item.message.kind {
                GroupMailboxMessageKind::MailboxRotation => {
                    let rotation: MailboxRotationPayload =
                        match serde_json::from_slice(&decoded.payload) {
                            Ok(rotation) => rotation,
                            Err(_) => continue,
                        };
                    if verify_mailbox_rotation_visibility(
                        &rotation,
                        item.message.sender_member_id.as_deref(),
                        &invite.group_id,
                        &invite.issuer_verifying_key_hex,
                    )
                    .is_err()
                    {
                        continue;
                    }
                    if rotation.new_mailbox_epoch > resolved_epoch {
                        resolved_epoch = rotation.new_mailbox_epoch;
                        if rotation.target_member_id.is_empty() {
                            resolved_invite.join_locked = rotation.join_locked;
                            if !rotation.join_locked {
                                if let (Some(descriptor), Some(capability)) = (
                                    rotation.public_mailbox_descriptor.clone(),
                                    rotation.public_mailbox_capability.clone(),
                                ) {
                                    resolved_invite.mailbox_descriptor = descriptor;
                                    resolved_invite.mailbox_capability = capability;
                                }
                                resolved_invite.content_crypto_state =
                                    rotation.public_content_crypto_state.clone();
                            }
                        } else {
                            resolved_invite.join_locked = rotation.join_locked;
                        }
                    }
                }
                GroupMailboxMessageKind::GroupDisband => {
                    let disband: GroupDisbandPayload =
                        match serde_json::from_slice(&decoded.payload) {
                            Ok(disband) => disband,
                            Err(_) => continue,
                        };
                    if verify_group_disband_payload(
                        &disband,
                        item.message.sender_member_id.as_deref(),
                        &invite.group_id,
                        invite.issuer_did.as_deref(),
                    )
                    .is_err()
                        || disband.owner_verifying_key_hex != invite.issuer_verifying_key_hex
                    {
                        continue;
                    }
                    if disband.mailbox_epoch >= invite_epoch {
                        bail!(
                            "Mailbox group {} was disbanded at epoch {}. Ask the owner to create a fresh group invite.",
                            invite.group_id,
                            disband.mailbox_epoch
                        );
                    }
                }
                _ => {}
            }
        }

        if next_cursor.is_none() || next_cursor == cursor {
            break;
        }
        cursor = next_cursor;
    }

    if resolved_epoch > invite_epoch {
        if resolved_invite.join_locked {
            bail!(
                "Mailbox group {} is locked at epoch {}. Ask the owner to unlock the group and send a fresh invite.",
                invite.group_id,
                resolved_epoch
            );
        }
        if resolved_invite.mailbox_descriptor != invite.mailbox_descriptor
            || resolved_invite.mailbox_capability != invite.mailbox_capability
        {
            return Ok(resolved_invite);
        }
        bail!(
            "Mailbox invite for {} is stale (invite epoch {} < current epoch {}). Ask the owner for a fresh invite.",
            invite.group_id,
            invite_epoch,
            resolved_epoch
        );
    }

    Ok(resolved_invite)
}

async fn resolve_group_invite_bundle_via_tor(
    config: &AppConfig,
    transport: &Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    invite: &GroupMailboxInvite,
) -> Result<Option<crate::network::group_invite_bundle::GroupInviteBundle>> {
    let issuer_contact_did = invite.issuer_contact_did();
    let canonical_did =
        crate::network::contact_did::decode_contact_did(&issuer_contact_did)?.canonical_did;
    let Some(endpoint) = crate::network::discovery::tor::resolve_public_bundle_endpoint_from_config(
        config,
        &canonical_did,
    ) else {
        return Ok(None);
    };
    let request = crate::network::group_invite_bundle::GroupInviteBundleGetRequest::new(
        issuer_contact_did,
        invite.invite_id.clone(),
    );
    let response = transport.get_from_endpoint(&endpoint, &request).await?;
    response.into_verified_bundle()
}

pub(crate) async fn resolve_group_mailbox_invite(
    config: &AppConfig,
    transport: &Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    invite: &GroupMailboxInvite,
) -> Result<crate::network::group_invite_bundle::ResolvedGroupMailboxInvite> {
    if !invite.verify_with_expiry()? {
        bail!("Group invite signature invalid");
    }
    let issuer_contact_did = invite.issuer_contact_did();
    let bundle = if let Some(bundle) =
        crate::network::group_invite_bundle_iroh::lookup_group_invite_bundle_via_iroh(
            &config.network.iroh,
            &issuer_contact_did,
            &invite.invite_id,
        )
        .await?
    {
        bundle
    } else if let Some(bundle) =
        resolve_group_invite_bundle_via_tor(config, transport, invite).await?
    {
        bundle
    } else {
        bail!(
            "No verified group invite bundle was found for {}. The owner may be offline or not publishing invite discovery yet.",
            invite.group_id
        );
    };
    bundle.resolve_against_token(invite)
}

pub(crate) async fn publish_group_mailbox_invite_bundle(
    config: &AppConfig,
    transport: &Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    public_iroh_service: Option<
        &Arc<crate::network::group_invite_bundle_iroh::IrohGroupInviteBundleService>,
    >,
    signing_key: &ed25519_dalek::SigningKey,
    invite: &GroupMailboxInvite,
    session: &GroupMailboxSession,
) -> Result<()> {
    let bundle = build_group_invite_bundle_from_session(signing_key, invite, session)?;
    publish_prebuilt_group_mailbox_invite_bundle(
        config,
        transport,
        public_iroh_service,
        invite,
        bundle,
        Some(signing_key.verifying_key().to_bytes()),
    )
    .await
}

pub(crate) async fn publish_prebuilt_group_mailbox_invite_bundle(
    config: &AppConfig,
    transport: &Arc<crate::network::group_invite_bundle_transport::GroupInviteBundleTransport>,
    public_iroh_service: Option<
        &Arc<crate::network::group_invite_bundle_iroh::IrohGroupInviteBundleService>,
    >,
    invite: &GroupMailboxInvite,
    bundle: crate::network::group_invite_bundle::GroupInviteBundle,
    local_service_verifying_key: Option<[u8; 32]>,
) -> Result<()> {
    let issuer_contact_did = bundle.issuer_contact_did();
    let mut published = false;

    if let Some(service) = public_iroh_service {
        if local_service_verifying_key
            .as_ref()
            .is_some_and(|bytes| invite.issuer_verifying_key == *bytes)
        {
            service.publish(bundle.clone()).await;
            published = true;
        }
    }

    let canonical_did =
        crate::network::contact_did::decode_contact_did(&issuer_contact_did)?.canonical_did;
    if let Some(endpoint) =
        crate::network::discovery::tor::resolve_public_bundle_endpoint_from_config(
            config,
            &canonical_did,
        )
    {
        let request = crate::network::group_invite_bundle::GroupInviteBundlePutRequest::new(
            issuer_contact_did,
            bundle,
        );
        transport.put_to_endpoint(&endpoint, &request).await?;
        published = true;
    }

    if !published {
        bail!(
            "No public group invite discovery channel is available. Enable iroh relay discovery or configure network.mailbox.pool_endpoints."
        );
    }
    Ok(())
}

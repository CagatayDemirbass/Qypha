use super::*;
use rand::seq::SliceRandom;

pub(crate) fn build_mailbox_capability() -> MailboxCapability {
    let access_key = rand::random::<[u8; 32]>();
    let auth_token = rand::random::<[u8; 32]>();
    MailboxCapability {
        capability_id: format!("cap_{}", uuid::Uuid::new_v4().simple()),
        access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(access_key),
        auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth_token),
        bootstrap_token: None,
    }
}

pub(crate) fn build_group_content_crypto_state(epoch: u64) -> GroupContentCryptoAdvertisedState {
    let secret = rand::random::<[u8; 32]>();
    GroupContentCryptoAdvertisedState {
        version: 1,
        suite: GroupContentCryptoSuite::EpochAegis256,
        epoch,
        content_secret_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
    }
}

pub(crate) fn build_anonymous_group_writer_state(
    epoch: u64,
) -> AnonymousGroupWriterCredentialAdvertisedState {
    let secret = rand::random::<[u8; 32]>();
    AnonymousGroupWriterCredentialAdvertisedState {
        version: 1,
        suite: AnonymousGroupWriterCredentialSuite::EpochHmacSha256,
        epoch,
        writer_secret_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
    }
}

pub(crate) fn empty_mailbox_capability() -> MailboxCapability {
    MailboxCapability {
        capability_id: String::new(),
        access_key_b64: String::new(),
        auth_token_b64: String::new(),
        bootstrap_token: None,
    }
}

pub(crate) fn group_chunk_size_for_mailbox(max_payload_bytes: usize) -> usize {
    let budget = max_payload_bytes / 6;
    budget.clamp(GROUP_CHUNK_MIN_BYTES, GROUP_CHUNK_MAX_BYTES)
}

pub(crate) fn group_chunk_transfer_ttl_ms(persistence: &GroupMailboxPersistence) -> u64 {
    match persistence {
        GroupMailboxPersistence::MemoryOnly => 60 * 60 * 1000,
        GroupMailboxPersistence::EncryptedDisk => MAILBOX_DEFAULT_RETENTION_MS,
    }
}

pub(crate) fn group_fast_transfer_expires_at(ttl_ms: u64) -> u64 {
    current_unix_ts().saturating_add((ttl_ms.max(1) / 1000).max(1))
}

pub(crate) fn group_fast_file_grant_expires_at(staged_expires_at: u64) -> u64 {
    let short_window = current_unix_ts()
        .saturating_add(GROUP_FAST_FILE_GRANT_TTL_SECS)
        .max(current_unix_ts().saturating_add(1));
    staged_expires_at.min(short_window)
}

pub(crate) fn source_display_name(source: &Path) -> Result<String> {
    source
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(|name| name.to_string())
        .ok_or_else(|| anyhow::anyhow!("Failed to determine source file name"))
}

pub(crate) fn packed_transfer_display_name(source: &Path) -> Result<String> {
    if source.is_dir() {
        let base = source_display_name(source)?;
        return Ok(format!("{base}.tar.gz"));
    }
    source_display_name(source)
}

pub(crate) fn encode_group_chunk_capability(
    payload: &GroupChunkCapabilityPayload,
) -> Result<String> {
    let encoded = serde_json::to_vec(payload).context("Failed to encode group chunk capability")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

pub(crate) fn decode_group_chunk_capability(encoded: &str) -> Result<GroupChunkCapabilityPayload> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .context("Invalid group chunk capability encoding")?;
    serde_json::from_slice(&decoded).context("Invalid group chunk capability payload")
}

pub(crate) fn build_group_chunk_descriptor(
    group_id: &str,
    endpoint: &str,
    poll_interval_ms: u64,
    max_payload_bytes: usize,
    transfer_id: &str,
    anonymous_group: bool,
) -> Result<MailboxDescriptor> {
    parse_mailbox_service_endpoint(endpoint)?;
    Ok(MailboxDescriptor {
        transport: MailboxTransportKind::Tor,
        namespace: if anonymous_group {
            format!("mailbox:anon_chunk_{}", uuid::Uuid::new_v4().simple())
        } else {
            format!("mailbox:{}:epoch:chunk_{}", group_id, transfer_id)
        },
        endpoint: Some(endpoint.to_string()),
        poll_interval_ms,
        max_payload_bytes,
    })
}

pub(crate) fn group_chunk_staging_root(
    agent_data_dir: &Path,
    persistence: &GroupMailboxPersistence,
) -> PathBuf {
    match persistence {
        GroupMailboxPersistence::MemoryOnly => runtime_temp_path("qypha-group-chunk"),
        GroupMailboxPersistence::EncryptedDisk => agent_data_dir.join("group_mailbox_chunks"),
    }
}

pub(crate) fn decode_persisted_group_mailbox_registry(
    encoded: &[u8],
    key: &[u8; 32],
) -> Result<PersistedGroupMailboxRegistry> {
    let blob: PersistedGroupMailboxBlob =
        bincode::deserialize(encoded).context("Failed to decode persisted mailbox group blob")?;
    if blob.version != 1 {
        bail!(
            "Unsupported mailbox group persistence version {}",
            blob.version
        );
    }
    if blob.ciphertext.len() < 32 {
        bail!("Persisted mailbox group blob is truncated");
    }
    let nonce: [u8; 32] = blob
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Persisted mailbox group nonce is invalid"))?;
    let tag_offset = blob.ciphertext.len() - 32;
    let ciphertext = &blob.ciphertext[..tag_offset];
    let tag: [u8; 32] = blob.ciphertext[tag_offset..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Persisted mailbox group tag is invalid"))?;
    let aegis = Aegis256::<32>::new(key, &nonce);
    let mut plaintext = aegis
        .decrypt(ciphertext, &tag, b"group-mailboxes-persist-v1")
        .map_err(|_| anyhow::anyhow!("Persisted mailbox group blob failed integrity check"))?;
    let registry: PersistedGroupMailboxRegistry = bincode::deserialize(&plaintext)
        .context("Failed to decode persisted mailbox group registry")?;
    plaintext.zeroize();
    if registry.version != 1 {
        bail!(
            "Unsupported persisted mailbox group registry version {}",
            registry.version
        );
    }
    Ok(registry)
}

pub(crate) fn should_quarantine_persisted_mailbox_group_blob(error: &anyhow::Error) -> bool {
    const CORRUPTION_MARKERS: &[&str] = &[
        "Failed to decode persisted mailbox group blob",
        "Persisted mailbox group blob is truncated",
        "Persisted mailbox group nonce is invalid",
        "Persisted mailbox group tag is invalid",
        "Persisted mailbox group blob failed integrity check",
        "Failed to decode persisted mailbox group registry",
    ];

    error.chain().any(|cause| {
        let text = cause.to_string();
        CORRUPTION_MARKERS
            .iter()
            .any(|marker| text.contains(marker))
    })
}

pub(crate) fn delete_corrupted_persisted_mailbox_group_blob(path: &Path) {
    secure_wipe_file(path);
}

pub(crate) fn wipe_orphaned_group_chunk_staging_root(persist_path: &Path) {
    let Some(agent_data_dir) = persist_path.parent() else {
        return;
    };
    let staging_root =
        group_chunk_staging_root(agent_data_dir, &GroupMailboxPersistence::EncryptedDisk);
    if staging_root.exists() {
        secure_wipe_dir(&staging_root);
    }
}

pub(crate) fn prepare_group_receive_target(
    log_mode: &LogMode,
    receive_dir_config: &ReceiveDirConfig,
    sender_selector: &str,
    transfer_id: &str,
) -> Result<(PathBuf, Option<(String, PathBuf)>)> {
    if ghost_secure_handoff_enabled(log_mode) {
        let (handoff_id, handoff_dir) = create_ghost_handoff_dir()
            .map_err(|e| anyhow::anyhow!("failed to create secure handoff dir: {}", e))?;
        return Ok((handoff_dir.clone(), Some((handoff_id, handoff_dir))));
    }

    let base_dir = effective_receive_base_dir(receive_dir_config, sender_selector);
    ensure_private_receive_dir(&base_dir)?;
    let target_dir = base_dir.join(format!("group-mailbox-{}", transfer_id));
    ensure_private_receive_dir(&target_dir)?;
    Ok((target_dir, None))
}

pub(crate) fn build_group_chunk_message(
    session: &GroupMailboxSession,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    sender_profile: Option<&GroupMailboxMemberProfile>,
    mailbox_descriptor: &MailboxDescriptor,
    crypto_context: &GroupMailboxCryptoContext,
    kind: GroupMailboxMessageKind,
    payload_bytes: &[u8],
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    let purpose = match kind {
        GroupMailboxMessageKind::FileChunkData => "message/file_chunk_data",
        GroupMailboxMessageKind::FileChunkComplete => "message/file_chunk_complete",
        _ => bail!("Unsupported group chunk mailbox message kind"),
    };
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let mailbox_message = if session.anonymous_group {
        let inner_kind = match kind {
            GroupMailboxMessageKind::FileChunkData => AnonymousMailboxInnerKind::FileChunkData,
            GroupMailboxMessageKind::FileChunkComplete => {
                AnonymousMailboxInnerKind::FileChunkComplete
            }
            _ => bail!("Unsupported anonymous group chunk mailbox message kind"),
        };
        let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
        let wrapped_payload = wrap_anonymous_group_mailbox_payload(
            session,
            kind.clone(),
            &message_id,
            created_at,
            created_at_ms,
            payload_bytes,
        )?;
        let opaque_payload = encode_anonymous_opaque_payload(inner_kind, &wrapped_payload);
        GroupMailboxMessage {
            version: 1,
            message_id: message_id.clone(),
            group_id: mailbox_namespace_group_label(&mailbox_descriptor.namespace).to_string(),
            anonymous_group: true,
            sender_member_id: None,
            kind: GroupMailboxMessageKind::AnonymousOpaque,
            created_at,
            created_at_ms,
            ttl_ms,
            ciphertext: seal_group_mailbox_payload_with_context(
                session,
                crypto_context,
                signing_key,
                sender_profile,
                kind.clone(),
                &message_id,
                created_at,
                created_at_ms,
                "message/anonymous_opaque",
                &opaque_payload,
            )?,
        }
    } else {
        let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
        GroupMailboxMessage {
            version: 1,
            message_id: message_id.clone(),
            group_id: session.group_id.clone(),
            anonymous_group: false,
            sender_member_id: session.local_member_id.clone(),
            kind: kind.clone(),
            created_at,
            created_at_ms,
            ttl_ms,
            ciphertext: seal_group_mailbox_payload_with_context(
                session,
                crypto_context,
                signing_key,
                sender_profile,
                kind,
                &message_id,
                created_at,
                created_at_ms,
                purpose,
                payload_bytes,
            )?,
        }
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn materialize_inline_group_file(
    log_mode: &LogMode,
    receive_dir_config: &ReceiveDirConfig,
    sender_selector: &str,
    manifest_id: &str,
    filename: &str,
    plaintext: &[u8],
) -> Result<(PathBuf, Option<(String, PathBuf)>)> {
    let (target_dir, handoff) =
        prepare_group_receive_target(log_mode, receive_dir_config, sender_selector, manifest_id)?;
    let output_path = target_dir.join(filename);
    if output_path.exists() {
        bail!(
            "Refusing to overwrite existing group mailbox file {}",
            output_path.display()
        );
    }
    std::fs::write(&output_path, plaintext)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((output_path, handoff))
}

pub(crate) fn queue_pending_group_file_offer(
    registry: &mut GroupMailboxRegistry,
    session: &GroupMailboxSession,
    manifest: &GroupFileManifestPayload,
    sender_member_id: Option<String>,
) -> Result<bool> {
    if manifest.inline_ciphertext.is_none()
        && manifest.chunk_capability.is_none()
        && manifest.fast_transfer_id.is_none()
    {
        bail!("Group file manifest does not carry inline data, chunk capability, or fast transfer");
    }
    registry.store_pending_file_offer(GroupPendingFileOffer {
        manifest_id: manifest.manifest_id.clone(),
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: session.anonymous_group,
        sender_member_id,
        persistence: session.persistence.clone(),
        crypto_context: crypto_context_for_session(session),
        manifest: manifest.clone(),
    })
}

pub(crate) fn queue_pending_group_handshake_offer(
    registry: &mut GroupMailboxRegistry,
    session: &GroupMailboxSession,
    sender_member_id: &str,
    invite_code: &str,
    received_at_ms: u64,
    expires_at_ms: u64,
) -> Result<bool> {
    registry.store_pending_handshake_offer(GroupPendingHandshakeOffer {
        sender_member_id: sender_member_id.to_string(),
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        persistence: session.persistence.clone(),
        invite_code: invite_code.to_string(),
        received_at_ms,
        expires_at_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupPendingHandshakeOfferOutcome {
    pub(crate) sender_member_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) invite_code: String,
    pub(crate) expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupPendingFileOfferAction {
    InlineSaved {
        path: PathBuf,
        handoff_id: Option<String>,
    },
    FastRelayRequested {
        transfer_id: String,
    },
    ChunkDownloadQueued {
        transfer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupPendingFileOfferOutcome {
    pub(crate) manifest_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) anonymous_group: bool,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) sender_member_id: Option<String>,
    pub(crate) fast_transfer_id: Option<String>,
    pub(crate) action: GroupPendingFileOfferAction,
}

pub(crate) async fn approve_pending_group_file_offer(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    selector: &str,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
    agent_data_dir: &Path,
) -> Result<Option<GroupPendingFileOfferOutcome>> {
    let offer = {
        let registry = registry.lock().await;
        registry.pending_file_offer_cloned_for_selector(selector)?
    };
    let Some(offer) = offer else {
        return Ok(None);
    };

    if let Some(inline_ciphertext) = offer.manifest.inline_ciphertext.as_ref() {
        let sender_selector = offer
            .sender_member_id
            .clone()
            .unwrap_or_else(|| format!("group:{}", offer.group_id));
        let receive_cfg = receive_dir_config.lock().await.clone();
        let plaintext =
            decode_group_inline_blob_with_context(&offer.crypto_context, inline_ciphertext)?;
        let (saved_path, handoff) = materialize_inline_group_file(
            log_mode,
            &receive_cfg,
            &sender_selector,
            &offer.manifest_id,
            &offer.manifest.filename,
            &plaintext,
        )?;
        {
            let mut registry = registry.lock().await;
            registry.remove_pending_file_offer(&offer.manifest_id)?;
        }
        return Ok(Some(GroupPendingFileOfferOutcome {
            manifest_id: offer.manifest_id,
            group_id: offer.group_id,
            group_name: offer.group_name,
            anonymous_group: offer.anonymous_group,
            filename: offer.manifest.filename,
            size_bytes: offer.manifest.size_bytes,
            sender_member_id: offer.sender_member_id,
            fast_transfer_id: None,
            action: GroupPendingFileOfferAction::InlineSaved {
                path: saved_path,
                handoff_id: handoff.map(|(handoff_id, _)| handoff_id),
            },
        }));
    }

    if offer.manifest.chunk_capability.is_none() {
        let Some(fast_transfer_id) = (!offer.anonymous_group)
            .then_some(offer.manifest.fast_transfer_id.clone())
            .flatten()
        else {
            bail!("Pending group file offer is missing chunk capability");
        };
        {
            let mut registry = registry.lock().await;
            registry.remove_pending_file_offer(&offer.manifest_id)?;
        }
        return Ok(Some(GroupPendingFileOfferOutcome {
            manifest_id: offer.manifest_id,
            group_id: offer.group_id,
            group_name: offer.group_name,
            anonymous_group: offer.anonymous_group,
            filename: offer.manifest.filename,
            size_bytes: offer.manifest.size_bytes,
            sender_member_id: offer.sender_member_id,
            fast_transfer_id: Some(fast_transfer_id.clone()),
            action: GroupPendingFileOfferAction::FastRelayRequested {
                transfer_id: fast_transfer_id,
            },
        }));
    }

    let encoded_capability =
        offer.manifest.chunk_capability.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Pending group file offer is missing chunk capability")
        })?;
    let capability = decode_group_chunk_capability(encoded_capability)?;
    {
        let mut registry = registry.lock().await;
        let Some(session) = registry.get_cloned(&offer.group_id) else {
            bail!(
                "Mailbox group {} is no longer joined; cannot approve pending file {}",
                offer.group_id,
                offer.manifest.filename
            );
        };
        register_group_chunk_download(
            &mut registry,
            &session,
            &capability,
            &offer.manifest,
            offer.sender_member_id.clone(),
            agent_data_dir,
        )?;
        registry.remove_pending_file_offer(&offer.manifest_id)?;
    }
    Ok(Some(GroupPendingFileOfferOutcome {
        manifest_id: offer.manifest_id,
        group_id: offer.group_id,
        group_name: offer.group_name,
        anonymous_group: offer.anonymous_group,
        filename: offer.manifest.filename,
        size_bytes: offer.manifest.size_bytes,
        sender_member_id: offer.sender_member_id,
        fast_transfer_id: (!offer.anonymous_group)
            .then_some(offer.manifest.fast_transfer_id.clone())
            .flatten(),
        action: GroupPendingFileOfferAction::ChunkDownloadQueued {
            transfer_id: capability.transfer_id,
        },
    }))
}

pub(crate) async fn reject_pending_group_file_offer(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    selector: &str,
) -> Result<Option<GroupPendingFileOfferSummary>> {
    let offer = {
        let mut registry = registry.lock().await;
        let offer = registry.pending_file_offer_cloned_for_selector(selector)?;
        let Some(offer) = offer else {
            return Ok(None);
        };
        registry.remove_pending_file_offer(&offer.manifest_id)?;
        offer
    };
    Ok(Some(GroupPendingFileOfferSummary {
        manifest_id: offer.manifest_id,
        group_id: offer.group_id,
        group_name: offer.group_name,
        anonymous_group: offer.anonymous_group,
        sender_member_id: offer.sender_member_id,
        filename: offer.manifest.filename,
        size_bytes: offer.manifest.size_bytes,
    }))
}

pub(crate) async fn accept_pending_group_handshake_offer(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    selector: &str,
) -> Result<Option<GroupPendingHandshakeOfferOutcome>> {
    let offer = {
        let mut registry = registry.lock().await;
        registry.take_pending_handshake_offer_for_selector(selector)?
    };
    Ok(offer.map(|offer| GroupPendingHandshakeOfferOutcome {
        sender_member_id: offer.sender_member_id,
        group_id: offer.group_id,
        group_name: offer.group_name,
        invite_code: offer.invite_code,
        expires_at_ms: offer.expires_at_ms,
    }))
}

pub(crate) async fn reject_pending_group_handshake_offer(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    selector: Option<&str>,
) -> Result<Option<GroupPendingHandshakeOfferSummary>> {
    let offer = {
        let mut registry = registry.lock().await;
        match selector {
            Some(selector) => registry.take_pending_handshake_offer_for_selector(selector)?,
            None => registry.take_single_pending_handshake_offer()?,
        }
    };
    Ok(offer.map(|offer| GroupPendingHandshakeOfferSummary {
        sender_member_id: offer.sender_member_id,
        group_id: offer.group_id,
        group_name: offer.group_name,
        received_at_ms: offer.received_at_ms,
        expires_at_ms: offer.expires_at_ms,
    }))
}

pub(crate) async fn clear_pending_group_handshake_offers(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
) -> Result<Vec<GroupPendingHandshakeOfferSummary>> {
    let offers = {
        let mut registry = registry.lock().await;
        registry.drain_pending_handshake_offers()?
    };
    let mut summaries = offers
        .into_iter()
        .map(|offer| GroupPendingHandshakeOfferSummary {
            sender_member_id: offer.sender_member_id,
            group_id: offer.group_id,
            group_name: offer.group_name,
            received_at_ms: offer.received_at_ms,
            expires_at_ms: offer.expires_at_ms,
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|a, b| {
        a.received_at_ms
            .cmp(&b.received_at_ms)
            .then_with(|| a.sender_member_id.cmp(&b.sender_member_id))
    });
    Ok(summaries)
}

#[cfg(test)]
pub(crate) async fn seed_pending_group_handshake_offer_for_test(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    group_id: &str,
    group_name: Option<&str>,
    sender_member_id: &str,
    invite_code: &str,
    persistence: GroupMailboxPersistence,
) -> Result<()> {
    let mut registry = registry.lock().await;
    registry.store_pending_handshake_offer(GroupPendingHandshakeOffer {
        sender_member_id: sender_member_id.to_string(),
        group_id: group_id.to_string(),
        group_name: group_name.map(str::to_string),
        persistence,
        invite_code: invite_code.to_string(),
        received_at_ms: current_unix_ts_ms(),
        expires_at_ms: current_unix_ts_ms().saturating_add(60_000),
    })?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn seed_identified_group_member_for_test(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    group_id: &str,
    group_name: Option<&str>,
    local_member_id: &str,
    local_display_name: &str,
    member_id: &str,
    member_display_name: &str,
) -> Result<()> {
    let local_keypair = AgentKeyPair::generate(local_display_name, "agent");
    let remote_keypair = AgentKeyPair::generate(member_display_name, "agent");
    let signing_key = local_keypair.signing_key.clone();
    let local_profile = GroupMailboxMemberProfile {
        member_id: local_member_id.to_string(),
        display_name: local_display_name.to_string(),
        verifying_key_hex: hex::encode(local_keypair.signing_key.verifying_key().to_bytes()),
        encryption_public_key_hex: hex::encode(local_keypair.x25519_public_key_bytes()),
        kyber_public_key_hex: (!local_keypair.kyber_public.is_empty())
            .then(|| hex::encode(&local_keypair.kyber_public)),
    };
    let remote_profile = GroupMailboxMemberProfile {
        member_id: member_id.to_string(),
        display_name: member_display_name.to_string(),
        verifying_key_hex: hex::encode(remote_keypair.signing_key.verifying_key().to_bytes()),
        encryption_public_key_hex: hex::encode(remote_keypair.x25519_public_key_bytes()),
        kyber_public_key_hex: (!remote_keypair.kyber_public.is_empty())
            .then(|| hex::encode(&remote_keypair.kyber_public)),
    };
    let descriptor = MailboxDescriptor {
        transport: MailboxTransportKind::Tor,
        namespace: group_id.to_string(),
        endpoint: Some(format!("tor://{}:443", "a".repeat(56))),
        poll_interval_ms: 5_000,
        max_payload_bytes: 256 * 1024,
    };
    let (session, _invite) = create_identified_group(
        &signing_key,
        local_member_id,
        group_name,
        descriptor,
        GroupMailboxPersistence::EncryptedDisk,
        local_profile,
    )?;
    let mut registry = registry.lock().await;
    registry.insert_session(session)?;
    registry.observe_member_profile(group_id, remote_profile)?;
    Ok(())
}

pub(crate) fn build_chat_message(
    session: &GroupMailboxSession,
    keypair: &AgentKeyPair,
    message: &str,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    let body = message.trim();
    if body.is_empty() {
        bail!("Group mailbox chat message must not be empty");
    }
    let payload = serde_json::to_vec(&GroupChatPayload {
        body: body.to_string(),
    })
    .context("Failed to encode group chat payload")?;
    let sender_profile = (!session.anonymous_group)
        .then(|| local_member_profile(session))
        .transpose()?;
    build_group_mailbox_message(
        session,
        Some(&keypair.signing_key),
        sender_profile.as_ref(),
        GroupMailboxMessageKind::Chat,
        "message/chat",
        &payload,
        ttl_ms,
    )
}

pub(crate) fn build_inline_file_manifest_message(
    session: &GroupMailboxSession,
    keypair: &AgentKeyPair,
    source: &Path,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    let file_bytes =
        std::fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;
    let size_bytes = file_bytes.len() as u64;

    let filename = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Failed to determine file name"))?
        .to_string();
    let plaintext_sha256 = hex::encode(Sha256::digest(&file_bytes));
    let inline_ciphertext = seal_bytes(session, "inline-file", &file_bytes)?;
    let payload = GroupFileManifestPayload {
        manifest_id: format!("gmanifest_{}", uuid::Uuid::new_v4().simple()),
        filename,
        size_bytes,
        plaintext_sha256,
        chunk_capability: None,
        inline_ciphertext: Some(inline_ciphertext),
        fast_transfer_id: None,
        fast_transfer_expires_at: None,
        fast_relay_only: true,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode group file manifest payload")?;
    let sender_profile = (!session.anonymous_group)
        .then(|| local_member_profile(session))
        .transpose()?;
    build_group_mailbox_message(
        session,
        Some(&keypair.signing_key),
        sender_profile.as_ref(),
        GroupMailboxMessageKind::FileManifest,
        "message/file_manifest",
        &payload_bytes,
        ttl_ms,
    )
}

pub(crate) async fn build_file_manifest_message_with_prepared_fast_transfer(
    transport: &TorMailboxTransport,
    session: &GroupMailboxSession,
    keypair: &AgentKeyPair,
    path: &str,
    ttl_ms: u64,
    fast_path_enabled: bool,
) -> Result<(GroupMailboxMessage, Option<PreparedFastGroupTransfer>)> {
    let source = Path::new(path);
    if !source.exists() {
        bail!("Path does not exist: {}", path);
    }

    if source.is_file() {
        let inline_threshold =
            (session.mailbox_descriptor.max_payload_bytes / 8).max(8 * 1024) as u64;
        let size_bytes = std::fs::metadata(source)
            .with_context(|| format!("Failed to stat {}", source.display()))?
            .len();
        if size_bytes <= inline_threshold {
            return Ok((
                build_inline_file_manifest_message(session, keypair, source, ttl_ms)?,
                None,
            ));
        }
    }

    let source_owned = source.to_path_buf();
    let packed_filename = packed_transfer_display_name(source)?;
    let packed_path =
        tokio::task::spawn_blocking(move || chunked_transfer::pack_to_temp_file(&source_owned))
            .await
            .map_err(|e| anyhow::anyhow!("group mailbox packing task failed: {}", e))??;
    let transfer_ttl_ms = group_chunk_transfer_ttl_ms(&session.persistence).max(ttl_ms);
    let fast_transfer_enabled = fast_path_enabled && !session.anonymous_group;
    if fast_transfer_enabled {
        let packed_path_for_fast_session = packed_path.clone();
        let packed_filename_for_fast_session = packed_filename.clone();
        let sender_keypair_fast = keypair.clone();
        let group_recipient_fast = format!("group:{}", session.group_id);
        let fast_session = tokio::task::spawn_blocking(move || {
            chunked_transfer::prepare_session_streaming(
                &sender_keypair_fast,
                &group_recipient_fast,
                &packed_filename_for_fast_session,
                "group_fast_relay",
                &packed_path_for_fast_session,
                super::super::IROH_CHUNK_SIZE_BYTES,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("group fast transfer session task failed: {}", e))??;
        let prepared_fast_transfer = PreparedFastGroupTransfer {
            transfer_id: fast_session.session_id.clone(),
            mailbox_transfer_id: format!("fastonly_{}", fast_session.session_id),
            filename: packed_filename.clone(),
            size_bytes: fast_session.total_size,
            plaintext_sha256: fast_session.plaintext_sha256.clone(),
            merkle_root: fast_session.merkle_root,
            total_chunks: fast_session.total_chunks,
            chunk_size: fast_session.chunk_size,
            relay_only: true,
            expires_at: group_fast_transfer_expires_at(transfer_ttl_ms),
            packed_path: packed_path.clone(),
            fast_session,
        };
        let payload = GroupFileManifestPayload {
            manifest_id: format!("gmanifest_{}", uuid::Uuid::new_v4().simple()),
            filename: prepared_fast_transfer.filename.clone(),
            size_bytes: prepared_fast_transfer.size_bytes,
            plaintext_sha256: prepared_fast_transfer.plaintext_sha256.clone(),
            chunk_capability: None,
            inline_ciphertext: None,
            fast_transfer_id: Some(prepared_fast_transfer.transfer_id.clone()),
            fast_transfer_expires_at: Some(prepared_fast_transfer.expires_at),
            fast_relay_only: prepared_fast_transfer.relay_only,
        };
        let payload_bytes =
            serde_json::to_vec(&payload).context("Failed to encode group file manifest payload")?;
        let sender_profile = (!session.anonymous_group)
            .then(|| local_member_profile(session))
            .transpose()?;
        let message = build_group_mailbox_message(
            session,
            Some(&keypair.signing_key),
            sender_profile.as_ref(),
            GroupMailboxMessageKind::FileManifest,
            "message/file_manifest",
            &payload_bytes,
            ttl_ms,
        )?;
        return Ok((message, Some(prepared_fast_transfer)));
    }

    let chunk_size = group_chunk_size_for_mailbox(session.mailbox_descriptor.max_payload_bytes);
    let group_recipient = format!("group:{}", session.group_id);
    let group_recipient_for_session = group_recipient.clone();
    let packed_filename_for_session = packed_filename.clone();
    let packed_path_for_session = packed_path.clone();
    let sender_keypair = keypair.clone();
    let transfer_session = tokio::task::spawn_blocking(move || {
        chunked_transfer::prepare_session_streaming(
            &sender_keypair,
            &group_recipient_for_session,
            &packed_filename_for_session,
            "group_mailbox",
            &packed_path_for_session,
            chunk_size,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("group mailbox chunk session task failed: {}", e))??;
    let prepared_fast_transfer: Option<PreparedFastGroupTransfer> = None;
    let chunk_descriptor = build_group_chunk_descriptor(
        &session.group_id,
        session
            .mailbox_descriptor
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Mailbox group is missing relay endpoint"))?,
        session.mailbox_descriptor.poll_interval_ms,
        session.mailbox_descriptor.max_payload_bytes,
        &transfer_session.session_id,
        session.anonymous_group,
    )?;
    let mut chunk_capability = build_mailbox_capability();
    issue_group_mailbox_bootstrap_token(
        &keypair.signing_key,
        MailboxBootstrapScopeKind::ChunkTransfer,
        &transfer_session.session_id,
        &chunk_descriptor,
        &mut chunk_capability,
        group_fast_transfer_expires_at(transfer_ttl_ms),
    )?;
    let chunk_crypto_context = GroupMailboxCryptoContext {
        group_id: session.group_id.clone(),
        anonymous_group: session.anonymous_group,
        mailbox_capability: chunk_capability.clone(),
        content_crypto_state: session.content_crypto_state.clone(),
        anonymous_writer_state: session.anonymous_writer_state.clone(),
    };
    let sender_profile = (!session.anonymous_group)
        .then(|| local_member_profile(session))
        .transpose()?;
    for chunk_state in &transfer_session.chunks {
        let chunk_bytes = chunked_transfer::read_chunk_from_file(
            &packed_path,
            &transfer_session,
            chunk_state.index,
        )?;
        let chunk_payload = GroupFileChunkPayload {
            transfer_id: transfer_session.session_id.clone(),
            artifact_id: transfer_session.artifact_id.clone(),
            chunk_index: chunk_state.index,
            total_chunks: transfer_session.total_chunks,
            chunk_sha256: chunk_state.sha256,
            chunk_bytes,
        };
        let chunk_bytes =
            bincode::serialize(&chunk_payload).context("Failed to encode group chunk payload")?;
        let chunk_message = build_group_chunk_message(
            session,
            Some(&keypair.signing_key),
            sender_profile.as_ref(),
            &chunk_descriptor,
            &chunk_crypto_context,
            GroupMailboxMessageKind::FileChunkData,
            &chunk_bytes,
            transfer_ttl_ms,
        )?;
        transport
            .post_message(&chunk_descriptor, &chunk_capability, &chunk_message)
            .await
            .with_context(|| {
                format!(
                    "Failed to upload group mailbox chunk {}/{}",
                    chunk_state.index + 1,
                    transfer_session.total_chunks
                )
            })?;
    }
    let complete_payload = GroupFileChunkCompletePayload {
        transfer_id: transfer_session.session_id.clone(),
        artifact_id: transfer_session.artifact_id.clone(),
        total_chunks: transfer_session.total_chunks,
    };
    let complete_bytes = bincode::serialize(&complete_payload)
        .context("Failed to encode group chunk complete payload")?;
    let complete_message = build_group_chunk_message(
        session,
        Some(&keypair.signing_key),
        sender_profile.as_ref(),
        &chunk_descriptor,
        &chunk_crypto_context,
        GroupMailboxMessageKind::FileChunkComplete,
        &complete_bytes,
        transfer_ttl_ms,
    )?;
    transport
        .post_message(&chunk_descriptor, &chunk_capability, &complete_message)
        .await
        .context("Failed to upload group mailbox chunk completion message")?;
    if prepared_fast_transfer.is_none() {
        secure_wipe_file(&packed_path);
    }

    let capability = GroupChunkCapabilityPayload {
        transfer_id: transfer_session.session_id.clone(),
        artifact_id: transfer_session.artifact_id.clone(),
        filename: packed_filename,
        chunk_size: transfer_session.chunk_size,
        total_chunks: transfer_session.total_chunks,
        total_size: transfer_session.total_size,
        plaintext_sha256: transfer_session.plaintext_sha256.clone(),
        merkle_root: transfer_session.merkle_root,
        sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
        mailbox_descriptor: chunk_descriptor,
        mailbox_capability: chunk_capability,
    };
    let fast_transfer_expires_at = prepared_fast_transfer
        .as_ref()
        .map(|prepared| prepared.expires_at);
    let payload = GroupFileManifestPayload {
        manifest_id: format!("gmanifest_{}", uuid::Uuid::new_v4().simple()),
        filename: capability.filename.clone(),
        size_bytes: capability.total_size,
        plaintext_sha256: capability.plaintext_sha256.clone(),
        chunk_capability: Some(encode_group_chunk_capability(&capability)?),
        inline_ciphertext: None,
        fast_transfer_id: prepared_fast_transfer
            .as_ref()
            .map(|prepared| prepared.transfer_id.clone()),
        fast_transfer_expires_at,
        fast_relay_only: true,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode group file manifest payload")?;
    let message = build_group_mailbox_message(
        session,
        Some(&keypair.signing_key),
        sender_profile.as_ref(),
        GroupMailboxMessageKind::FileManifest,
        "message/file_manifest",
        &payload_bytes,
        transfer_ttl_ms,
    )?;
    Ok((message, prepared_fast_transfer))
}

pub(crate) async fn build_file_manifest_message(
    transport: &TorMailboxTransport,
    session: &GroupMailboxSession,
    keypair: &AgentKeyPair,
    path: &str,
    ttl_ms: u64,
    fast_path_enabled: bool,
) -> Result<GroupMailboxMessage> {
    let (message, prepared_fast_transfer) =
        build_file_manifest_message_with_prepared_fast_transfer(
            transport,
            session,
            keypair,
            path,
            ttl_ms,
            fast_path_enabled,
        )
        .await?;
    if let Some(prepared) = prepared_fast_transfer {
        secure_wipe_file(&prepared.packed_path);
    }
    Ok(message)
}

pub(crate) async fn post_group_mailbox_message<T: MailboxTransport + ?Sized>(
    transport: &T,
    session: &GroupMailboxSession,
    message: &GroupMailboxMessage,
) -> Result<MailboxPostReceipt> {
    transport
        .post_message(
            &session.mailbox_descriptor,
            &session.mailbox_capability,
            message,
        )
        .await
}

pub(crate) async fn emit_due_anonymous_cover_traffic_once(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &TorMailboxTransport,
) {
    let now_ms = current_unix_ts_ms();
    let mut sessions = {
        let registry = registry.lock().await;
        registry
            .sessions
            .values()
            .filter(|session| {
                session.anonymous_group
                    && session
                        .next_cover_traffic_at
                        .map(|deadline| deadline <= now_ms)
                        .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    if sessions.len() > 1 {
        sessions.shuffle(&mut rand::thread_rng());
    }

    for session in sessions {
        let cover_message = match build_ghost_anonymous_cover_message(&session) {
            Ok(message) => message,
            Err(error) => {
                let group_log_id = redacted_log_marker("group", &session.group_id);
                tracing::warn!(
                    group_id = %group_log_id,
                    %error,
                    "Failed to build anonymous cover traffic message"
                );
                let mut registry = registry.lock().await;
                registry
                    .reschedule_anonymous_cover_traffic(&session.group_id, current_unix_ts_ms());
                continue;
            }
        };
        if let Err(error) = post_group_mailbox_message(transport, &session, &cover_message).await {
            let group_log_id = redacted_log_marker("group", &session.group_id);
            tracing::warn!(
                group_id = %group_log_id,
                %error,
                "Anonymous cover traffic send failed"
            );
        }
        let mut registry = registry.lock().await;
        registry.reschedule_anonymous_cover_traffic(&session.group_id, current_unix_ts_ms());
    }
}

pub(crate) fn build_group_chunk_init(
    capability: &GroupChunkCapabilityPayload,
) -> ChunkTransferInitPayload {
    ChunkTransferInitPayload {
        session_id: capability.transfer_id.clone(),
        artifact_id: capability.artifact_id.clone(),
        filename: capability.filename.clone(),
        classification: "group_mailbox".to_string(),
        total_size: capability.total_size,
        chunk_size: capability.chunk_size,
        total_chunks: capability.total_chunks,
        merkle_root: capability.merkle_root,
        plaintext_sha256: capability.plaintext_sha256.clone(),
        sender_verifying_key_hex: capability.sender_verifying_key_hex.clone(),
        version: 1,
        requires_reapproval: false,
        resume_requested: false,
        resume_token: String::new(),
    }
}

pub(crate) fn crypto_context_for_session(
    session: &GroupMailboxSession,
) -> GroupMailboxCryptoContext {
    GroupMailboxCryptoContext {
        group_id: session.group_id.clone(),
        anonymous_group: session.anonymous_group,
        mailbox_capability: session.mailbox_capability.clone(),
        content_crypto_state: session.content_crypto_state.clone(),
        anonymous_writer_state: session.anonymous_writer_state.clone(),
    }
}

pub(crate) fn register_group_chunk_download(
    registry: &mut GroupMailboxRegistry,
    session: &GroupMailboxSession,
    capability: &GroupChunkCapabilityPayload,
    manifest: &GroupFileManifestPayload,
    sender_member_id: Option<String>,
    agent_data_dir: &Path,
) -> Result<bool> {
    if registry.chunk_download_exists(&capability.transfer_id) {
        return Ok(false);
    }
    if capability.total_size != manifest.size_bytes {
        bail!("Group chunk capability size mismatch");
    }
    if capability.plaintext_sha256 != manifest.plaintext_sha256 {
        bail!("Group chunk capability sha256 mismatch");
    }
    let token = capability
        .mailbox_capability
        .bootstrap_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Group chunk capability missing mailbox bootstrap token"))?;
    verify_mailbox_bootstrap_token(
        token,
        Some(MailboxBootstrapScopeKind::ChunkTransfer),
        &capability.mailbox_descriptor.namespace,
        &capability.mailbox_capability,
        false,
    )?;
    let sender_selector = sender_member_id
        .clone()
        .unwrap_or_else(|| format!("group:{}", session.group_id));
    let recv = ChunkedReceiveSession::new_in_root(
        build_group_chunk_init(capability),
        sender_selector,
        describe_group(session),
        &group_chunk_staging_root(agent_data_dir, &session.persistence),
    )?;
    registry.upsert_chunk_download(GroupChunkDownloadState {
        transfer_id: capability.transfer_id.clone(),
        artifact_id: capability.artifact_id.clone(),
        manifest_id: manifest.manifest_id.clone(),
        group_id: session.group_id.clone(),
        filename: capability.filename.clone(),
        sender_member_id,
        crypto_context: GroupMailboxCryptoContext {
            group_id: session.group_id.clone(),
            anonymous_group: session.anonymous_group,
            mailbox_capability: capability.mailbox_capability.clone(),
            content_crypto_state: session.content_crypto_state.clone(),
            anonymous_writer_state: session.anonymous_writer_state.clone(),
        },
        mailbox_descriptor: capability.mailbox_descriptor.clone(),
        mailbox_capability: capability.mailbox_capability.clone(),
        poll_cursor: None,
        persistence: session.persistence.clone(),
        recv,
    })?;
    Ok(true)
}

pub(crate) async fn finalize_group_chunk_download(
    download: &GroupChunkDownloadState,
    log_mode: &LogMode,
    receive_dir_config: &ReceiveDirConfig,
) -> Result<(PathBuf, Option<(String, PathBuf)>)> {
    let sender_selector = download
        .sender_member_id
        .clone()
        .unwrap_or_else(|| format!("group:{}", download.group_id));
    let (target_dir, handoff) = prepare_group_receive_target(
        log_mode,
        receive_dir_config,
        &sender_selector,
        &download.transfer_id,
    )?;
    tokio::task::block_in_place(|| download.recv.finalize_ref(&target_dir))?;
    Ok((target_dir, handoff))
}

pub(crate) async fn poll_group_chunk_downloads_once<T: MailboxTransport + ?Sized>(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &T,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    actor_did: &str,
    receive_dir_config: &Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    log_mode: &LogMode,
) {
    let downloads = {
        let registry = registry.lock().await;
        registry.chunk_downloads()
    };
    let receive_cfg = receive_dir_config.lock().await.clone();

    for mut download in downloads {
        let group_session = {
            let registry = registry.lock().await;
            registry.get_cloned(&download.group_id)
        };
        let Some(group_session) = group_session else {
            let mut registry = registry.lock().await;
            let _ = registry.remove_chunk_download(&download.transfer_id);
            continue;
        };

        let result = match transport
            .poll_messages(
                &download.mailbox_descriptor,
                &download.mailbox_capability,
                &MailboxPollRequest {
                    cursor: download.poll_cursor.clone(),
                    limit: 64,
                },
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                let group_log_id = log_group_id(log_mode, &download.group_id);
                tracing::warn!(
                    transfer_id = %transfer_log_id,
                    group_id = %group_log_id,
                    %e,
                    "Group chunk mailbox poll failed"
                );
                continue;
            }
        };
        let batch_len = result.items.len();

        let mut ack_ids = Vec::new();
        for item in result.items {
            if let Err(error) = message_is_live(&item.message, current_unix_ts()) {
                let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                let message_log_id = log_message_id(log_mode, &item.message.message_id);
                tracing::warn!(
                    transfer_id = %transfer_log_id,
                    message_id = %message_log_id,
                    %error,
                    "Rejected stale group chunk mailbox message"
                );
                continue;
            }
            let decoded = match decode_group_mailbox_message_with_context(
                &download.crypto_context,
                &item.message,
            ) {
                Ok(decoded) => decoded,
                Err(e) => {
                    let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                    let message_log_id = log_message_id(log_mode, &item.message.message_id);
                    tracing::warn!(
                        transfer_id = %transfer_log_id,
                        message_id = %message_log_id,
                        %e,
                        "Group chunk mailbox payload decode failed"
                    );
                    continue;
                }
            };
            let Some(kind) = decoded.kind else {
                ack_ids.push(item.envelope_id);
                continue;
            };
            match kind {
                GroupMailboxMessageKind::FileChunkData => {
                    let chunk: GroupFileChunkPayload = match bincode::deserialize(&decoded.payload)
                    {
                        Ok(chunk) => chunk,
                        Err(e) => {
                            let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                            tracing::warn!(transfer_id = %transfer_log_id, %e, "Group chunk payload decode failed");
                            continue;
                        }
                    };
                    if chunk.transfer_id != download.transfer_id {
                        continue;
                    }
                    let actual_hash: [u8; 32] = Sha256::digest(&chunk.chunk_bytes).into();
                    if actual_hash != chunk.chunk_sha256 {
                        let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                        tracing::warn!(
                            transfer_id = %transfer_log_id,
                            chunk_index = chunk.chunk_index,
                            "Group chunk sha256 mismatch"
                        );
                        continue;
                    }
                    match download
                        .recv
                        .store_chunk(chunk.chunk_index, chunk.chunk_bytes)
                    {
                        Ok(stored_new_chunk) => {
                            ack_ids.push(item.envelope_id);
                            if stored_new_chunk {
                                let approx_received_bytes = std::cmp::min(
                                    download.recv.received_count as u64
                                        * download.recv.init.chunk_size as u64,
                                    download.recv.init.total_size,
                                );
                                emit_transfer_progress_event_with_group(
                                    "incoming_progress",
                                    "group_mailbox",
                                    download.sender_member_id.as_deref(),
                                    Some(&describe_group(&group_session)),
                                    Some(&download.transfer_id),
                                    Some(&download.filename),
                                    download.recv.received_count,
                                    download.recv.init.total_chunks,
                                    approx_received_bytes,
                                    download.recv.init.total_size,
                                    Some(&download.group_id),
                                    group_session.group_name.as_deref(),
                                );
                            }
                        }
                        Err(e) => {
                            let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                            tracing::warn!(
                                transfer_id = %transfer_log_id,
                                chunk_index = chunk.chunk_index,
                                %e,
                                "Failed to store group chunk"
                            );
                        }
                    }
                }
                GroupMailboxMessageKind::FileChunkComplete => {
                    let complete: GroupFileChunkCompletePayload = match bincode::deserialize(
                        &decoded.payload,
                    ) {
                        Ok(complete) => complete,
                        Err(e) => {
                            let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                            tracing::warn!(transfer_id = %transfer_log_id, %e, "Group chunk complete decode failed");
                            continue;
                        }
                    };
                    if complete.transfer_id != download.transfer_id {
                        continue;
                    }
                    download.recv.transfer_complete_received = true;
                    ack_ids.push(item.envelope_id);
                }
                _ => continue,
            }
        }

        if ack_ids.len() == batch_len {
            download.poll_cursor = result.next_cursor;
        }
        {
            let mut registry = registry.lock().await;
            if let Err(error) = registry.upsert_chunk_download(download.clone()) {
                let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                tracing::warn!(transfer_id = %transfer_log_id, %error, "Failed to persist group chunk download state");
            }
        }

        if download.recv.transfer_complete_received && download.recv.is_complete() {
            match finalize_group_chunk_download(&download, log_mode, &receive_cfg).await {
                Ok((target_dir, handoff)) => {
                    if let Some((handoff_id, handoff_dir)) = handoff.as_ref() {
                        emit_transfer_event_with_handoff(
                            "incoming_staged",
                            "group_mailbox",
                            download.sender_member_id.as_deref(),
                            Some(&describe_group(&group_session)),
                            Some(&download.transfer_id),
                            Some(&download.filename),
                            Some("group_mailbox_chunk_ready"),
                            Some(handoff_id),
                            Some(handoff_dir.as_path()),
                        );
                    } else {
                        emit_transfer_event_with_group(
                            "incoming_complete",
                            "group_mailbox",
                            download.sender_member_id.as_deref(),
                            Some(&describe_group(&group_session)),
                            Some(&download.transfer_id),
                            Some(&download.filename),
                            Some("group_mailbox_chunk_complete"),
                            Some(&download.group_id),
                            group_session.group_name.as_deref(),
                        );
                    }
                    println!(
                        "   {} {} -> {}",
                        "Group file complete:".green().bold(),
                        download.filename.cyan(),
                        target_dir.display()
                    );
                    let mut registry = registry.lock().await;
                    let _ = registry.remove_chunk_download(&download.transfer_id);
                    let mut audit = audit.lock().await;
                    audit.record(
                        "GROUP_MAILBOX_FILE_RECV_COMPLETE",
                        actor_did,
                        &format!(
                            "group_id={} transfer_id={} filename={}",
                            download.group_id, download.transfer_id, download.filename
                        ),
                    );
                }
                Err(e) => {
                    let transfer_log_id = log_transfer_id(log_mode, &download.transfer_id);
                    tracing::warn!(transfer_id = %transfer_log_id, %e, "Group chunk finalize failed");
                }
            }
        }
    }
}

pub(crate) async fn announce_local_identified_membership_state(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &(impl MailboxTransport + ?Sized),
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    group_id: &str,
    state: MembershipNoticeState,
) -> Result<MailboxPostReceipt> {
    let session = {
        let mut registry = registry.lock().await;
        if state == MembershipNoticeState::Joined {
            registry.observe_member_profile(group_id, local_profile.clone())?;
        }
        registry
            .get_cloned(group_id)
            .ok_or_else(|| anyhow::anyhow!("Mailbox group {} not found", group_id))?
    };
    let message = build_membership_notice_message_with_state(
        &session,
        signing_key,
        local_profile,
        state,
        GROUP_IDENTIFIED_MEMBERSHIP_NOTICE_TTL_MS,
    )?;
    let receipt = post_group_mailbox_message(transport, &session, &message).await?;
    if state == MembershipNoticeState::Joined {
        let mut registry = registry.lock().await;
        registry.mark_local_post(group_id, &message.message_id);
    }
    Ok(receipt)
}

pub(crate) async fn announce_local_identified_membership(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &(impl MailboxTransport + ?Sized),
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    group_id: &str,
) -> Result<MailboxPostReceipt> {
    announce_local_identified_membership_state(
        registry,
        transport,
        signing_key,
        local_profile,
        group_id,
        MembershipNoticeState::Joined,
    )
    .await
}

pub(crate) async fn announce_local_identified_departure(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &(impl MailboxTransport + ?Sized),
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    group_id: &str,
) -> Result<MailboxPostReceipt> {
    announce_local_identified_membership_state(
        registry,
        transport,
        signing_key,
        local_profile,
        group_id,
        MembershipNoticeState::Left,
    )
    .await
}

pub(crate) async fn announce_all_local_identified_memberships(
    registry: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: &(impl MailboxTransport + ?Sized),
    signing_key: &ed25519_dalek::SigningKey,
) {
    let sessions = {
        let registry = registry.lock().await;
        registry
            .sessions
            .values()
            .filter(|session| !session.anonymous_group)
            .cloned()
            .collect::<Vec<_>>()
    };

    for session in sessions {
        let now_ms = current_unix_ts_ms();
        let announce_due = {
            let registry = registry.lock().await;
            registry.mailbox_transport_due(&session.group_id, now_ms)
        };
        if !announce_due {
            continue;
        }
        let Ok(local_profile) = local_member_profile(&session) else {
            continue;
        };
        match announce_local_identified_membership(
            registry,
            transport,
            signing_key,
            &local_profile,
            &session.group_id,
        )
        .await
        {
            Ok(_) => {
                let mut registry = registry.lock().await;
                registry.note_mailbox_transport_success(&session.group_id);
            }
            Err(error) => {
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
                    let group_log_id = redacted_log_marker("group", &session.group_id);
                    tracing::debug!(
                        group_id = %group_log_id,
                        retry_in_ms = failure.next_retry_after_ms,
                        consecutive_failures = failure.failures,
                        %error,
                        "Failed to announce mailbox membership during runtime startup"
                    );
                }
            }
        }
    }
}

pub(crate) fn spawn_startup_identified_membership_announcements<T>(
    registry: Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    transport: Arc<T>,
    signing_key: ed25519_dalek::SigningKey,
) -> tokio::task::JoinHandle<()>
where
    T: MailboxTransport + Send + Sync + 'static,
{
    tokio::spawn(async move {
        announce_all_local_identified_memberships(&registry, transport.as_ref(), &signing_key)
            .await;
    })
}

pub(crate) fn decode_group_mailbox_message_payload(
    session: &GroupMailboxSession,
    message: &GroupMailboxMessage,
) -> Result<Vec<u8>> {
    let decoded =
        decode_group_mailbox_message_with_context(&crypto_context_for_session(session), message)?;
    match decoded.kind {
        Some(_) => Ok(decoded.payload),
        None => bail!("Cover traffic does not carry an application payload"),
    }
}

pub(crate) fn decode_group_inline_blob(
    session: &GroupMailboxSession,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    open_bytes(session, "inline-file", sealed)
}

pub(crate) fn decode_group_inline_blob_with_context(
    context: &GroupMailboxCryptoContext,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    open_bytes_with_context(context, "inline-file", sealed)
}

pub(crate) fn describe_group(session: &GroupMailboxSession) -> String {
    session
        .group_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| session.group_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mailbox_transport::MailboxPollResult;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct BlockingMailboxTransport {
        post_calls: Arc<AtomicUsize>,
        post_started: Arc<AtomicBool>,
        post_started_notify: Arc<tokio::sync::Notify>,
        release_post: Arc<tokio::sync::Notify>,
    }

    impl BlockingMailboxTransport {
        async fn wait_until_post_starts(&self) {
            if self.post_started.load(Ordering::SeqCst) {
                return;
            }
            self.post_started_notify.notified().await;
        }

        fn release(&self) {
            self.release_post.notify_waiters();
        }
    }

    #[async_trait]
    impl MailboxTransport for BlockingMailboxTransport {
        async fn post_message(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            _message: &GroupMailboxMessage,
        ) -> Result<MailboxPostReceipt> {
            self.post_calls.fetch_add(1, Ordering::SeqCst);
            self.post_started.store(true, Ordering::SeqCst);
            self.post_started_notify.notify_waiters();
            self.release_post.notified().await;
            Ok(MailboxPostReceipt {
                message_id: "blocked-startup-post".to_string(),
                server_cursor: Some("0".to_string()),
            })
        }

        async fn poll_messages(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            _request: &MailboxPollRequest,
        ) -> Result<MailboxPollResult> {
            Ok(MailboxPollResult {
                items: Vec::new(),
                next_cursor: None,
            })
        }

        async fn ack_messages(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            _envelope_ids: &[String],
        ) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn startup_membership_announcements_run_in_background() {
        let owner = AgentKeyPair::generate("agent1", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_startup_background",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();

        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        registry.lock().await.insert_session(session).unwrap();

        let transport = Arc::new(BlockingMailboxTransport::default());
        let handle = spawn_startup_identified_membership_announcements(
            Arc::clone(&registry),
            Arc::clone(&transport),
            owner.signing_key.clone(),
        );

        tokio::time::timeout(
            Duration::from_millis(200),
            transport.wait_until_post_starts(),
        )
        .await
        .expect("startup announce should begin promptly");
        assert_eq!(transport.post_calls.load(Ordering::SeqCst), 1);
        assert!(
            !handle.is_finished(),
            "startup helper should not block the caller while mailbox post is pending"
        );

        transport.release();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("background startup announce should finish after release")
            .expect("startup announce task should not panic");
    }
}

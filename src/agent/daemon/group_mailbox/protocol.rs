use super::*;

pub(crate) fn create_ghost_anonymous_group_with_id_and_bundle(
    group_id: &str,
    group_name: Option<&str>,
    mailbox_descriptor: MailboxDescriptor,
) -> Result<(
    GroupMailboxSession,
    GroupMailboxInvite,
    crate::network::group_invite_bundle::GroupInviteBundle,
)> {
    let now = chrono::Utc::now().timestamp() as u64;
    let now_ms = current_unix_ts_ms();
    let mut mailbox_capability = build_mailbox_capability();
    let content_crypto_state = Some(build_group_content_crypto_state(0));
    let anonymous_writer_state = Some(build_anonymous_group_writer_state(0));
    let session = GroupMailboxSession {
        group_id: group_id.to_string(),
        group_name: trim_group_name(group_name),
        anonymous_group: true,
        join_locked: false,
        mailbox_descriptor: mailbox_descriptor.clone(),
        mailbox_capability: mailbox_capability.clone(),
        content_crypto_state: content_crypto_state.clone(),
        anonymous_writer_state: anonymous_writer_state.clone(),
        local_member_id: None,
        owner_member_id: None,
        persistence: GroupMailboxPersistence::MemoryOnly,
        joined_at: now,
        invite_id: String::new(),
        owner_special_id: Some(format!("gadm_{}", uuid::Uuid::new_v4().simple())),
        mailbox_epoch: 0,
        poll_cursor: None,
        next_cover_traffic_at: Some(next_ghost_anonymous_cover_traffic_at(now_ms)),
        last_real_activity_at: Some(now_ms),
        known_members: HashMap::new(),
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles: Vec::new(),
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let invite = GroupMailboxInvite::generate(
        &signing_key,
        None,
        group_id,
        session.group_name.as_deref(),
        true,
        mailbox_descriptor.clone(),
        mailbox_capability.clone(),
        content_crypto_state,
        anonymous_writer_state,
        now.saturating_add(INVITE_TTL_TOR_SECS),
    )?;
    issue_group_mailbox_bootstrap_token(
        &signing_key,
        MailboxBootstrapScopeKind::Invite,
        &invite.invite_id,
        &mailbox_descriptor,
        &mut mailbox_capability,
        invite.expiry,
    )?;
    let session = GroupMailboxSession {
        mailbox_capability,
        invite_id: invite.invite_id.clone(),
        ..session
    };
    let bundle = build_group_invite_bundle_from_session(&signing_key, &invite, &session)?;
    validate_group_mailbox_session(&session)?;
    Ok((session, invite, bundle))
}

pub(crate) fn create_ghost_anonymous_group_with_id(
    group_id: &str,
    group_name: Option<&str>,
    mailbox_descriptor: MailboxDescriptor,
) -> Result<(GroupMailboxSession, GroupMailboxInvite)> {
    let (session, invite, _) =
        create_ghost_anonymous_group_with_id_and_bundle(group_id, group_name, mailbox_descriptor)?;
    Ok((session, invite))
}

pub(crate) fn create_ghost_anonymous_group(
    group_name: Option<&str>,
    mailbox_descriptor: MailboxDescriptor,
) -> Result<(GroupMailboxSession, GroupMailboxInvite)> {
    let group_id = mailbox_namespace_group_label(&mailbox_descriptor.namespace).to_string();
    create_ghost_anonymous_group_with_id(&group_id, group_name, mailbox_descriptor)
}

pub(crate) fn write_canonical_str(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

pub(crate) fn write_canonical_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

pub(crate) fn write_canonical_opt_str(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            buf.push(0x01);
            write_canonical_str(buf, value);
        }
        None => buf.push(0x00),
    }
}

pub(crate) fn write_canonical_group_content_crypto_state(
    buf: &mut Vec<u8>,
    state: &GroupContentCryptoAdvertisedState,
) {
    buf.push(state.version);
    write_canonical_str(buf, state.suite.as_str());
    buf.extend_from_slice(&state.epoch.to_le_bytes());
    write_canonical_str(buf, &state.content_secret_b64);
}

pub(crate) fn write_canonical_opt_group_content_crypto_state(
    buf: &mut Vec<u8>,
    state: Option<&GroupContentCryptoAdvertisedState>,
) {
    match state {
        Some(state) => {
            buf.push(0x01);
            write_canonical_group_content_crypto_state(buf, state);
        }
        None => buf.push(0x00),
    }
}

pub(crate) fn write_canonical_mailbox_descriptor(
    buf: &mut Vec<u8>,
    descriptor: &MailboxDescriptor,
) {
    write_canonical_str(buf, &descriptor.namespace);
    write_canonical_opt_str(buf, descriptor.endpoint.as_deref());
    buf.push(match descriptor.transport {
        MailboxTransportKind::Tor => 0u8,
    });
    buf.extend_from_slice(&descriptor.poll_interval_ms.to_le_bytes());
    buf.extend_from_slice(&(descriptor.max_payload_bytes as u64).to_le_bytes());
}

pub(crate) fn write_canonical_opt_mailbox_descriptor(
    buf: &mut Vec<u8>,
    descriptor: Option<&MailboxDescriptor>,
) {
    match descriptor {
        Some(descriptor) => {
            buf.push(0x01);
            write_canonical_mailbox_descriptor(buf, descriptor);
        }
        None => buf.push(0x00),
    }
}

pub(crate) fn write_canonical_mailbox_capability(
    buf: &mut Vec<u8>,
    capability: &MailboxCapability,
) {
    write_canonical_str(buf, &capability.capability_id);
    write_canonical_str(buf, &capability.access_key_b64);
    write_canonical_str(buf, &capability.auth_token_b64);
    match capability.bootstrap_token.as_ref() {
        Some(token) => {
            buf.push(0x01);
            buf.push(token.version);
            buf.push(match token.scope_kind {
                MailboxBootstrapScopeKind::Invite => 0x01,
                MailboxBootstrapScopeKind::EpochRotation => 0x02,
                MailboxBootstrapScopeKind::ChunkTransfer => 0x03,
            });
            write_canonical_str(buf, &token.scope_id);
            write_canonical_str(buf, &token.namespace);
            write_canonical_str(buf, &token.capability_id);
            write_canonical_str(buf, &token.access_key_sha256);
            write_canonical_str(buf, &token.auth_token_sha256);
            buf.extend_from_slice(&token.issued_at.to_le_bytes());
            buf.extend_from_slice(&token.expires_at.to_le_bytes());
            write_canonical_str(buf, &token.issuer_verifying_key_hex);
            buf.push(token.pow_difficulty_bits);
            write_canonical_str(buf, &token.pow_nonce_hex);
            write_canonical_str(buf, &token.signature_b64);
        }
        None => buf.push(0x00),
    }
}

pub(crate) fn write_canonical_opt_mailbox_capability(
    buf: &mut Vec<u8>,
    capability: Option<&MailboxCapability>,
) {
    match capability {
        Some(capability) => {
            buf.push(0x01);
            write_canonical_mailbox_capability(buf, capability);
        }
        None => buf.push(0x00),
    }
}

pub(crate) fn issue_group_mailbox_bootstrap_token(
    signing_key: &ed25519_dalek::SigningKey,
    scope_kind: MailboxBootstrapScopeKind,
    scope_id: &str,
    descriptor: &MailboxDescriptor,
    capability: &mut MailboxCapability,
    expires_at: u64,
) -> Result<()> {
    capability.bootstrap_token = Some(issue_mailbox_bootstrap_token(
        signing_key,
        scope_kind,
        scope_id,
        &descriptor.namespace,
        capability,
        expires_at,
    )?);
    Ok(())
}

pub(crate) fn derive_did_from_verifying_key_hex(verifying_key_hex: &str) -> Result<String> {
    let verifying_key_bytes =
        hex::decode(verifying_key_hex).context("Invalid member verifying key hex")?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Member verifying key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&verifying_key_bytes).context("Invalid Ed25519 verifying key")?;
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    Ok(format!("did:nxf:{}", hex::encode(hasher.finalize())))
}

pub(crate) fn parse_x25519_public_key_hex(public_key_hex: &str) -> Result<[u8; 32]> {
    let public_key = hex::decode(public_key_hex).context("Invalid X25519 public key hex")?;
    public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 public key must be 32 bytes"))
}

pub(crate) fn membership_notice_state_label(state: MembershipNoticeState) -> &'static str {
    match state {
        MembershipNoticeState::Joined => "joined",
        MembershipNoticeState::Left => "left",
    }
}

pub(crate) fn membership_notice_signing_data_v1(payload: &MembershipNoticePayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(b"Qypha-GroupMembershipNotice-v1:");
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.member_id);
    write_canonical_str(&mut data, &payload.display_name);
    write_canonical_str(&mut data, &payload.verifying_key_hex);
    write_canonical_str(&mut data, &payload.encryption_public_key_hex);
    write_canonical_opt_str(&mut data, payload.kyber_public_key_hex.as_deref());
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn membership_notice_signing_data(payload: &MembershipNoticePayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(544);
    data.extend_from_slice(b"Qypha-GroupMembershipNotice-v2:");
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.member_id);
    write_canonical_str(&mut data, &payload.display_name);
    write_canonical_str(&mut data, &payload.verifying_key_hex);
    write_canonical_str(&mut data, &payload.encryption_public_key_hex);
    write_canonical_opt_str(&mut data, payload.kyber_public_key_hex.as_deref());
    write_canonical_str(&mut data, membership_notice_state_label(payload.state));
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn authenticated_group_mailbox_payload_signing_data(
    payload: &AuthenticatedGroupMailboxPayload,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(payload.payload.len().saturating_add(256));
    data.extend_from_slice(b"Qypha-GroupAuthenticatedPayload-v1:");
    data.push(payload.version);
    write_canonical_str(&mut data, kind_label(&payload.kind));
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.sender_member_id);
    write_canonical_str(&mut data, &payload.sender_verifying_key_hex);
    data.extend_from_slice(&payload.mailbox_epoch.to_le_bytes());
    write_canonical_str(&mut data, &payload.message_id);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data.extend_from_slice(&payload.created_at_ms.to_le_bytes());
    write_canonical_bytes(&mut data, &payload.payload);
    data
}

pub(crate) fn anonymous_authenticated_mailbox_payload_auth_data(
    payload: &AnonymousAuthenticatedMailboxPayload,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(payload.payload.len().saturating_add(192));
    data.extend_from_slice(b"Qypha-AnonymousGroupWriter-v1:");
    data.push(payload.version);
    write_canonical_str(&mut data, kind_label(&payload.kind));
    write_canonical_str(&mut data, &payload.group_id);
    data.extend_from_slice(&payload.mailbox_epoch.to_le_bytes());
    write_canonical_str(&mut data, &payload.message_id);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data.extend_from_slice(&payload.created_at_ms.to_le_bytes());
    write_canonical_bytes(&mut data, &payload.payload);
    data
}

pub(crate) fn kind_uses_authenticated_group_envelope(kind: &GroupMailboxMessageKind) -> bool {
    matches!(
        kind,
        GroupMailboxMessageKind::Chat
            | GroupMailboxMessageKind::FileManifest
            | GroupMailboxMessageKind::FileChunkData
            | GroupMailboxMessageKind::FileChunkComplete
            | GroupMailboxMessageKind::FastFileOffer
            | GroupMailboxMessageKind::FastFileStatus
    )
}

pub(crate) fn kind_uses_anonymous_writer_envelope(kind: &GroupMailboxMessageKind) -> bool {
    matches!(
        kind,
        GroupMailboxMessageKind::Chat
            | GroupMailboxMessageKind::FileManifest
            | GroupMailboxMessageKind::FileChunkData
            | GroupMailboxMessageKind::FileChunkComplete
    )
}

pub(crate) fn wrap_anonymous_group_mailbox_payload(
    session: &GroupMailboxSession,
    kind: GroupMailboxMessageKind,
    message_id: &str,
    created_at: u64,
    created_at_ms: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if !session.anonymous_group
        || session.anonymous_writer_state.is_none()
        || !kind_uses_anonymous_writer_envelope(&kind)
    {
        return Ok(payload.to_vec());
    }
    let content_state = session.content_crypto_state.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Anonymous v2 group payload is missing content crypto state")
    })?;
    let writer_state = session
        .anonymous_writer_state
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Anonymous v2 group payload is missing writer state"))?;
    validate_anonymous_group_state_pair(
        true,
        &session.group_id,
        Some(content_state),
        Some(writer_state),
    )?;
    if content_state.epoch != session.mailbox_epoch || writer_state.epoch != session.mailbox_epoch {
        bail!("Anonymous group epoch state is out of sync with mailbox epoch");
    }
    let mut envelope = AnonymousAuthenticatedMailboxPayload {
        version: 1,
        kind,
        group_id: session.group_id.clone(),
        mailbox_epoch: session.mailbox_epoch,
        message_id: message_id.to_string(),
        created_at,
        created_at_ms,
        payload: payload.to_vec(),
        auth_tag: Vec::new(),
    };
    let mut auth_key =
        derive_anonymous_writer_auth_key(writer_state, &session.group_id, "group_message")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&auth_key)
        .map_err(|_| anyhow::anyhow!("Anonymous group writer auth key rejected"))?;
    mac.update(&anonymous_authenticated_mailbox_payload_auth_data(
        &envelope,
    ));
    envelope.auth_tag = mac.finalize().into_bytes().to_vec();
    auth_key.zeroize();
    serde_json::to_vec(&envelope).context("Failed to encode anonymous authenticated payload")
}

pub(crate) fn wrap_authenticated_group_mailbox_payload(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    kind: GroupMailboxMessageKind,
    message_id: &str,
    created_at: u64,
    created_at_ms: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if session.anonymous_group
        || session.content_crypto_state.is_none()
        || !kind_uses_authenticated_group_envelope(&kind)
    {
        return Ok(payload.to_vec());
    }
    if session.local_member_id.as_deref() != Some(sender_profile.member_id.as_str()) {
        bail!("Authenticated group sender/profile mismatch");
    }
    let mut envelope = AuthenticatedGroupMailboxPayload {
        version: 1,
        kind,
        group_id: session.group_id.clone(),
        sender_member_id: sender_profile.member_id.clone(),
        sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
        mailbox_epoch: session.mailbox_epoch,
        message_id: message_id.to_string(),
        created_at,
        created_at_ms,
        payload: payload.to_vec(),
        signature: Vec::new(),
    };
    envelope.signature = signing_key
        .sign(&authenticated_group_mailbox_payload_signing_data(&envelope))
        .to_bytes()
        .to_vec();
    serde_json::to_vec(&envelope).context("Failed to encode authenticated group payload")
}

pub(crate) fn unwrap_anonymous_group_mailbox_payload(
    context: &GroupMailboxCryptoContext,
    kind: GroupMailboxMessageKind,
    message: &GroupMailboxMessage,
    payload_bytes: &[u8],
) -> Result<DecodedGroupMailboxMessage> {
    if !context.anonymous_group || !kind_uses_anonymous_writer_envelope(&kind) {
        return Ok(DecodedGroupMailboxMessage {
            kind: Some(kind),
            payload: payload_bytes.to_vec(),
            authenticated_sender: None,
        });
    }
    match (
        context.content_crypto_state.as_ref(),
        context.anonymous_writer_state.as_ref(),
    ) {
        (None, None) => {
            return Ok(DecodedGroupMailboxMessage {
                kind: Some(kind),
                payload: payload_bytes.to_vec(),
                authenticated_sender: None,
            });
        }
        (Some(_), Some(_)) => validate_anonymous_group_state_pair(
            true,
            &context.group_id,
            context.content_crypto_state.as_ref(),
            context.anonymous_writer_state.as_ref(),
        )?,
        _ => {
            bail!("Anonymous mailbox payload is missing required v2 writer/content state");
        }
    }
    let writer_state = context
        .anonymous_writer_state
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Anonymous mailbox payload missing writer state"))?;
    let envelope: AnonymousAuthenticatedMailboxPayload =
        serde_json::from_slice(payload_bytes).context("Invalid anonymous authenticated payload")?;
    if envelope.version != 1 {
        bail!("Unsupported anonymous authenticated payload version");
    }
    if envelope.kind != kind {
        bail!("Anonymous authenticated payload kind mismatch");
    }
    if envelope.group_id != context.group_id {
        bail!("Anonymous authenticated payload group_id mismatch");
    }
    if envelope.mailbox_epoch != writer_state.epoch {
        bail!("Anonymous authenticated payload epoch mismatch");
    }
    if envelope.message_id != message.message_id {
        bail!("Anonymous authenticated payload message_id mismatch");
    }
    if envelope.created_at != message.created_at || envelope.created_at_ms != message.created_at_ms
    {
        bail!("Anonymous authenticated payload timestamp mismatch");
    }
    let mut auth_key =
        derive_anonymous_writer_auth_key(writer_state, &context.group_id, "group_message")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&auth_key)
        .map_err(|_| anyhow::anyhow!("Anonymous group writer auth key rejected"))?;
    mac.update(&anonymous_authenticated_mailbox_payload_auth_data(
        &envelope,
    ));
    mac.verify_slice(&envelope.auth_tag)
        .map_err(|_| anyhow::anyhow!("Anonymous authenticated payload auth tag invalid"))?;
    auth_key.zeroize();
    Ok(DecodedGroupMailboxMessage {
        kind: Some(kind),
        payload: envelope.payload,
        authenticated_sender: None,
    })
}

pub(crate) fn unwrap_authenticated_group_mailbox_payload(
    context: &GroupMailboxCryptoContext,
    message: &GroupMailboxMessage,
    payload_bytes: &[u8],
) -> Result<DecodedGroupMailboxMessage> {
    if context.anonymous_group
        || context.content_crypto_state.is_none()
        || !kind_uses_authenticated_group_envelope(&message.kind)
    {
        return Ok(DecodedGroupMailboxMessage {
            kind: Some(message.kind.clone()),
            payload: payload_bytes.to_vec(),
            authenticated_sender: None,
        });
    }
    let envelope: AuthenticatedGroupMailboxPayload =
        serde_json::from_slice(payload_bytes).context("Invalid authenticated group payload")?;
    if envelope.version != 1 {
        bail!("Unsupported authenticated group payload version");
    }
    if envelope.kind != message.kind {
        bail!("Authenticated group payload kind mismatch");
    }
    if envelope.group_id != context.group_id {
        bail!("Authenticated group payload group_id mismatch");
    }
    if message.sender_member_id.as_deref() != Some(envelope.sender_member_id.as_str()) {
        bail!("Authenticated group payload sender mismatch");
    }
    if envelope.message_id != message.message_id {
        bail!("Authenticated group payload message_id mismatch");
    }
    if envelope.created_at != message.created_at || envelope.created_at_ms != message.created_at_ms
    {
        bail!("Authenticated group payload timestamp mismatch");
    }
    let expected_did = derive_did_from_verifying_key_hex(&envelope.sender_verifying_key_hex)?;
    if expected_did != envelope.sender_member_id {
        bail!("Authenticated group payload DID/verifying key mismatch");
    }
    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|_| anyhow::anyhow!("Invalid authenticated group payload signature"))?;
    let verifying_key_bytes = hex::decode(&envelope.sender_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Authenticated group verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid authenticated group Ed25519 verifying key")?;
    verifying_key
        .verify_strict(
            &authenticated_group_mailbox_payload_signing_data(&envelope),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("Authenticated group payload signature invalid"))?;
    Ok(DecodedGroupMailboxMessage {
        kind: Some(message.kind.clone()),
        payload: envelope.payload,
        authenticated_sender: Some(AuthenticatedGroupMailboxSender {
            member_id: envelope.sender_member_id,
            verifying_key_hex: envelope.sender_verifying_key_hex,
        }),
    })
}

pub(crate) fn group_disband_signing_data(payload: &GroupDisbandPayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(384);
    data.extend_from_slice(b"Qypha-GroupDisband-v1:");
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.owner_member_id);
    write_canonical_str(&mut data, &payload.owner_verifying_key_hex);
    data.extend_from_slice(&payload.mailbox_epoch.to_le_bytes());
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn direct_handshake_offer_signing_data(
    payload: &DirectHandshakeOfferPayload,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(b"Qypha-GroupDirectHandshakeOffer-v1:");
    write_canonical_str(&mut data, &payload.offer_id);
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.sender_member_id);
    write_canonical_str(&mut data, &payload.sender_verifying_key_hex);
    write_canonical_str(&mut data, &payload.target_member_id);
    write_canonical_bytes(&mut data, &payload.encrypted_invite_envelope);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn encode_direct_handshake_offer_payload(
    payload: &DirectHandshakeOfferPayload,
) -> Result<Vec<u8>> {
    bincode::serialize(payload).context("Failed to encode direct handshake offer payload")
}

pub(crate) fn decode_direct_handshake_offer_payload_bytes(
    bytes: &[u8],
) -> Result<DirectHandshakeOfferPayload> {
    match bincode::deserialize(bytes) {
        Ok(payload) => Ok(payload),
        Err(_) => {
            serde_json::from_slice(bytes).context("Failed to decode direct handshake offer payload")
        }
    }
}

pub(crate) fn decode_direct_handshake_offer_envelope(bytes: &[u8]) -> Result<EncryptedEnvelope> {
    match bincode::deserialize(bytes) {
        Ok(envelope) => Ok(envelope),
        Err(_) => serde_json::from_slice(bytes).context("Invalid direct invite envelope"),
    }
}

pub(crate) fn mailbox_rotation_signing_data(payload: &MailboxRotationPayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(1024);
    data.extend_from_slice(b"Qypha-GroupMailboxRotation-v1:");
    write_canonical_str(&mut data, &payload.rotation_id);
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.sender_member_id);
    write_canonical_str(&mut data, &payload.sender_verifying_key_hex);
    write_canonical_str(&mut data, &payload.target_member_id);
    write_canonical_str(&mut data, &payload.kicked_member_id);
    data.extend_from_slice(&payload.new_mailbox_epoch.to_le_bytes());
    if payload.target_member_id.is_empty()
        || payload.public_mailbox_descriptor.is_some()
        || payload.public_mailbox_capability.is_some()
        || payload.public_content_crypto_state.is_some()
    {
        data.push(u8::from(payload.join_locked));
        write_canonical_opt_mailbox_descriptor(
            &mut data,
            payload.public_mailbox_descriptor.as_ref(),
        );
        write_canonical_opt_mailbox_capability(
            &mut data,
            payload.public_mailbox_capability.as_ref(),
        );
        write_canonical_opt_group_content_crypto_state(
            &mut data,
            payload.public_content_crypto_state.as_ref(),
        );
    }
    write_canonical_str(&mut data, &payload.encrypted_session_bundle_b64);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn verify_mailbox_rotation_visibility(
    payload: &MailboxRotationPayload,
    outer_sender_member_id: Option<&str>,
    current_group_id: &str,
    expected_owner_verifying_key_hex: &str,
) -> Result<()> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.sender_verifying_key_hex)?;
    if expected_did != payload.sender_member_id {
        bail!("Mailbox rotation DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.sender_member_id.as_str())
    {
        bail!("Mailbox rotation sender_member_id mismatch");
    }
    if payload.group_id != current_group_id {
        bail!("Mailbox rotation group_id mismatch");
    }
    if payload.sender_verifying_key_hex != expected_owner_verifying_key_hex {
        bail!("Mailbox rotation was not signed by the invite owner");
    }
    if let Some(state) = payload.public_content_crypto_state.as_ref() {
        validate_group_content_crypto_state(state, current_group_id)?;
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid mailbox rotation signature"))?;
    let verifying_key_bytes = hex::decode(&payload.sender_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Mailbox rotation verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid mailbox rotation Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&mailbox_rotation_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Mailbox rotation signature invalid"))?;
    Ok(())
}

pub(crate) fn fast_file_accept_signing_data(payload: &GroupFastFileAcceptPayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(b"Qypha-GroupFastFileAccept-v1:");
    write_canonical_str(&mut data, &payload.transfer_id);
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.recipient_member_id);
    write_canonical_str(&mut data, &payload.recipient_verifying_key_hex);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn fast_file_grant_signing_data(payload: &GroupFastFileGrantPayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(1024);
    data.extend_from_slice(b"Qypha-GroupFastFileGrant-v1:");
    write_canonical_str(&mut data, &payload.grant_id);
    write_canonical_str(&mut data, &payload.transfer_id);
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.sender_member_id);
    write_canonical_str(&mut data, &payload.recipient_member_id);
    write_canonical_str(&mut data, &payload.sender_verifying_key_hex);
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data.extend_from_slice(&payload.expires_at.to_le_bytes());
    write_canonical_bytes(&mut data, &payload.encrypted_grant_envelope);
    data
}

pub(crate) fn build_local_member_profile(
    keypair: &AgentKeyPair,
    display_name: &str,
) -> GroupMailboxMemberProfile {
    GroupMailboxMemberProfile {
        member_id: keypair.did.clone(),
        display_name: display_name.trim().to_string(),
        verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
        encryption_public_key_hex: hex::encode(keypair.x25519_public_key_bytes()),
        kyber_public_key_hex: (!keypair.kyber_public.is_empty())
            .then(|| hex::encode(&keypair.kyber_public)),
    }
}

pub(crate) fn derive_group_mailbox_persist_key(keypair: &AgentKeyPair) -> [u8; 32] {
    let mut signing_key = keypair.signing_key.to_bytes();
    let mut encryption_secret = keypair.x25519_secret_key_bytes();
    let mut material = Vec::with_capacity(signing_key.len() + encryption_secret.len());
    material.extend_from_slice(&signing_key);
    material.extend_from_slice(&encryption_secret);
    signing_key.zeroize();
    encryption_secret.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-GroupMailbox-Persist-Key-v1"), &material);
    material.zeroize();
    let mut key = [0u8; 32];
    hk.expand(keypair.did.as_bytes(), &mut key)
        .expect("HKDF expand for mailbox persistence key should not fail");
    key
}

pub(crate) fn local_member_profile(
    session: &GroupMailboxSession,
) -> Result<GroupMailboxMemberProfile> {
    let local_member_id = session
        .local_member_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Mailbox group is missing local member id"))?;
    session
        .known_members
        .get(local_member_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Local mailbox member profile is not known yet"))
}

pub(crate) fn stage_sender_fast_file_transfer_from_prepared(
    registry: &mut GroupMailboxRegistry,
    session: &GroupMailboxSession,
    manifest: &GroupFileManifestPayload,
    prepared: PreparedFastGroupTransfer,
    endpoint_addr_json: String,
    endpoint_verifying_key_hex: String,
) -> Result<Option<String>> {
    if session.anonymous_group {
        secure_wipe_file(&prepared.packed_path);
        return Ok(None);
    }
    let Some(transfer_id) = manifest.fast_transfer_id.clone() else {
        secure_wipe_file(&prepared.packed_path);
        return Ok(None);
    };
    let Some(expires_at) = manifest.fast_transfer_expires_at else {
        secure_wipe_file(&prepared.packed_path);
        return Ok(None);
    };
    let local_member_id = session
        .local_member_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Identified mailbox group is missing local member id"))?;
    let manifest_bytes =
        serde_json::to_vec(manifest).context("Failed to encode staged fast file manifest")?;
    let file_manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
    registry.stage_fast_file_transfer(GroupStagedFastFileTransfer {
        transfer_id: transfer_id.clone(),
        mailbox_transfer_id: prepared.mailbox_transfer_id,
        manifest_id: manifest.manifest_id.clone(),
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        sender_member_id: local_member_id,
        filename: prepared.filename,
        size_bytes: prepared.size_bytes,
        file_manifest_hash,
        plaintext_sha256: prepared.plaintext_sha256,
        merkle_root: prepared.merkle_root,
        total_chunks: prepared.total_chunks,
        chunk_size: prepared.chunk_size,
        relay_only: prepared.relay_only,
        endpoint_addr_json,
        endpoint_verifying_key_hex,
        expires_at,
        packed_path: prepared.packed_path,
        fast_session: prepared.fast_session,
    });
    Ok(Some(transfer_id))
}

pub(crate) fn build_fast_file_accept_message(
    session: &GroupMailboxSession,
    keypair: &AgentKeyPair,
    transfer_id: &str,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support fast file accept");
    }
    let local_profile = local_member_profile(session)?;
    let mut payload = GroupFastFileAcceptPayload {
        transfer_id: transfer_id.to_string(),
        group_id: session.group_id.clone(),
        recipient_member_id: local_profile.member_id.clone(),
        recipient_verifying_key_hex: local_profile.verifying_key_hex.clone(),
        created_at: current_unix_ts(),
        signature: Vec::new(),
    };
    payload.signature = keypair
        .signing_key
        .sign(&fast_file_accept_signing_data(&payload))
        .to_bytes()
        .to_vec();
    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode fast file accept payload")?;
    build_group_mailbox_message(
        session,
        Some(&keypair.signing_key),
        Some(&local_profile),
        GroupMailboxMessageKind::FastFileAccept,
        "message/fast_file_accept",
        &payload_bytes,
        ttl_ms,
    )
}

pub(crate) fn build_fast_file_offer_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    offer: &GroupFastFileOfferPayload,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support fast file offers");
    }
    let payload_bytes =
        serde_json::to_vec(offer).context("Failed to encode fast file offer payload")?;
    build_group_mailbox_message(
        session,
        Some(signing_key),
        Some(sender_profile),
        GroupMailboxMessageKind::FastFileOffer,
        "message/fast_file_offer",
        &payload_bytes,
        ttl_ms,
    )
}

pub(crate) fn decrypt_fast_file_accept_payload(
    payload: &GroupFastFileAcceptPayload,
    outer_sender_member_id: Option<&str>,
    current_group_id: &str,
) -> Result<String> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.recipient_verifying_key_hex)?;
    if expected_did != payload.recipient_member_id {
        bail!("Fast file accept DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.recipient_member_id.as_str())
    {
        bail!("Fast file accept sender_member_id mismatch");
    }
    if payload.group_id != current_group_id {
        bail!("Fast file accept group_id mismatch");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid fast file accept signature"))?;
    let verifying_key_bytes = hex::decode(&payload.recipient_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Fast file accept verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid fast file accept Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&fast_file_accept_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Fast file accept signature invalid"))?;
    Ok(payload.recipient_member_id.clone())
}

pub(crate) fn build_fast_file_grant_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    target_profile: &GroupMailboxMemberProfile,
    staged: &GroupStagedFastFileTransfer,
    ttl_ms: u64,
) -> Result<(
    GroupMailboxMessage,
    GroupFastFileGrantPayload,
    GroupFastFileGrantSecret,
)> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support fast file grants");
    }
    if sender_profile.member_id == target_profile.member_id {
        bail!("Fast file grant target must be a different member");
    }
    let recipient_x25519 = parse_x25519_public_key_hex(&target_profile.encryption_public_key_hex)?;
    let recipient_kyber = target_profile
        .kyber_public_key_hex
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Fast file grant target missing Kyber mailbox profile"))?;
    let recipient_kyber =
        hex::decode(recipient_kyber).context("Invalid fast file grant target Kyber public key")?;
    let grant_expires_at = group_fast_file_grant_expires_at(staged.expires_at);
    let secret = GroupFastFileGrantSecret {
        transfer_id: staged.transfer_id.clone(),
        group_id: staged.group_id.clone(),
        mailbox_transfer_id: staged.mailbox_transfer_id.clone(),
        recipient_did: target_profile.member_id.clone(),
        ticket_id: format!("gfticket_{}", uuid::Uuid::new_v4().simple()),
        relay_only: staged.relay_only,
        endpoint_addr_json: staged.endpoint_addr_json.clone(),
        expires_at: grant_expires_at,
    };
    let secret_bytes =
        bincode::serialize(&secret).context("Failed to encode fast file grant secret")?;
    let envelope = hybrid_encrypt_message(
        &recipient_x25519,
        Some(recipient_kyber.as_slice()),
        &secret_bytes,
    )?;
    let envelope_bytes =
        bincode::serialize(&envelope).context("Failed to encode fast file grant envelope")?;
    let mut payload = GroupFastFileGrantPayload {
        grant_id: format!("gfgrant_{}", uuid::Uuid::new_v4().simple()),
        transfer_id: staged.transfer_id.clone(),
        group_id: session.group_id.clone(),
        sender_member_id: sender_profile.member_id.clone(),
        recipient_member_id: target_profile.member_id.clone(),
        sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
        created_at: current_unix_ts(),
        expires_at: grant_expires_at,
        encrypted_grant_envelope: envelope_bytes,
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&fast_file_grant_signing_data(&payload))
        .to_bytes()
        .to_vec();
    let payload_bytes =
        bincode::serialize(&payload).context("Failed to encode fast file grant payload")?;
    let message = build_group_mailbox_message(
        session,
        Some(signing_key),
        Some(sender_profile),
        GroupMailboxMessageKind::FastFileGrant,
        "message/fast_file_grant",
        &payload_bytes,
        ttl_ms,
    )?;
    Ok((message, payload, secret))
}

pub(crate) fn decrypt_fast_file_grant_payload(
    payload: &GroupFastFileGrantPayload,
    keypair: &AgentKeyPair,
    outer_sender_member_id: Option<&str>,
    local_member_id: &str,
    current_group_id: &str,
) -> Result<(String, GroupFastFileGrantSecret)> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.sender_verifying_key_hex)?;
    if expected_did != payload.sender_member_id {
        bail!("Fast file grant DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.sender_member_id.as_str())
    {
        bail!("Fast file grant sender_member_id mismatch");
    }
    if payload.group_id != current_group_id {
        bail!("Fast file grant group_id mismatch");
    }
    if payload.recipient_member_id != local_member_id {
        bail!("Fast file grant is not targeted to this member");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid fast file grant signature"))?;
    let verifying_key_bytes = hex::decode(&payload.sender_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Fast file grant verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid fast file grant Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&fast_file_grant_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Fast file grant signature invalid"))?;

    let envelope: EncryptedEnvelope = bincode::deserialize(&payload.encrypted_grant_envelope)
        .context("Invalid fast file grant envelope")?;
    let secret = hybrid_decrypt_message(
        &keypair.x25519_secret_key_bytes(),
        (!keypair.kyber_secret.is_empty()).then_some(keypair.kyber_secret.as_slice()),
        &envelope,
    )?;
    let secret: GroupFastFileGrantSecret =
        bincode::deserialize(&secret).context("Invalid fast file grant secret")?;
    if secret.transfer_id != payload.transfer_id {
        bail!("Fast file grant secret transfer_id mismatch");
    }
    if secret.group_id != payload.group_id {
        bail!("Fast file grant secret group_id mismatch");
    }
    if secret.recipient_did != local_member_id {
        bail!("Fast file grant secret recipient mismatch");
    }
    if secret.expires_at != payload.expires_at {
        bail!("Fast file grant expiry mismatch");
    }
    Ok((payload.sender_member_id.clone(), secret))
}

pub(crate) fn rotated_mailbox_namespace(group_id: &str, mailbox_epoch: u64) -> String {
    format!(
        "mailbox:{group_id}:epoch:{mailbox_epoch}:slot:{}",
        uuid::Uuid::new_v4().simple()
    )
}

pub(crate) fn create_identified_group(
    signing_key: &ed25519_dalek::SigningKey,
    issuer_did: &str,
    group_name: Option<&str>,
    mailbox_descriptor: MailboxDescriptor,
    persistence: GroupMailboxPersistence,
    local_profile: GroupMailboxMemberProfile,
) -> Result<(GroupMailboxSession, GroupMailboxInvite)> {
    let now = chrono::Utc::now().timestamp() as u64;
    let group_id = mailbox_namespace_group_label(&mailbox_descriptor.namespace).to_string();
    let mut mailbox_capability = build_mailbox_capability();
    let content_crypto_state = Some(build_group_content_crypto_state(0));
    let mut known_members = HashMap::new();
    known_members.insert(local_profile.member_id.clone(), local_profile.clone());
    let session = GroupMailboxSession {
        group_id: group_id.clone(),
        group_name: trim_group_name(group_name),
        anonymous_group: false,
        join_locked: false,
        mailbox_descriptor: mailbox_descriptor.clone(),
        mailbox_capability: mailbox_capability.clone(),
        content_crypto_state: content_crypto_state.clone(),
        anonymous_writer_state: None,
        local_member_id: Some(local_profile.member_id.clone()),
        owner_member_id: Some(local_profile.member_id.clone()),
        persistence,
        joined_at: now,
        invite_id: String::new(),
        owner_special_id: None,
        mailbox_epoch: 0,
        poll_cursor: None,
        next_cover_traffic_at: None,
        last_real_activity_at: None,
        known_members,
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles: Vec::new(),
    };
    let invite = GroupMailboxInvite::generate(
        signing_key,
        Some(issuer_did),
        &group_id,
        session.group_name.as_deref(),
        false,
        mailbox_descriptor.clone(),
        mailbox_capability.clone(),
        content_crypto_state,
        None,
        now.saturating_add(INVITE_TTL_TOR_SECS),
    )?;
    issue_group_mailbox_bootstrap_token(
        signing_key,
        MailboxBootstrapScopeKind::Invite,
        &invite.invite_id,
        &mailbox_descriptor,
        &mut mailbox_capability,
        invite.expiry,
    )?;
    let session = GroupMailboxSession {
        mailbox_capability,
        invite_id: invite.invite_id.clone(),
        ..session
    };
    validate_group_mailbox_session(&session)?;
    Ok((session, invite))
}

pub(crate) fn regenerate_identified_group_invite(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    issuer_did: &str,
) -> Result<GroupMailboxInvite> {
    if session.anonymous_group {
        bail!("Identified group invite regeneration requires a non-anonymous mailbox group");
    }
    if session.join_locked {
        bail!("Mailbox group is locked. Use /unlock_g before generating a new invite");
    }
    let now = chrono::Utc::now().timestamp() as u64;
    GroupMailboxInvite::generate(
        signing_key,
        Some(issuer_did),
        &session.group_id,
        session.group_name.as_deref(),
        false,
        session.mailbox_descriptor.clone(),
        session.mailbox_capability.clone(),
        session.content_crypto_state.clone(),
        None,
        now.saturating_add(INVITE_TTL_TOR_SECS),
    )
}

pub(crate) fn build_group_invite_bundle_from_session(
    signing_key: &ed25519_dalek::SigningKey,
    invite: &GroupMailboxInvite,
    session: &GroupMailboxSession,
) -> Result<crate::network::group_invite_bundle::GroupInviteBundle> {
    let mut mailbox_capability = session.mailbox_capability.clone();
    issue_group_mailbox_bootstrap_token(
        signing_key,
        MailboxBootstrapScopeKind::Invite,
        &invite.invite_id,
        &session.mailbox_descriptor,
        &mut mailbox_capability,
        invite.expiry,
    )?;
    crate::network::group_invite_bundle::GroupInviteBundle::from_group_invite(
        signing_key,
        invite,
        session.group_name.as_deref(),
        session.join_locked,
        session.mailbox_descriptor.clone(),
        mailbox_capability,
        session.content_crypto_state.clone(),
        session.anonymous_writer_state.clone(),
        session.owner_member_id.as_deref(),
    )
}

pub(crate) fn derive_mailbox_key(
    capability: &MailboxCapability,
    group_id: &str,
    purpose: &str,
) -> Result<[u8; 32]> {
    let mut access_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(capability.access_key_b64.as_bytes())
        .context("Mailbox access key is not valid base64")?;
    let mut auth_token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(capability.auth_token_b64.as_bytes())
        .context("Mailbox auth token is not valid base64")?;
    let mut material = Vec::with_capacity(access_key.len() + auth_token.len());
    material.extend_from_slice(&access_key);
    material.extend_from_slice(&auth_token);
    access_key.zeroize();
    auth_token.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-GroupMailbox-v1"), &material);
    material.zeroize();
    let mut key = [0u8; 32];
    let info = format!("group_id={group_id};purpose={purpose}");
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("Failed to derive group mailbox key"))?;
    Ok(key)
}

pub(crate) fn validate_group_content_crypto_state(
    state: &GroupContentCryptoAdvertisedState,
    group_id: &str,
) -> Result<()> {
    if state.version != 1 {
        bail!(
            "Mailbox group {} uses unsupported content crypto state version {}",
            group_id,
            state.version
        );
    }
    let mut secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state.content_secret_b64.as_bytes())
        .context("Group content secret is not valid base64")?;
    if secret.len() < 32 {
        secret.zeroize();
        bail!("Group content secret must be at least 32 bytes");
    }
    secret.zeroize();
    Ok(())
}

pub(crate) fn validate_anonymous_group_writer_state(
    state: &AnonymousGroupWriterCredentialAdvertisedState,
    group_id: &str,
) -> Result<()> {
    if state.version != 1 {
        bail!(
            "Anonymous mailbox group {} uses unsupported writer state version {}",
            group_id,
            state.version
        );
    }
    let mut secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state.writer_secret_b64.as_bytes())
        .context("Anonymous group writer secret is not valid base64")?;
    if secret.len() < 32 {
        secret.zeroize();
        bail!("Anonymous group writer secret must be at least 32 bytes");
    }
    secret.zeroize();
    Ok(())
}

pub(crate) fn validate_anonymous_group_state_pair(
    anonymous_group: bool,
    group_id: &str,
    content_state: Option<&GroupContentCryptoAdvertisedState>,
    writer_state: Option<&AnonymousGroupWriterCredentialAdvertisedState>,
) -> Result<()> {
    match (anonymous_group, content_state, writer_state) {
        (false, _, None) => Ok(()),
        (false, _, Some(_)) => bail!(
            "Identified mailbox group {} must not carry anonymous writer state",
            group_id
        ),
        (true, None, None) => Ok(()),
        (true, Some(content_state), Some(writer_state)) => {
            validate_group_content_crypto_state(content_state, group_id)?;
            validate_anonymous_group_writer_state(writer_state, group_id)?;
            if writer_state.epoch != content_state.epoch {
                bail!(
                    "Anonymous mailbox group {} has mismatched content/writer epochs",
                    group_id
                );
            }
            Ok(())
        }
        (true, _, _) => bail!(
            "Anonymous mailbox group {} requires content crypto state and anonymous writer state together",
            group_id
        ),
    }
}

pub(crate) fn derive_content_state_key(
    state: &GroupContentCryptoAdvertisedState,
    group_id: &str,
    purpose: &str,
) -> Result<[u8; 32]> {
    validate_group_content_crypto_state(state, group_id)?;
    let mut secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state.content_secret_b64.as_bytes())
        .context("Group content secret is not valid base64")?;
    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-GroupContent-v1"), &secret);
    secret.zeroize();
    let mut key = [0u8; 32];
    let info = format!(
        "group_id={group_id};epoch={};suite={};purpose={purpose}",
        state.epoch,
        state.suite.as_str()
    );
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("Failed to derive group content key"))?;
    Ok(key)
}

pub(crate) fn derive_anonymous_writer_auth_key(
    state: &AnonymousGroupWriterCredentialAdvertisedState,
    group_id: &str,
    purpose: &str,
) -> Result<[u8; 32]> {
    validate_anonymous_group_writer_state(state, group_id)?;
    let mut secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state.writer_secret_b64.as_bytes())
        .context("Anonymous group writer secret is not valid base64")?;
    let hk = Hkdf::<Sha256>::new(Some(b"Qypha-AnonymousGroupWriter-v1"), &secret);
    secret.zeroize();
    let mut key = [0u8; 32];
    let info = format!(
        "group_id={group_id};epoch={};suite={};purpose={purpose}",
        state.epoch,
        state.suite.as_str()
    );
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("Failed to derive anonymous writer auth key"))?;
    Ok(key)
}

pub(crate) fn sealed_payload_version_for_context(context: &GroupMailboxCryptoContext) -> u8 {
    if context.content_crypto_state.is_some() {
        2
    } else {
        1
    }
}

pub(crate) fn derive_context_key(
    context: &GroupMailboxCryptoContext,
    purpose: &str,
    sealed_version: u8,
) -> Result<[u8; 32]> {
    match sealed_version {
        1 => derive_mailbox_key(&context.mailbox_capability, &context.group_id, purpose),
        2 => {
            let state = context.content_crypto_state.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Mailbox payload is missing content crypto state")
            })?;
            derive_content_state_key(state, &context.group_id, purpose)
        }
        _ => bail!("Unsupported sealed mailbox payload version"),
    }
}

pub(crate) fn aad_for(
    context: &GroupMailboxCryptoContext,
    purpose: &str,
    sealed_version: u8,
) -> Vec<u8> {
    match sealed_version {
        1 => format!(
            "Qypha-GroupMailboxAAD-v1|group_id={}|anonymous={}|purpose={}",
            context.group_id, context.anonymous_group, purpose
        )
        .into_bytes(),
        2 => {
            let state = context
                .content_crypto_state
                .as_ref()
                .expect("sealed payload version checked before AAD derivation");
            format!(
                "Qypha-GroupMailboxAAD-v2|group_id={}|anonymous={}|purpose={}|suite={}|epoch={}",
                context.group_id,
                context.anonymous_group,
                purpose,
                state.suite.as_str(),
                state.epoch
            )
            .into_bytes()
        }
        _ => Vec::new(),
    }
}

pub(crate) fn seal_bytes(
    session: &GroupMailboxSession,
    purpose: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_bytes_with_context(&crypto_context_for_session(session), purpose, plaintext)
}

pub(crate) fn seal_group_mailbox_payload(
    session: &GroupMailboxSession,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    sender_profile: Option<&GroupMailboxMemberProfile>,
    kind: GroupMailboxMessageKind,
    message_id: &str,
    created_at: u64,
    created_at_ms: u64,
    purpose: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let payload = if session.anonymous_group || session.content_crypto_state.is_none() {
        payload.to_vec()
    } else {
        let signing_key = signing_key
            .ok_or_else(|| anyhow::anyhow!("Identified v2 group payload requires a signing key"))?;
        let sender_profile = match sender_profile {
            Some(profile) => profile.clone(),
            None => local_member_profile(session)?,
        };
        wrap_authenticated_group_mailbox_payload(
            session,
            signing_key,
            &sender_profile,
            kind,
            message_id,
            created_at,
            created_at_ms,
            payload,
        )?
    };
    seal_bytes(session, purpose, &payload)
}

pub(crate) fn seal_group_mailbox_payload_with_context(
    session: &GroupMailboxSession,
    context: &GroupMailboxCryptoContext,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    sender_profile: Option<&GroupMailboxMemberProfile>,
    kind: GroupMailboxMessageKind,
    message_id: &str,
    created_at: u64,
    created_at_ms: u64,
    purpose: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let payload = if session.anonymous_group || context.content_crypto_state.is_none() {
        payload.to_vec()
    } else {
        let signing_key = signing_key
            .ok_or_else(|| anyhow::anyhow!("Identified v2 group payload requires a signing key"))?;
        let sender_profile = match sender_profile {
            Some(profile) => profile.clone(),
            None => local_member_profile(session)?,
        };
        wrap_authenticated_group_mailbox_payload(
            session,
            signing_key,
            &sender_profile,
            kind,
            message_id,
            created_at,
            created_at_ms,
            payload,
        )?
    };
    seal_bytes_with_context(context, purpose, &payload)
}

pub(crate) fn seal_bytes_with_context(
    context: &GroupMailboxCryptoContext,
    purpose: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let sealed_version = sealed_payload_version_for_context(context);
    let mut key = derive_context_key(context, purpose, sealed_version)?;
    let nonce: [u8; 32] = rand::random();
    let aegis = Aegis256::<32>::new(&key, &nonce);
    key.zeroize();
    let aad = aad_for(context, purpose, sealed_version);
    let (ct, tag) = aegis.encrypt(plaintext, &aad);
    let mut ciphertext = ct;
    ciphertext.extend_from_slice(&tag);
    serde_json::to_vec(&SealedGroupMailboxPayload {
        version: sealed_version,
        nonce: nonce.to_vec(),
        ciphertext,
    })
    .context("Failed to encode sealed mailbox payload")
}

pub(crate) fn open_bytes(
    session: &GroupMailboxSession,
    purpose: &str,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    open_bytes_with_context(&crypto_context_for_session(session), purpose, sealed)
}

pub(crate) fn open_bytes_with_context(
    context: &GroupMailboxCryptoContext,
    purpose: &str,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let envelope: SealedGroupMailboxPayload =
        serde_json::from_slice(sealed).context("Invalid sealed mailbox payload")?;
    let sealed_version = envelope.version;
    if sealed_version != 1 && sealed_version != 2 {
        bail!("Unsupported sealed mailbox payload version");
    }
    if envelope.ciphertext.len() < 32 {
        bail!("Sealed mailbox payload too short");
    }
    let nonce: [u8; 32] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid mailbox payload nonce"))?;
    let tag_offset = envelope.ciphertext.len() - 32;
    let ciphertext = &envelope.ciphertext[..tag_offset];
    let tag: [u8; 32] = envelope.ciphertext[tag_offset..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid mailbox payload tag"))?;
    let mut key = derive_context_key(context, purpose, sealed_version)?;
    let aegis = Aegis256::<32>::new(&key, &nonce);
    key.zeroize();
    let aad = aad_for(context, purpose, sealed_version);
    aegis
        .decrypt(ciphertext, &tag, &aad)
        .map_err(|_| anyhow::anyhow!("Mailbox payload decryption failed"))
}

pub(crate) fn build_group_mailbox_message(
    session: &GroupMailboxSession,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    sender_profile: Option<&GroupMailboxMemberProfile>,
    kind: GroupMailboxMessageKind,
    purpose: &str,
    payload: &[u8],
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let mailbox_message = if session.anonymous_group {
        let inner_kind = match kind {
            GroupMailboxMessageKind::Chat => AnonymousMailboxInnerKind::Chat,
            GroupMailboxMessageKind::FileManifest => AnonymousMailboxInnerKind::FileManifest,
            GroupMailboxMessageKind::FileChunkData => AnonymousMailboxInnerKind::FileChunkData,
            GroupMailboxMessageKind::FileChunkComplete => {
                AnonymousMailboxInnerKind::FileChunkComplete
            }
            _ => bail!(
                "Anonymous mailbox groups do not support outer kind {}",
                kind_label(&kind)
            ),
        };
        let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
        let wrapped_payload = wrap_anonymous_group_mailbox_payload(
            session,
            kind.clone(),
            &message_id,
            created_at,
            created_at_ms,
            payload,
        )?;
        let opaque_payload = encode_anonymous_opaque_payload(inner_kind, &wrapped_payload);
        GroupMailboxMessage {
            version: 1,
            message_id: message_id.clone(),
            group_id: mailbox_namespace_group_label(&session.mailbox_descriptor.namespace)
                .to_string(),
            anonymous_group: true,
            sender_member_id: None,
            kind: GroupMailboxMessageKind::AnonymousOpaque,
            created_at,
            created_at_ms,
            ttl_ms,
            ciphertext: seal_group_mailbox_payload(
                session,
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
            ciphertext: seal_group_mailbox_payload(
                session,
                signing_key,
                sender_profile,
                kind,
                &message_id,
                created_at,
                created_at_ms,
                purpose,
                payload,
            )?,
        }
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn build_ghost_anonymous_cover_message(
    session: &GroupMailboxSession,
) -> Result<GroupMailboxMessage> {
    if !session.anonymous_group {
        bail!("Anonymous cover traffic requires an anonymous mailbox group");
    }
    let opaque_payload = encode_anonymous_opaque_payload(AnonymousMailboxInnerKind::Cover, &[]);
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: format!("gmsg_{}", uuid::Uuid::new_v4().simple()),
        group_id: mailbox_namespace_group_label(&session.mailbox_descriptor.namespace).to_string(),
        anonymous_group: true,
        sender_member_id: None,
        kind: GroupMailboxMessageKind::AnonymousOpaque,
        created_at,
        created_at_ms,
        ttl_ms: ghost_anonymous_cover_ttl_ms(session.mailbox_descriptor.poll_interval_ms),
        ciphertext: seal_bytes(session, "message/anonymous_opaque", &opaque_payload)?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn decode_group_mailbox_message_with_context(
    context: &GroupMailboxCryptoContext,
    message: &GroupMailboxMessage,
) -> Result<DecodedGroupMailboxMessage> {
    if context.anonymous_group && message.kind == GroupMailboxMessageKind::AnonymousOpaque {
        let opaque_payload =
            open_bytes_with_context(context, "message/anonymous_opaque", &message.ciphertext)?;
        let (inner_kind, payload) = decode_anonymous_opaque_payload(&opaque_payload)?;
        return match inner_kind.into_outer_kind() {
            Some(kind) => unwrap_anonymous_group_mailbox_payload(context, kind, message, &payload),
            None => Ok(DecodedGroupMailboxMessage {
                kind: None,
                payload,
                authenticated_sender: None,
            }),
        };
    }

    let purpose = match message.kind {
        GroupMailboxMessageKind::AnonymousOpaque => {
            bail!("Anonymous opaque mailbox message requires an anonymous group session")
        }
        GroupMailboxMessageKind::Chat => "message/chat",
        GroupMailboxMessageKind::FileManifest => "message/file_manifest",
        GroupMailboxMessageKind::FileChunkData => "message/file_chunk_data",
        GroupMailboxMessageKind::FileChunkComplete => "message/file_chunk_complete",
        GroupMailboxMessageKind::FastFileOffer => "message/fast_file_offer",
        GroupMailboxMessageKind::FastFileAccept => "message/fast_file_accept",
        GroupMailboxMessageKind::FastFileGrant => "message/fast_file_grant",
        GroupMailboxMessageKind::FastFileStatus => "message/fast_file_status",
        GroupMailboxMessageKind::DirectHandshakeOffer => "message/direct_handshake_offer",
        GroupMailboxMessageKind::MembershipNotice => "message/membership_notice",
        GroupMailboxMessageKind::KickNotice => "message/kick_notice",
        GroupMailboxMessageKind::GroupDisband => "message/group_disband",
        GroupMailboxMessageKind::MailboxRotation => "message/mailbox_rotation",
    };
    let payload = open_bytes_with_context(context, purpose, &message.ciphertext)?;
    unwrap_authenticated_group_mailbox_payload(context, message, &payload)
}

pub(crate) fn ensure_message_fits(
    session: &GroupMailboxSession,
    message: &GroupMailboxMessage,
) -> Result<()> {
    let encoded = serde_json::to_vec(message).context("Failed to encode mailbox message")?;
    if encoded.len() > session.mailbox_descriptor.max_payload_bytes {
        bail!(
            "Mailbox payload too large: {} bytes exceeds limit of {} bytes",
            encoded.len(),
            session.mailbox_descriptor.max_payload_bytes
        );
    }
    Ok(())
}

pub(crate) fn regenerate_anonymous_group_invite_with_bundle(
    session: &GroupMailboxSession,
) -> Result<(
    GroupMailboxSession,
    GroupMailboxInvite,
    crate::network::group_invite_bundle::GroupInviteBundle,
)> {
    if !session.anonymous_group {
        bail!("Anonymous invite regeneration requires an anonymous mailbox group");
    }
    let endpoint = session
        .mailbox_descriptor
        .endpoint
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Anonymous mailbox group is missing relay endpoint"))?;
    let next_mailbox_epoch = session.mailbox_epoch.saturating_add(1);
    let mut rotated_session = GroupMailboxSession {
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: true,
        join_locked: false,
        mailbox_descriptor: MailboxDescriptor {
            transport: session.mailbox_descriptor.transport.clone(),
            namespace: rotated_mailbox_namespace(&session.group_id, next_mailbox_epoch),
            endpoint: Some(endpoint),
            poll_interval_ms: session.mailbox_descriptor.poll_interval_ms,
            max_payload_bytes: session.mailbox_descriptor.max_payload_bytes,
        },
        mailbox_capability: build_mailbox_capability(),
        content_crypto_state: Some(build_group_content_crypto_state(next_mailbox_epoch)),
        anonymous_writer_state: Some(build_anonymous_group_writer_state(next_mailbox_epoch)),
        local_member_id: None,
        owner_member_id: None,
        persistence: session.persistence.clone(),
        joined_at: session.joined_at,
        invite_id: String::new(),
        owner_special_id: session.owner_special_id.clone(),
        mailbox_epoch: next_mailbox_epoch,
        poll_cursor: None,
        next_cover_traffic_at: Some(next_ghost_anonymous_cover_traffic_at(current_unix_ts_ms())),
        last_real_activity_at: Some(current_unix_ts_ms()),
        known_members: HashMap::new(),
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles: Vec::new(),
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let now = chrono::Utc::now().timestamp() as u64;
    let invite = GroupMailboxInvite::generate(
        &signing_key,
        None,
        &rotated_session.group_id,
        rotated_session.group_name.as_deref(),
        true,
        rotated_session.mailbox_descriptor.clone(),
        rotated_session.mailbox_capability.clone(),
        rotated_session.content_crypto_state.clone(),
        rotated_session.anonymous_writer_state.clone(),
        now.saturating_add(INVITE_TTL_TOR_SECS),
    )?;
    issue_group_mailbox_bootstrap_token(
        &signing_key,
        MailboxBootstrapScopeKind::Invite,
        &invite.invite_id,
        &rotated_session.mailbox_descriptor,
        &mut rotated_session.mailbox_capability,
        invite.expiry,
    )?;
    let mut rotated_session = GroupMailboxSession {
        invite_id: invite.invite_id.clone(),
        ..rotated_session
    };
    let bundle = build_group_invite_bundle_from_session(&signing_key, &invite, &rotated_session)?;
    validate_group_mailbox_session(&rotated_session)?;
    Ok((rotated_session, invite, bundle))
}

pub(crate) fn regenerate_anonymous_group_invite(
    session: &GroupMailboxSession,
) -> Result<(GroupMailboxSession, GroupMailboxInvite)> {
    let (session, invite, _) = regenerate_anonymous_group_invite_with_bundle(session)?;
    Ok((session, invite))
}

pub(crate) fn build_membership_notice_message_with_state(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    state: MembershipNoticeState,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups must not publish membership notices");
    }
    if session.local_member_id.as_deref() != Some(local_profile.member_id.as_str()) {
        bail!("Membership notice local member_id mismatch");
    }

    let mut payload = MembershipNoticePayload {
        group_id: session.group_id.clone(),
        member_id: local_profile.member_id.clone(),
        display_name: local_profile.display_name.clone(),
        verifying_key_hex: local_profile.verifying_key_hex.clone(),
        encryption_public_key_hex: local_profile.encryption_public_key_hex.clone(),
        kyber_public_key_hex: local_profile.kyber_public_key_hex.clone(),
        state,
        created_at: chrono::Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&membership_notice_signing_data(&payload))
        .to_bytes()
        .to_vec();

    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode membership notice payload")?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(local_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::MembershipNotice,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            session,
            Some(signing_key),
            Some(local_profile),
            GroupMailboxMessageKind::MembershipNotice,
            &message_id,
            created_at,
            created_at_ms,
            "message/membership_notice",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn build_membership_notice_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    build_membership_notice_message_with_state(
        session,
        signing_key,
        local_profile,
        MembershipNoticeState::Joined,
        ttl_ms,
    )
}

pub(crate) fn build_group_disband_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support authenticated disband notices");
    }
    if session.local_member_id.as_deref() != Some(local_profile.member_id.as_str()) {
        bail!("Group disband local member_id mismatch");
    }
    if session.owner_member_id.as_deref() != Some(local_profile.member_id.as_str()) {
        bail!("Only the mailbox group owner may publish a disband notice");
    }

    let mut payload = GroupDisbandPayload {
        group_id: session.group_id.clone(),
        owner_member_id: local_profile.member_id.clone(),
        owner_verifying_key_hex: local_profile.verifying_key_hex.clone(),
        mailbox_epoch: session.mailbox_epoch,
        created_at: current_unix_ts(),
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&group_disband_signing_data(&payload))
        .to_bytes()
        .to_vec();

    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode group disband payload")?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(local_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::GroupDisband,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            session,
            Some(signing_key),
            Some(local_profile),
            GroupMailboxMessageKind::GroupDisband,
            &message_id,
            created_at,
            created_at_ms,
            "message/group_disband",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn group_kick_notice_signing_data(payload: &GroupKickNoticePayload) -> Vec<u8> {
    let mut data = Vec::new();
    write_canonical_str(&mut data, &payload.group_id);
    write_canonical_str(&mut data, &payload.owner_member_id);
    write_canonical_str(&mut data, &payload.owner_verifying_key_hex);
    write_canonical_str(&mut data, &payload.kicked_member_id);
    write_canonical_str(&mut data, &payload.kicked_display_name);
    data.extend_from_slice(&payload.mailbox_epoch.to_le_bytes());
    data.extend_from_slice(&payload.created_at.to_le_bytes());
    data
}

pub(crate) fn build_group_kick_notice_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    local_profile: &GroupMailboxMemberProfile,
    kicked_profile: &GroupMailboxMemberProfile,
    mailbox_epoch: u64,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support kick notices");
    }
    if session.local_member_id.as_deref() != Some(local_profile.member_id.as_str()) {
        bail!("Group kick notice local member_id mismatch");
    }
    if session.owner_member_id.as_deref() != Some(local_profile.member_id.as_str()) {
        bail!("Only the mailbox group owner may publish a kick notice");
    }

    let mut payload = GroupKickNoticePayload {
        group_id: session.group_id.clone(),
        owner_member_id: local_profile.member_id.clone(),
        owner_verifying_key_hex: local_profile.verifying_key_hex.clone(),
        kicked_member_id: kicked_profile.member_id.clone(),
        kicked_display_name: kicked_profile.display_name.clone(),
        mailbox_epoch,
        created_at: current_unix_ts(),
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&group_kick_notice_signing_data(&payload))
        .to_bytes()
        .to_vec();

    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode group kick notice payload")?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(local_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::KickNotice,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            session,
            Some(signing_key),
            Some(local_profile),
            GroupMailboxMessageKind::KickNotice,
            &message_id,
            created_at,
            created_at_ms,
            "message/kick_notice",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn verify_membership_notice_payload(
    payload: &MembershipNoticePayload,
    outer_sender_member_id: Option<&str>,
) -> Result<(GroupMailboxMemberProfile, MembershipNoticeState)> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.verifying_key_hex)?;
    if expected_did != payload.member_id {
        bail!("Membership notice DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.member_id.as_str())
    {
        bail!("Membership notice sender_member_id mismatch");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid membership notice signature"))?;
    let verifying_key_bytes = hex::decode(&payload.verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Membership notice verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid membership notice Ed25519 verifying key")?;
    let signature_valid = verifying_key
        .verify_strict(&membership_notice_signing_data(payload), &signature)
        .is_ok()
        || (payload.state == MembershipNoticeState::Joined
            && verifying_key
                .verify_strict(&membership_notice_signing_data_v1(payload), &signature)
                .is_ok());
    if !signature_valid {
        bail!("Membership notice signature invalid");
    }

    Ok((
        GroupMailboxMemberProfile {
            member_id: payload.member_id.clone(),
            display_name: payload.display_name.clone(),
            verifying_key_hex: payload.verifying_key_hex.clone(),
            encryption_public_key_hex: payload.encryption_public_key_hex.clone(),
            kyber_public_key_hex: payload.kyber_public_key_hex.clone(),
        },
        payload.state,
    ))
}

pub(crate) fn verify_authenticated_group_sender_authorized(
    session: &GroupMailboxSession,
    kind: &GroupMailboxMessageKind,
    sender: &AuthenticatedGroupMailboxSender,
) -> Result<()> {
    if session.anonymous_group || session.content_crypto_state.is_none() {
        return Ok(());
    }

    let sender_known = session.known_members.contains_key(&sender.member_id)
        || session.local_member_id.as_deref() == Some(sender.member_id.as_str())
        || session.owner_member_id.as_deref() == Some(sender.member_id.as_str());

    match kind {
        GroupMailboxMessageKind::MembershipNotice => Ok(()),
        GroupMailboxMessageKind::KickNotice
        | GroupMailboxMessageKind::GroupDisband
        | GroupMailboxMessageKind::MailboxRotation => {
            if session.owner_member_id.as_deref() == Some(sender.member_id.as_str()) {
                Ok(())
            } else {
                bail!("Authenticated group control message is not from the owner")
            }
        }
        _ => {
            if sender_known {
                Ok(())
            } else {
                bail!("Authenticated group sender is not a known member")
            }
        }
    }
}

pub(crate) fn verify_group_disband_payload(
    payload: &GroupDisbandPayload,
    outer_sender_member_id: Option<&str>,
    current_group_id: &str,
    expected_owner_member_id: Option<&str>,
) -> Result<String> {
    if payload.group_id != current_group_id {
        bail!("Group disband group_id mismatch");
    }
    let expected_did = derive_did_from_verifying_key_hex(&payload.owner_verifying_key_hex)?;
    if expected_did != payload.owner_member_id {
        bail!("Group disband DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.owner_member_id.as_str())
    {
        bail!("Group disband sender_member_id mismatch");
    }
    if expected_owner_member_id.is_some()
        && expected_owner_member_id != Some(payload.owner_member_id.as_str())
    {
        bail!("Group disband sender is not the current group owner");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid group disband signature"))?;
    let verifying_key_bytes = hex::decode(&payload.owner_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Group disband verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid group disband Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&group_disband_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Group disband signature invalid"))?;
    Ok(payload.owner_member_id.clone())
}

pub(crate) fn verify_group_kick_notice_payload(
    payload: &GroupKickNoticePayload,
    outer_sender_member_id: Option<&str>,
    current_group_id: &str,
    expected_owner_member_id: Option<&str>,
) -> Result<String> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.owner_verifying_key_hex)?;
    if expected_did != payload.owner_member_id {
        bail!("Group kick notice DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.owner_member_id.as_str())
    {
        bail!("Group kick notice sender_member_id mismatch");
    }
    if payload.group_id != current_group_id {
        bail!("Group kick notice group_id mismatch");
    }
    if expected_owner_member_id.is_some()
        && expected_owner_member_id != Some(payload.owner_member_id.as_str())
    {
        bail!("Group kick notice owner_member_id mismatch");
    }
    if payload.kicked_member_id.is_empty() {
        bail!("Group kick notice kicked_member_id missing");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid group kick notice signature"))?;
    let verifying_key_bytes = hex::decode(&payload.owner_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Group kick notice verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid group kick notice Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&group_kick_notice_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Group kick notice signature invalid"))?;
    Ok(payload.owner_member_id.clone())
}

pub(crate) fn build_direct_handshake_offer_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    target_profile: &GroupMailboxMemberProfile,
    direct_invite_code: &str,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups must not carry direct handshake offers");
    }
    if sender_profile.member_id == target_profile.member_id {
        bail!("Direct handshake offer target must be a different member");
    }
    let recipient_x25519 = parse_x25519_public_key_hex(&target_profile.encryption_public_key_hex)?;
    let recipient_kyber = target_profile
        .kyber_public_key_hex
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Target member missing Kyber mailbox profile"))?;
    let recipient_kyber =
        hex::decode(recipient_kyber).context("Invalid target Kyber public key")?;
    let envelope = hybrid_encrypt_message(
        &recipient_x25519,
        Some(recipient_kyber.as_slice()),
        direct_invite_code.as_bytes(),
    )?;
    let envelope_bytes =
        bincode::serialize(&envelope).context("Failed to encode direct invite envelope")?;
    let mut payload = DirectHandshakeOfferPayload {
        offer_id: format!("goffer_{}", uuid::Uuid::new_v4().simple()),
        group_id: session.group_id.clone(),
        sender_member_id: sender_profile.member_id.clone(),
        sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
        target_member_id: target_profile.member_id.clone(),
        encrypted_invite_envelope: envelope_bytes,
        created_at: chrono::Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&direct_handshake_offer_signing_data(&payload))
        .to_bytes()
        .to_vec();
    let payload_bytes = encode_direct_handshake_offer_payload(&payload)?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(sender_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::DirectHandshakeOffer,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            session,
            Some(signing_key),
            Some(sender_profile),
            GroupMailboxMessageKind::DirectHandshakeOffer,
            &message_id,
            created_at,
            created_at_ms,
            "message/direct_handshake_offer",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn decrypt_direct_handshake_offer_payload(
    payload: &DirectHandshakeOfferPayload,
    keypair: &AgentKeyPair,
    outer_sender_member_id: Option<&str>,
    local_member_id: &str,
) -> Result<(String, String)> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.sender_verifying_key_hex)?;
    if expected_did != payload.sender_member_id {
        bail!("Direct handshake offer DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.sender_member_id.as_str())
    {
        bail!("Direct handshake offer sender_member_id mismatch");
    }
    if payload.target_member_id != local_member_id {
        bail!("Direct handshake offer is not targeted to this member");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid direct handshake offer signature"))?;
    let verifying_key_bytes = hex::decode(&payload.sender_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Direct handshake offer verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid direct handshake offer Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&direct_handshake_offer_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Direct handshake offer signature invalid"))?;

    let envelope = decode_direct_handshake_offer_envelope(&payload.encrypted_invite_envelope)?;
    let invite_code = hybrid_decrypt_message(
        &keypair.x25519_secret_key_bytes(),
        (!keypair.kyber_secret.is_empty()).then_some(keypair.kyber_secret.as_slice()),
        &envelope,
    )?;
    let invite_code =
        String::from_utf8(invite_code).context("Direct handshake offer is not valid UTF-8")?;
    Ok((payload.sender_member_id.clone(), invite_code))
}

pub(crate) fn join_bridge_handle_for_session(
    session: &GroupMailboxSession,
) -> GroupMailboxJoinBridgeHandle {
    GroupMailboxJoinBridgeHandle {
        mailbox_epoch: session.mailbox_epoch,
        mailbox_descriptor: session.mailbox_descriptor.clone(),
        mailbox_capability: session.mailbox_capability.clone(),
        content_crypto_state: session.content_crypto_state.clone(),
    }
}

pub(crate) fn ensure_join_bridge_handle(
    handles: &mut Vec<GroupMailboxJoinBridgeHandle>,
    session: &GroupMailboxSession,
) {
    let handle = join_bridge_handle_for_session(session);
    if handles.iter().any(|existing| existing == &handle) {
        return;
    }
    handles.push(handle);
    handles.sort_by(|a, b| a.mailbox_epoch.cmp(&b.mailbox_epoch));
}

pub(crate) fn bridge_session_for_handle(
    session: &GroupMailboxSession,
    handle: &GroupMailboxJoinBridgeHandle,
) -> Result<GroupMailboxSession> {
    let bridge_session = GroupMailboxSession {
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: false,
        join_locked: session.join_locked,
        mailbox_descriptor: handle.mailbox_descriptor.clone(),
        mailbox_capability: handle.mailbox_capability.clone(),
        content_crypto_state: handle.content_crypto_state.clone(),
        anonymous_writer_state: None,
        local_member_id: session.local_member_id.clone(),
        owner_member_id: session.owner_member_id.clone(),
        persistence: session.persistence.clone(),
        joined_at: session.joined_at,
        invite_id: session.invite_id.clone(),
        owner_special_id: session.owner_special_id.clone(),
        mailbox_epoch: handle.mailbox_epoch,
        poll_cursor: None,
        next_cover_traffic_at: None,
        last_real_activity_at: None,
        known_members: HashMap::new(),
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles: Vec::new(),
    };
    validate_group_mailbox_session(&bridge_session)?;
    Ok(bridge_session)
}

pub(crate) fn build_public_join_bridge_rotation_message(
    handle: &GroupMailboxJoinBridgeHandle,
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    let bridge_session = bridge_session_for_handle(session, handle)?;
    let mut payload = MailboxRotationPayload {
        rotation_id: format!("grot_{}", uuid::Uuid::new_v4().simple()),
        group_id: session.group_id.clone(),
        sender_member_id: sender_profile.member_id.clone(),
        sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
        target_member_id: String::new(),
        kicked_member_id: String::new(),
        new_mailbox_epoch: session.mailbox_epoch,
        join_locked: session.join_locked,
        public_mailbox_descriptor: (!session.join_locked)
            .then(|| session.mailbox_descriptor.clone()),
        public_mailbox_capability: (!session.join_locked)
            .then(|| session.mailbox_capability.clone()),
        public_content_crypto_state: (!session.join_locked)
            .then(|| session.content_crypto_state.clone())
            .flatten(),
        encrypted_session_bundle_b64: String::new(),
        created_at: current_unix_ts(),
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&mailbox_rotation_signing_data(&payload))
        .to_bytes()
        .to_vec();
    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode public join bridge payload")?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(sender_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::MailboxRotation,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            &bridge_session,
            Some(signing_key),
            Some(sender_profile),
            GroupMailboxMessageKind::MailboxRotation,
            &message_id,
            created_at,
            created_at_ms,
            "message/mailbox_rotation",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(&bridge_session, &message)?;
    Ok(message)
}

pub(crate) async fn publish_group_join_bridge_updates(
    transport: &TorMailboxTransport,
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    ttl_ms: u64,
) -> Vec<(u64, std::result::Result<(), String>)> {
    let Ok(sender_profile) = local_member_profile(session) else {
        return Vec::new();
    };
    let mut outcomes = Vec::new();
    for handle in &session.join_bridge_handles {
        let outcome = match build_public_join_bridge_rotation_message(
            handle,
            session,
            signing_key,
            &sender_profile,
            ttl_ms,
        ) {
            Ok(message) => match bridge_session_for_handle(session, handle) {
                Ok(bridge_session) => {
                    match post_group_mailbox_message(transport, &bridge_session, &message).await {
                        Ok(_) => Ok(()),
                        Err(error) => Err(error.to_string()),
                    }
                }
                Err(error) => Err(error.to_string()),
            },
            Err(error) => Err(error.to_string()),
        };
        outcomes.push((handle.mailbox_epoch, outcome));
    }
    outcomes
}

pub(crate) fn plan_owner_kick_rotation(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    kicked_member_id: &str,
) -> Result<(
    GroupMailboxSession,
    GroupMailboxMemberProfile,
    Vec<(String, GroupMailboxMessage)>,
)> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support /kick_g");
    }
    let local_member_id = session
        .local_member_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Mailbox group is missing local member id"))?;
    if session.owner_member_id.as_deref() != Some(local_member_id) {
        bail!("Only the mailbox group owner may use /kick_g");
    }
    if kicked_member_id == local_member_id {
        bail!("Group owner cannot remove themselves");
    }
    let sender_profile = local_member_profile(session)?;
    let kicked_profile = session
        .known_members
        .get(kicked_member_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Group member {} is unknown", kicked_member_id))?;
    let endpoint = session
        .mailbox_descriptor
        .endpoint
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Mailbox session is missing service endpoint"))?;
    let next_mailbox_epoch = session.mailbox_epoch.saturating_add(1);
    let mut rotated_session = GroupMailboxSession {
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: false,
        join_locked: session.join_locked,
        mailbox_descriptor: MailboxDescriptor {
            transport: session.mailbox_descriptor.transport.clone(),
            namespace: rotated_mailbox_namespace(&session.group_id, next_mailbox_epoch),
            endpoint: Some(endpoint),
            poll_interval_ms: session.mailbox_descriptor.poll_interval_ms,
            max_payload_bytes: session.mailbox_descriptor.max_payload_bytes,
        },
        mailbox_capability: build_mailbox_capability(),
        content_crypto_state: Some(build_group_content_crypto_state(next_mailbox_epoch)),
        anonymous_writer_state: None,
        local_member_id: session.local_member_id.clone(),
        owner_member_id: session.owner_member_id.clone(),
        persistence: session.persistence.clone(),
        joined_at: session.joined_at,
        invite_id: session.invite_id.clone(),
        owner_special_id: session.owner_special_id.clone(),
        mailbox_epoch: next_mailbox_epoch,
        poll_cursor: None,
        next_cover_traffic_at: None,
        last_real_activity_at: None,
        known_members: session
            .known_members
            .iter()
            .filter(|(member_id, _)| member_id.as_str() != kicked_member_id)
            .map(|(member_id, profile)| (member_id.clone(), profile.clone()))
            .collect::<HashMap<_, _>>(),
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        // Kicking a member invalidates all pre-rotation bridge state so stale invites
        // cannot be revived into the new epoch after a later unlock.
        join_bridge_handles: Vec::new(),
    };
    issue_group_mailbox_bootstrap_token(
        signing_key,
        MailboxBootstrapScopeKind::EpochRotation,
        &format!("{}:epoch:{}", session.group_id, next_mailbox_epoch),
        &rotated_session.mailbox_descriptor,
        &mut rotated_session.mailbox_capability,
        chrono::Utc::now().timestamp().max(0) as u64 + INVITE_TTL_TOR_SECS,
    )?;
    validate_group_mailbox_session(&rotated_session)?;
    if !rotated_session.known_members.contains_key(local_member_id) {
        bail!("Mailbox owner profile missing after kick rotation");
    }
    let mut recipients = rotated_session
        .known_members
        .values()
        .cloned()
        .collect::<Vec<_>>();
    recipients.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    let mut rotation_messages = Vec::new();
    for profile in recipients {
        if profile.member_id == sender_profile.member_id {
            continue;
        }
        let message = build_mailbox_rotation_message(
            session,
            signing_key,
            &sender_profile,
            &profile,
            &rotated_session,
            kicked_member_id,
            120_000,
        )?;
        rotation_messages.push((profile.member_id.clone(), message));
    }
    Ok((rotated_session, kicked_profile, rotation_messages))
}

pub(crate) fn plan_owner_access_rotation(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    join_locked: bool,
) -> Result<(GroupMailboxSession, Vec<(String, GroupMailboxMessage)>)> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups do not support /lock_g or /unlock_g");
    }
    let local_member_id = session
        .local_member_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Mailbox group is missing local member id"))?;
    if session.owner_member_id.as_deref() != Some(local_member_id) {
        bail!("Only the mailbox group owner may use /lock_g or /unlock_g");
    }
    if session.join_locked == join_locked {
        if join_locked {
            bail!("Mailbox group is already locked");
        }
        bail!("Mailbox group is already unlocked");
    }
    let sender_profile = local_member_profile(session)?;
    let endpoint = session
        .mailbox_descriptor
        .endpoint
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Mailbox session is missing service endpoint"))?;
    let mut join_bridge_handles = session.join_bridge_handles.clone();
    if join_locked {
        ensure_join_bridge_handle(&mut join_bridge_handles, session);
    }
    let next_mailbox_epoch = session.mailbox_epoch.saturating_add(1);
    let mut rotated_session = GroupMailboxSession {
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: false,
        join_locked,
        mailbox_descriptor: MailboxDescriptor {
            transport: session.mailbox_descriptor.transport.clone(),
            namespace: rotated_mailbox_namespace(&session.group_id, next_mailbox_epoch),
            endpoint: Some(endpoint),
            poll_interval_ms: session.mailbox_descriptor.poll_interval_ms,
            max_payload_bytes: session.mailbox_descriptor.max_payload_bytes,
        },
        mailbox_capability: build_mailbox_capability(),
        content_crypto_state: Some(build_group_content_crypto_state(next_mailbox_epoch)),
        anonymous_writer_state: None,
        local_member_id: session.local_member_id.clone(),
        owner_member_id: session.owner_member_id.clone(),
        persistence: session.persistence.clone(),
        joined_at: session.joined_at,
        invite_id: session.invite_id.clone(),
        owner_special_id: session.owner_special_id.clone(),
        mailbox_epoch: next_mailbox_epoch,
        poll_cursor: None,
        next_cover_traffic_at: None,
        last_real_activity_at: None,
        known_members: session.known_members.clone(),
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles,
    };
    issue_group_mailbox_bootstrap_token(
        signing_key,
        MailboxBootstrapScopeKind::EpochRotation,
        &format!("{}:epoch:{}", session.group_id, next_mailbox_epoch),
        &rotated_session.mailbox_descriptor,
        &mut rotated_session.mailbox_capability,
        chrono::Utc::now().timestamp().max(0) as u64 + INVITE_TTL_TOR_SECS,
    )?;
    validate_group_mailbox_session(&rotated_session)?;
    let mut recipients = rotated_session
        .known_members
        .values()
        .cloned()
        .collect::<Vec<_>>();
    recipients.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    let mut rotation_messages = Vec::new();
    for profile in recipients {
        if profile.member_id == sender_profile.member_id {
            continue;
        }
        let message = build_mailbox_rotation_message(
            session,
            signing_key,
            &sender_profile,
            &profile,
            &rotated_session,
            "",
            120_000,
        )?;
        rotation_messages.push((profile.member_id.clone(), message));
    }
    Ok((rotated_session, rotation_messages))
}

pub(crate) fn build_mailbox_rotation_message(
    session: &GroupMailboxSession,
    signing_key: &ed25519_dalek::SigningKey,
    sender_profile: &GroupMailboxMemberProfile,
    target_profile: &GroupMailboxMemberProfile,
    rotated_session: &GroupMailboxSession,
    kicked_member_id: &str,
    ttl_ms: u64,
) -> Result<GroupMailboxMessage> {
    if session.anonymous_group || rotated_session.anonymous_group {
        bail!("Anonymous mailbox groups must not carry mailbox rotations");
    }
    validate_group_mailbox_session(rotated_session)?;
    if sender_profile.member_id == target_profile.member_id {
        bail!("Mailbox rotation target must be a different member");
    }
    let recipient_x25519 = parse_x25519_public_key_hex(&target_profile.encryption_public_key_hex)?;
    let recipient_kyber = target_profile
        .kyber_public_key_hex
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Rotation target missing Kyber mailbox profile"))?;
    let recipient_kyber =
        hex::decode(recipient_kyber).context("Invalid rotation target Kyber public key")?;
    let secret = MailboxRotationSecret {
        group_id: rotated_session.group_id.clone(),
        mailbox_descriptor: rotated_session.mailbox_descriptor.clone(),
        mailbox_capability: rotated_session.mailbox_capability.clone(),
        content_crypto_state: rotated_session.content_crypto_state.clone(),
        owner_member_id: rotated_session
            .owner_member_id
            .clone()
            .unwrap_or_else(|| sender_profile.member_id.clone()),
        new_mailbox_epoch: rotated_session.mailbox_epoch,
        join_locked: rotated_session.join_locked,
        // Join-bridge history is only needed by the owner when publishing public
        // bridge updates for older invite epochs. Replicating the full handle
        // history to every member causes mailbox rotation payloads to grow with
        // every lock/unlock cycle and can exceed the relay payload limit.
        join_bridge_handles: Vec::new(),
    };
    let secret_bytes =
        serde_json::to_vec(&secret).context("Failed to encode mailbox rotation secret")?;
    let envelope = hybrid_encrypt_message(
        &recipient_x25519,
        Some(recipient_kyber.as_slice()),
        &secret_bytes,
    )?;
    let envelope_bytes =
        serde_json::to_vec(&envelope).context("Failed to encode mailbox rotation envelope")?;
    let mut payload = MailboxRotationPayload {
        rotation_id: format!("grot_{}", uuid::Uuid::new_v4().simple()),
        group_id: session.group_id.clone(),
        sender_member_id: sender_profile.member_id.clone(),
        sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
        target_member_id: target_profile.member_id.clone(),
        kicked_member_id: kicked_member_id.to_string(),
        new_mailbox_epoch: rotated_session.mailbox_epoch,
        join_locked: rotated_session.join_locked,
        public_mailbox_descriptor: None,
        public_mailbox_capability: None,
        public_content_crypto_state: None,
        encrypted_session_bundle_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&envelope_bytes),
        created_at: current_unix_ts(),
        signature: Vec::new(),
    };
    payload.signature = signing_key
        .sign(&mailbox_rotation_signing_data(&payload))
        .to_bytes()
        .to_vec();
    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to encode mailbox rotation payload")?;
    let (created_at, created_at_ms) = current_mailbox_message_timestamps();
    let message_id = format!("gmsg_{}", uuid::Uuid::new_v4().simple());
    let mailbox_message = GroupMailboxMessage {
        version: 1,
        message_id: message_id.clone(),
        group_id: session.group_id.clone(),
        anonymous_group: false,
        sender_member_id: Some(sender_profile.member_id.clone()),
        kind: GroupMailboxMessageKind::MailboxRotation,
        created_at,
        created_at_ms,
        ttl_ms,
        ciphertext: seal_group_mailbox_payload(
            session,
            Some(signing_key),
            Some(sender_profile),
            GroupMailboxMessageKind::MailboxRotation,
            &message_id,
            created_at,
            created_at_ms,
            "message/mailbox_rotation",
            &payload_bytes,
        )?,
    };
    ensure_message_fits(session, &mailbox_message)?;
    Ok(mailbox_message)
}

pub(crate) fn decrypt_mailbox_rotation_payload(
    payload: &MailboxRotationPayload,
    keypair: &AgentKeyPair,
    outer_sender_member_id: Option<&str>,
    local_member_id: &str,
    current_group_id: &str,
) -> Result<(String, String, MailboxRotationSecret)> {
    let expected_did = derive_did_from_verifying_key_hex(&payload.sender_verifying_key_hex)?;
    if expected_did != payload.sender_member_id {
        bail!("Mailbox rotation DID/verifying key mismatch");
    }
    if outer_sender_member_id.is_some()
        && outer_sender_member_id != Some(payload.sender_member_id.as_str())
    {
        bail!("Mailbox rotation sender_member_id mismatch");
    }
    if payload.group_id != current_group_id {
        bail!("Mailbox rotation group_id mismatch");
    }
    if payload.target_member_id != local_member_id {
        bail!("Mailbox rotation is not targeted to this member");
    }
    if !payload.kicked_member_id.is_empty() && payload.kicked_member_id == local_member_id {
        bail!("Mailbox rotation cannot target the kicked member");
    }
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| anyhow::anyhow!("Invalid mailbox rotation signature"))?;
    let verifying_key_bytes = hex::decode(&payload.sender_verifying_key_hex)?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Mailbox rotation verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid mailbox rotation Ed25519 verifying key")?;
    verifying_key
        .verify_strict(&mailbox_rotation_signing_data(payload), &signature)
        .map_err(|_| anyhow::anyhow!("Mailbox rotation signature invalid"))?;

    let envelope_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.encrypted_session_bundle_b64.as_bytes())
        .context("Invalid mailbox rotation envelope encoding")?;
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(&envelope_bytes).context("Invalid mailbox rotation envelope")?;
    let secret = hybrid_decrypt_message(
        &keypair.x25519_secret_key_bytes(),
        (!keypair.kyber_secret.is_empty()).then_some(keypair.kyber_secret.as_slice()),
        &envelope,
    )?;
    let secret: MailboxRotationSecret =
        serde_json::from_slice(&secret).context("Invalid mailbox rotation secret")?;
    if secret.group_id != payload.group_id {
        bail!("Mailbox rotation secret group_id mismatch");
    }
    if let Some(state) = secret.content_crypto_state.as_ref() {
        validate_group_content_crypto_state(state, &secret.group_id)?;
    }
    if secret.new_mailbox_epoch != payload.new_mailbox_epoch {
        bail!("Mailbox rotation epoch mismatch");
    }
    Ok((
        payload.sender_member_id.clone(),
        payload.kicked_member_id.clone(),
        secret,
    ))
}

pub(crate) fn apply_mailbox_rotation(
    session: &GroupMailboxSession,
    sender_member_id: &str,
    kicked_member_id: &str,
    secret: MailboxRotationSecret,
) -> Result<GroupMailboxSession> {
    if session.anonymous_group {
        bail!("Anonymous mailbox groups must not apply mailbox rotation");
    }
    if secret.group_id != session.group_id {
        bail!("Mailbox rotation secret group mismatch");
    }
    if secret.new_mailbox_epoch <= session.mailbox_epoch {
        bail!("Mailbox rotation epoch is stale");
    }
    if secret.owner_member_id != sender_member_id {
        bail!("Mailbox rotation sender is not the advertised owner");
    }
    let mut known_members = session.known_members.clone();
    if !kicked_member_id.is_empty() {
        known_members.remove(kicked_member_id);
    }
    let rotated_session = GroupMailboxSession {
        group_id: session.group_id.clone(),
        group_name: session.group_name.clone(),
        anonymous_group: false,
        join_locked: secret.join_locked,
        mailbox_descriptor: secret.mailbox_descriptor,
        mailbox_capability: secret.mailbox_capability,
        content_crypto_state: secret.content_crypto_state,
        anonymous_writer_state: None,
        local_member_id: session.local_member_id.clone(),
        owner_member_id: Some(secret.owner_member_id),
        persistence: session.persistence.clone(),
        joined_at: session.joined_at,
        invite_id: session.invite_id.clone(),
        owner_special_id: session.owner_special_id.clone(),
        mailbox_epoch: secret.new_mailbox_epoch,
        poll_cursor: None,
        next_cover_traffic_at: None,
        last_real_activity_at: None,
        known_members,
        local_posted_message_ids: HashSet::new(),
        seen_message_ids: HashMap::new(),
        join_bridge_handles: secret.join_bridge_handles,
    };
    validate_group_mailbox_session(&rotated_session)?;
    Ok(rotated_session)
}

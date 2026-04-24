use super::*;

pub(crate) fn trim_group_name(group_name: Option<&str>) -> Option<String> {
    group_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn anonymous_group_security_state(session: &GroupMailboxSession) -> Option<String> {
    if !session.anonymous_group {
        return None;
    }
    Some(
        if session.content_crypto_state.is_some() && session.anonymous_writer_state.is_some() {
            "v2_secure"
        } else {
            "legacy"
        }
        .to_string(),
    )
}

impl AnonymousMailboxInnerKind {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Chat => 0x01,
            Self::FileManifest => 0x02,
            Self::FileChunkData => 0x03,
            Self::FileChunkComplete => 0x04,
            Self::Cover => 0xff,
        }
    }

    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            0x01 => Ok(Self::Chat),
            0x02 => Ok(Self::FileManifest),
            0x03 => Ok(Self::FileChunkData),
            0x04 => Ok(Self::FileChunkComplete),
            0xff => Ok(Self::Cover),
            _ => bail!("Unknown anonymous mailbox inner kind {}", code),
        }
    }

    pub(crate) fn into_outer_kind(self) -> Option<GroupMailboxMessageKind> {
        match self {
            Self::Chat => Some(GroupMailboxMessageKind::Chat),
            Self::FileManifest => Some(GroupMailboxMessageKind::FileManifest),
            Self::FileChunkData => Some(GroupMailboxMessageKind::FileChunkData),
            Self::FileChunkComplete => Some(GroupMailboxMessageKind::FileChunkComplete),
            Self::Cover => None,
        }
    }
}

pub(crate) fn current_unix_ts() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

pub(crate) fn current_unix_ts_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

pub(crate) fn current_mailbox_message_timestamps() -> (u64, u64) {
    let created_at_ms = current_unix_ts_ms();
    (created_at_ms / 1000, created_at_ms)
}

pub(crate) fn ui_event_ts_ms_from_message(message: &GroupMailboxMessage) -> i64 {
    let created_at_ms = if message.created_at_ms > 0 {
        message.created_at_ms
    } else {
        message.created_at.saturating_mul(1000)
    };
    created_at_ms.min(i64::MAX as u64) as i64
}

pub(crate) fn format_group_file_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.1} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.1} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.1} KB", bytes_f / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

pub(crate) fn display_group_member_label(display_name: Option<&str>, member_id: &str) -> String {
    let visible_member_id = crate::agent::contact_identity::displayed_did(member_id);
    match display_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(label) => format!("{label} ({visible_member_id})"),
        None => visible_member_id,
    }
}

pub(crate) fn mailbox_namespace_group_label(namespace: &str) -> &str {
    let trimmed = namespace.trim();
    let without_prefix = trimmed.strip_prefix("mailbox:").unwrap_or(trimmed);
    without_prefix
        .split(":epoch:")
        .next()
        .unwrap_or(without_prefix)
}

pub(crate) fn mailbox_namespace_epoch(namespace: &str) -> Result<u64> {
    let trimmed = namespace.trim();
    let without_prefix = trimmed.strip_prefix("mailbox:").unwrap_or(trimmed);
    let mut parts = without_prefix.split(":epoch:");
    let _group = parts.next().unwrap_or_default();
    let Some(epoch_raw) = parts.next() else {
        return Ok(0);
    };
    if parts.next().is_some() {
        bail!("Mailbox namespace contains multiple epoch markers");
    }
    let epoch_value = epoch_raw.split(':').next().unwrap_or(epoch_raw);
    epoch_value
        .parse::<u64>()
        .with_context(|| format!("Mailbox namespace has invalid epoch '{}'", epoch_raw))
}

pub(crate) fn next_ghost_anonymous_cover_traffic_at(now_ms: u64) -> u64 {
    let jitter_ms =
        rand::thread_rng().gen_range(-GHOST_ANON_COVER_JITTER_MS..=GHOST_ANON_COVER_JITTER_MS);
    now_ms
        .saturating_add(GHOST_ANON_COVER_SLOT_MS)
        .saturating_add_signed(jitter_ms)
}

pub(crate) fn anonymous_padding_bucket(min_len: usize) -> usize {
    GHOST_ANON_PAD_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= min_len)
        .unwrap_or(min_len)
}

pub(crate) fn encode_anonymous_opaque_payload(
    inner_kind: AnonymousMailboxInnerKind,
    payload: &[u8],
) -> Vec<u8> {
    let minimum_len = 6usize.saturating_add(payload.len());
    let target_len = anonymous_padding_bucket(minimum_len);
    let mut encoded = Vec::with_capacity(target_len);
    encoded.push(1u8);
    encoded.push(inner_kind.code());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    if encoded.len() < target_len {
        let mut padding = vec![0u8; target_len - encoded.len()];
        rand::thread_rng().fill_bytes(&mut padding);
        encoded.extend_from_slice(&padding);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_group_member_label_uses_contact_did_when_name_exists() {
        let label = display_group_member_label(
            Some("agent1"),
            "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02",
        );

        assert_eq!(
            label,
            format!(
                "agent1 ({})",
                crate::network::contact_did::contact_did_from_canonical_did(
                    "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02"
                )
                .expect("canonical DID should convert")
            )
        );
    }

    #[test]
    fn display_group_member_label_falls_back_to_contact_did_without_name() {
        let label = display_group_member_label(
            Some("   "),
            "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02",
        );

        assert_eq!(
            label,
            crate::network::contact_did::contact_did_from_canonical_did(
                "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02"
            )
            .expect("canonical DID should convert")
        );
    }
}

pub(crate) fn decode_anonymous_opaque_payload(
    encoded: &[u8],
) -> Result<(AnonymousMailboxInnerKind, Vec<u8>)> {
    if encoded.len() < 6 {
        bail!("Anonymous mailbox payload frame is truncated");
    }
    if encoded[0] != 1 {
        bail!("Unsupported anonymous mailbox payload frame version");
    }
    let inner_kind = AnonymousMailboxInnerKind::from_code(encoded[1])?;
    let payload_len =
        u32::from_le_bytes(encoded[2..6].try_into().expect("payload len slice")) as usize;
    let payload_end = 6usize.saturating_add(payload_len);
    if payload_end > encoded.len() {
        bail!("Anonymous mailbox payload frame length is invalid");
    }
    Ok((inner_kind, encoded[6..payload_end].to_vec()))
}

pub(crate) fn ghost_anonymous_cover_ttl_ms(poll_interval_ms: u64) -> u64 {
    poll_interval_ms.max(1).saturating_mul(3).clamp(
        GHOST_ANON_EPHEMERAL_MIN_RETENTION_MS,
        GHOST_ANON_EPHEMERAL_MAX_RETENTION_MS,
    )
}

pub(crate) fn effective_ttl_secs(ttl_ms: u64) -> u64 {
    let ttl_ms = if ttl_ms == 0 {
        MAILBOX_DEFAULT_RETENTION_MS
    } else {
        ttl_ms.min(MAILBOX_MAX_RETENTION_MS)
    };
    (ttl_ms.saturating_add(999) / 1000).max(1)
}

pub(crate) fn message_is_live(message: &GroupMailboxMessage, now: u64) -> Result<()> {
    if message.created_at > now.saturating_add(MAILBOX_MAX_CLOCK_SKEW_SECS) {
        bail!("Mailbox message timestamp is too far in the future");
    }
    let ttl_secs = effective_ttl_secs(message.ttl_ms);
    if now > message.created_at.saturating_add(ttl_secs) {
        bail!("Mailbox message expired before processing");
    }
    Ok(())
}

pub(crate) fn prune_seen_message_ids(session: &mut GroupMailboxSession, now: u64) {
    let cutoff = now.saturating_sub(effective_ttl_secs(MAILBOX_MAX_RETENTION_MS));
    session
        .seen_message_ids
        .retain(|_, created_at| *created_at >= cutoff);
    if session.seen_message_ids.len() <= MAILBOX_RUNTIME_SEEN_MESSAGE_LIMIT {
        return;
    }
    let mut entries = session
        .seen_message_ids
        .iter()
        .map(|(message_id, created_at)| (message_id.clone(), *created_at))
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    session.seen_message_ids.clear();
    for (message_id, created_at) in entries.into_iter().take(MAILBOX_RUNTIME_SEEN_MESSAGE_LIMIT) {
        session.seen_message_ids.insert(message_id, created_at);
    }
}

pub(crate) fn note_group_activity(session: &mut GroupMailboxSession, now: u64) {
    if !session.anonymous_group {
        return;
    }
    session.last_real_activity_at = Some(now);
    session.next_cover_traffic_at = Some(next_ghost_anonymous_cover_traffic_at(now));
}

pub(crate) fn known_member_ids_sorted(session: &GroupMailboxSession) -> Vec<String> {
    let mut member_ids = session.known_members.keys().cloned().collect::<Vec<_>>();
    member_ids.sort();
    member_ids
}

pub(crate) fn known_members_sorted(
    session: &GroupMailboxSession,
) -> Vec<GroupMailboxMemberSummary> {
    let mut members = session
        .known_members
        .values()
        .map(|profile| GroupMailboxMemberSummary {
            member_id: profile.member_id.clone(),
            display_name: profile.display_name.clone(),
        })
        .collect::<Vec<_>>();
    members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    members
}

pub(crate) fn kind_label(kind: &GroupMailboxMessageKind) -> &'static str {
    match kind {
        GroupMailboxMessageKind::AnonymousOpaque => "anonymous_opaque",
        GroupMailboxMessageKind::Chat => "chat",
        GroupMailboxMessageKind::FileManifest => "file_manifest",
        GroupMailboxMessageKind::FileChunkData => "file_chunk_data",
        GroupMailboxMessageKind::FileChunkComplete => "file_chunk_complete",
        GroupMailboxMessageKind::FastFileOffer => "fast_file_offer",
        GroupMailboxMessageKind::FastFileAccept => "fast_file_accept",
        GroupMailboxMessageKind::FastFileGrant => "fast_file_grant",
        GroupMailboxMessageKind::FastFileStatus => "fast_file_status",
        GroupMailboxMessageKind::DirectHandshakeOffer => "direct_handshake_offer",
        GroupMailboxMessageKind::MembershipNotice => "membership_notice",
        GroupMailboxMessageKind::KickNotice => "kick_notice",
        GroupMailboxMessageKind::GroupDisband => "group_disband",
        GroupMailboxMessageKind::MailboxRotation => "mailbox_rotation",
    }
}

pub(crate) fn emit_ui_event(event: &GroupMailboxUiEvent) {
    let headless = std::env::var("QYPHA_HEADLESS")
        .map(|value| value == "1")
        .unwrap_or(false);
    if headless {
        if let Ok(encoded) = serde_json::to_string(event) {
            println!("GROUP_MAILBOX_EVENT {}", encoded);
        }
    }
}

pub(crate) fn build_mailbox_descriptor(
    group_id: &str,
    service_endpoint: &str,
    poll_interval_ms: u64,
    max_payload_bytes: usize,
) -> Result<MailboxDescriptor> {
    parse_mailbox_service_endpoint(service_endpoint)?;
    Ok(MailboxDescriptor {
        transport: MailboxTransportKind::Tor,
        namespace: rotated_mailbox_namespace(group_id, 0),
        endpoint: Some(service_endpoint.to_string()),
        poll_interval_ms,
        max_payload_bytes,
    })
}

pub(crate) fn build_ghost_anonymous_mailbox_descriptor(
    service_endpoint: &str,
    poll_interval_ms: u64,
    max_payload_bytes: usize,
) -> Result<MailboxDescriptor> {
    parse_mailbox_service_endpoint(service_endpoint)?;
    Ok(MailboxDescriptor {
        transport: MailboxTransportKind::Tor,
        namespace: format!("mailbox:anon_{}", uuid::Uuid::new_v4().simple()),
        endpoint: Some(service_endpoint.to_string()),
        poll_interval_ms,
        max_payload_bytes,
    })
}

pub(crate) fn configured_mailbox_endpoint(config: &AppConfig) -> Option<String> {
    config.network.mailbox.endpoint.clone().or_else(|| {
        std::env::var("QYPHA_MAILBOX_ENDPOINT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

pub(crate) fn configured_mailbox_pool_endpoints(config: &AppConfig) -> Vec<String> {
    let mut endpoints = config
        .network
        .mailbox
        .pool_endpoints
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if let Ok(env_value) = std::env::var("QYPHA_MAILBOX_POOL_ENDPOINTS") {
        endpoints.extend(
            env_value
                .split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        );
    }
    endpoints
}

pub(crate) fn mailbox_requires_external_provider(_config: &AppConfig) -> bool {
    false
}

pub(crate) async fn resolve_mailbox_endpoint(
    config: &AppConfig,
    agent_data_dir: &Path,
    group_id: &str,
) -> Result<ResolvedMailboxEndpoint> {
    if let Some(endpoint) = configured_mailbox_endpoint(config) {
        parse_mailbox_service_endpoint(&endpoint)?;
        return Ok(ResolvedMailboxEndpoint {
            endpoint,
            auto_provisioned: false,
            selected_from_pool: false,
        });
    }
    let pool_endpoints = configured_mailbox_pool_endpoints(config);
    if !pool_endpoints.is_empty() {
        let idx = (rand::random::<u64>() as usize) % pool_endpoints.len();
        let endpoint = pool_endpoints[idx].clone();
        parse_mailbox_service_endpoint(&endpoint)?;
        return Ok(ResolvedMailboxEndpoint {
            endpoint,
            auto_provisioned: false,
            selected_from_pool: true,
        });
    }
    let endpoint = ensure_embedded_mailbox_service(config, agent_data_dir, group_id).await?;
    Ok(ResolvedMailboxEndpoint {
        endpoint,
        auto_provisioned: true,
        selected_from_pool: false,
    })
}

pub(crate) async fn resolve_ghost_anonymous_mailbox_endpoint(
    config: &AppConfig,
    group_id: &str,
) -> Result<ResolvedMailboxEndpoint> {
    let endpoint = ensure_ghost_anonymous_mailbox_service(config, group_id).await?;
    Ok(ResolvedMailboxEndpoint {
        endpoint,
        auto_provisioned: true,
        selected_from_pool: false,
    })
}

pub(crate) fn mailbox_join_allowed_for_mode(mode: &str, invite: &GroupMailboxInvite) -> Result<()> {
    if mode.eq_ignore_ascii_case("ghost") && !invite.anonymous_group {
        bail!("Ghost mode only accepts anonymous mailbox group invites");
    }
    Ok(())
}

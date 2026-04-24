use super::*;
use crate::network::mailbox_bootstrap::verify_mailbox_bootstrap_token;

fn validate_group_mailbox_member_profile(
    profile: &GroupMailboxMemberProfile,
    group_id: &str,
) -> Result<()> {
    if profile.member_id.trim().is_empty() {
        bail!(
            "Mailbox group {} has a member profile with an empty member_id",
            group_id
        );
    }
    if profile.display_name.trim().is_empty() {
        bail!(
            "Mailbox group {} member {} has an empty display name",
            group_id,
            profile.member_id
        );
    }
    derive_did_from_verifying_key_hex(&profile.verifying_key_hex).with_context(|| {
        format!(
            "Mailbox group {} member {} has an invalid verifying key",
            group_id, profile.member_id
        )
    })?;
    parse_x25519_public_key_hex(&profile.encryption_public_key_hex).with_context(|| {
        format!(
            "Mailbox group {} member {} has an invalid X25519 public key",
            group_id, profile.member_id
        )
    })?;
    if let Some(kyber_public_key_hex) = profile.kyber_public_key_hex.as_deref() {
        let kyber_public_key = hex::decode(kyber_public_key_hex).with_context(|| {
            format!(
                "Mailbox group {} member {} has an invalid Kyber public key",
                group_id, profile.member_id
            )
        })?;
        if kyber_public_key.is_empty() {
            bail!(
                "Mailbox group {} member {} has an empty Kyber public key",
                group_id,
                profile.member_id
            );
        }
    }
    Ok(())
}

fn validate_mailbox_descriptor_fields(
    descriptor: &MailboxDescriptor,
    group_id: &str,
    mailbox_epoch: u64,
    context_label: &str,
    require_namespace_group_match: bool,
) -> Result<()> {
    if descriptor.namespace.trim().is_empty() {
        bail!(
            "{context_label} {} is missing a mailbox namespace",
            group_id
        );
    }
    if require_namespace_group_match
        && mailbox_namespace_group_label(&descriptor.namespace) != group_id
    {
        bail!(
            "{context_label} {} has a mailbox namespace/group mismatch",
            group_id
        );
    }
    let namespace_epoch = mailbox_namespace_epoch(&descriptor.namespace)?;
    if namespace_epoch != mailbox_epoch {
        bail!(
            "{context_label} {} has namespace epoch {} but mailbox epoch {}",
            group_id,
            namespace_epoch,
            mailbox_epoch
        );
    }
    if descriptor.poll_interval_ms == 0 {
        bail!(
            "{context_label} {} has invalid poll_interval_ms=0",
            group_id
        );
    }
    if descriptor.max_payload_bytes == 0 {
        bail!(
            "{context_label} {} has invalid max_payload_bytes=0",
            group_id
        );
    }
    let endpoint = descriptor.endpoint.as_deref().ok_or_else(|| {
        anyhow::anyhow!("{context_label} {} is missing a service endpoint", group_id)
    })?;
    parse_mailbox_service_endpoint(endpoint).with_context(|| {
        format!(
            "{context_label} {} has an invalid service endpoint",
            group_id
        )
    })?;
    Ok(())
}

pub(crate) fn validate_mailbox_capability_fields(
    capability: &MailboxCapability,
    group_id: &str,
    context_label: &str,
) -> Result<()> {
    if capability.capability_id.trim().is_empty() {
        bail!(
            "{context_label} {} is missing a mailbox capability id",
            group_id
        );
    }
    let mut access_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(capability.access_key_b64.as_bytes())
        .with_context(|| {
            format!(
                "{context_label} {} has an invalid mailbox access key",
                group_id
            )
        })?;
    if access_key.is_empty() {
        access_key.zeroize();
        bail!(
            "{context_label} {} has an empty mailbox access key",
            group_id
        );
    }
    let mut auth_token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(capability.auth_token_b64.as_bytes())
        .with_context(|| {
            format!(
                "{context_label} {} has an invalid mailbox auth token",
                group_id
            )
        })?;
    if auth_token.is_empty() {
        access_key.zeroize();
        auth_token.zeroize();
        bail!(
            "{context_label} {} has an empty mailbox auth token",
            group_id
        );
    }
    access_key.zeroize();
    auth_token.zeroize();
    Ok(())
}

pub(crate) fn validate_group_mailbox_join_bridge_handle(
    handle: &GroupMailboxJoinBridgeHandle,
    group_id: &str,
) -> Result<()> {
    validate_mailbox_descriptor_fields(
        &handle.mailbox_descriptor,
        group_id,
        handle.mailbox_epoch,
        "Join bridge handle for mailbox group",
        true,
    )?;
    validate_mailbox_capability_fields(
        &handle.mailbox_capability,
        group_id,
        "Join bridge handle for mailbox group",
    )?;
    if let Some(content_crypto_state) = handle.content_crypto_state.as_ref() {
        validate_group_content_crypto_state(content_crypto_state, group_id)?;
        if content_crypto_state.epoch != handle.mailbox_epoch {
            bail!(
                "Join bridge handle for mailbox group {} has crypto epoch {} but mailbox epoch {}",
                group_id,
                content_crypto_state.epoch,
                handle.mailbox_epoch
            );
        }
    }
    if let Some(token) = handle.mailbox_capability.bootstrap_token.as_ref() {
        verify_mailbox_bootstrap_token(
            token,
            None,
            &handle.mailbox_descriptor.namespace,
            &handle.mailbox_capability,
            false,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_group_mailbox_session(session: &GroupMailboxSession) -> Result<()> {
    if session.group_id.trim().is_empty() {
        bail!("Mailbox group session is missing group_id");
    }
    if let Some(local_member_id) = session.local_member_id.as_deref() {
        if local_member_id.trim().is_empty() {
            bail!(
                "Mailbox group {} has an empty local member id",
                session.group_id
            );
        }
    }
    if let Some(owner_member_id) = session.owner_member_id.as_deref() {
        if owner_member_id.trim().is_empty() {
            bail!(
                "Mailbox group {} has an empty owner member id",
                session.group_id
            );
        }
    }
    if let Some(owner_special_id) = session.owner_special_id.as_deref() {
        if owner_special_id.trim().is_empty() {
            bail!(
                "Mailbox group {} has an empty owner special id",
                session.group_id
            );
        }
    }
    validate_mailbox_descriptor_fields(
        &session.mailbox_descriptor,
        &session.group_id,
        session.mailbox_epoch,
        "Mailbox group",
        !session.anonymous_group,
    )?;
    validate_mailbox_capability_fields(
        &session.mailbox_capability,
        &session.group_id,
        "Mailbox group",
    )?;
    if let Some(token) = session.mailbox_capability.bootstrap_token.as_ref() {
        verify_mailbox_bootstrap_token(
            token,
            None,
            &session.mailbox_descriptor.namespace,
            &session.mailbox_capability,
            false,
        )?;
    }
    validate_anonymous_group_state_pair(
        session.anonymous_group,
        &session.group_id,
        session.content_crypto_state.as_ref(),
        session.anonymous_writer_state.as_ref(),
    )?;
    if let Some(content_crypto_state) = session.content_crypto_state.as_ref() {
        validate_group_content_crypto_state(content_crypto_state, &session.group_id)?;
        if content_crypto_state.epoch != session.mailbox_epoch {
            bail!(
                "Mailbox group {} has content crypto epoch {} but mailbox epoch {}",
                session.group_id,
                content_crypto_state.epoch,
                session.mailbox_epoch
            );
        }
    }
    if let Some(writer_state) = session.anonymous_writer_state.as_ref() {
        if writer_state.epoch != session.mailbox_epoch {
            bail!(
                "Mailbox group {} has anonymous writer epoch {} but mailbox epoch {}",
                session.group_id,
                writer_state.epoch,
                session.mailbox_epoch
            );
        }
    }
    for (member_id, profile) in &session.known_members {
        if member_id != &profile.member_id {
            bail!(
                "Mailbox group {} has a known member key/profile mismatch for {}",
                session.group_id,
                member_id
            );
        }
        validate_group_mailbox_member_profile(profile, &session.group_id)?;
    }
    let mut seen_join_bridge_epochs = HashSet::new();
    for handle in &session.join_bridge_handles {
        validate_group_mailbox_join_bridge_handle(handle, &session.group_id)?;
        if !seen_join_bridge_epochs.insert(handle.mailbox_epoch) {
            bail!(
                "Mailbox group {} has duplicate join bridge handle epoch {}",
                session.group_id,
                handle.mailbox_epoch
            );
        }
        if handle.mailbox_epoch >= session.mailbox_epoch {
            bail!(
                "Mailbox group {} has join bridge handle epoch {} that is not older than current epoch {}",
                session.group_id,
                handle.mailbox_epoch,
                session.mailbox_epoch
            );
        }
    }
    if session.anonymous_group {
        if session.join_locked {
            bail!(
                "Anonymous mailbox group {} must not be join-locked",
                session.group_id
            );
        }
        if session.local_member_id.is_some() {
            bail!(
                "Anonymous mailbox group {} must not store a local member id",
                session.group_id
            );
        }
        if session.owner_member_id.is_some() {
            bail!(
                "Anonymous mailbox group {} must not store an owner member id",
                session.group_id
            );
        }
        if !session.known_members.is_empty() {
            bail!(
                "Anonymous mailbox group {} must not persist known member identities",
                session.group_id
            );
        }
        if !session.join_bridge_handles.is_empty() {
            bail!(
                "Anonymous mailbox group {} must not carry join bridge handles",
                session.group_id
            );
        }
    } else {
        if session.owner_member_id.is_none() {
            bail!(
                "Identified mailbox group {} is missing an owner member id",
                session.group_id
            );
        }
        if session.owner_special_id.is_some() {
            bail!(
                "Identified mailbox group {} must not carry an anonymous owner special id",
                session.group_id
            );
        }
    }
    Ok(())
}

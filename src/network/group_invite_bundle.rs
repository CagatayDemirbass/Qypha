use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::network::contact_did::{contact_did_from_verifying_key_bytes, is_contact_did};
use crate::network::invite::GroupMailboxInvite;
use crate::network::mailbox_bootstrap::verify_mailbox_bootstrap_token;
use crate::network::mailbox_transport::parse_mailbox_service_endpoint;
use crate::network::protocol::{
    AnonymousGroupWriterCredentialAdvertisedState, GroupContentCryptoAdvertisedState,
    MailboxBootstrapScopeKind, MailboxCapability, MailboxDescriptor, MailboxTransportKind,
};

const GROUP_INVITE_BUNDLE_PREFIX: &[u8] = b"QYPHA_GROUP_INVITE_BUNDLE_V1:";
const FUTURE_SKEW_TOLERANCE_SECS: u64 = 300;

pub const GROUP_INVITE_BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteBundleGetRequest {
    pub version: u8,
    pub issuer_contact_did: String,
    pub invite_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteBundlePutRequest {
    pub version: u8,
    pub issuer_contact_did: String,
    pub bundle: GroupInviteBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteBundleGetResponse {
    pub version: u8,
    pub issuer_contact_did: String,
    pub invite_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<GroupInviteBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteBundle {
    pub version: u8,
    pub invite_id: String,
    pub group_id: String,
    #[serde(default)]
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    #[serde(default)]
    pub join_locked: bool,
    pub mailbox_descriptor: MailboxDescriptor,
    pub mailbox_capability: MailboxCapability,
    #[serde(default)]
    pub content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    #[serde(default)]
    pub anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
    #[serde(default)]
    pub issuer_did: Option<String>,
    pub issuer_verifying_key: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGroupMailboxInvite {
    pub group_id: String,
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    pub join_locked: bool,
    pub mailbox_descriptor: MailboxDescriptor,
    pub mailbox_capability: MailboxCapability,
    pub content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    pub anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
    pub issuer_did: Option<String>,
    pub issuer_verifying_key_hex: String,
    pub invite_id: String,
    pub expiry: u64,
}

fn write_canonical_str(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn write_canonical_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

fn write_canonical_opt_str(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            buf.push(0x01);
            write_canonical_str(buf, value);
        }
        None => buf.push(0x00),
    }
}

fn write_canonical_mailbox_descriptor(buf: &mut Vec<u8>, descriptor: &MailboxDescriptor) {
    write_canonical_str(buf, &descriptor.namespace);
    write_canonical_opt_str(buf, descriptor.endpoint.as_deref());
    buf.push(match descriptor.transport {
        MailboxTransportKind::Tor => 0u8,
    });
    buf.extend_from_slice(&descriptor.poll_interval_ms.to_le_bytes());
    buf.extend_from_slice(&(descriptor.max_payload_bytes as u64).to_le_bytes());
}

fn write_canonical_mailbox_bootstrap_token(
    buf: &mut Vec<u8>,
    value: &crate::network::protocol::MailboxBootstrapToken,
) {
    buf.push(value.version);
    buf.push(match value.scope_kind {
        MailboxBootstrapScopeKind::Invite => 0x01,
        MailboxBootstrapScopeKind::EpochRotation => 0x02,
        MailboxBootstrapScopeKind::ChunkTransfer => 0x03,
    });
    write_canonical_str(buf, &value.scope_id);
    write_canonical_str(buf, &value.namespace);
    write_canonical_str(buf, &value.capability_id);
    write_canonical_str(buf, &value.access_key_sha256);
    write_canonical_str(buf, &value.auth_token_sha256);
    buf.extend_from_slice(&value.issued_at.to_le_bytes());
    buf.extend_from_slice(&value.expires_at.to_le_bytes());
    write_canonical_str(buf, &value.issuer_verifying_key_hex);
    buf.push(value.pow_difficulty_bits);
    write_canonical_str(buf, &value.pow_nonce_hex);
    write_canonical_str(buf, &value.signature_b64);
}

fn write_canonical_mailbox_capability(buf: &mut Vec<u8>, capability: &MailboxCapability) {
    write_canonical_str(buf, &capability.capability_id);
    write_canonical_str(buf, &capability.access_key_b64);
    write_canonical_str(buf, &capability.auth_token_b64);
    match capability.bootstrap_token.as_ref() {
        Some(token) => {
            buf.push(0x01);
            write_canonical_mailbox_bootstrap_token(buf, token);
        }
        None => buf.push(0x00),
    }
}

fn write_canonical_group_content_crypto_state(
    buf: &mut Vec<u8>,
    state: &GroupContentCryptoAdvertisedState,
) {
    buf.push(state.version);
    write_canonical_str(buf, state.suite.as_str());
    buf.extend_from_slice(&state.epoch.to_le_bytes());
    write_canonical_str(buf, &state.content_secret_b64);
}

fn write_canonical_opt_group_content_crypto_state(
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

fn write_canonical_anonymous_writer_state(
    buf: &mut Vec<u8>,
    state: &AnonymousGroupWriterCredentialAdvertisedState,
) {
    buf.push(state.version);
    write_canonical_str(buf, state.suite.as_str());
    buf.extend_from_slice(&state.epoch.to_le_bytes());
    write_canonical_str(buf, &state.writer_secret_b64);
}

fn write_canonical_opt_anonymous_writer_state(
    buf: &mut Vec<u8>,
    state: Option<&AnonymousGroupWriterCredentialAdvertisedState>,
) {
    match state {
        Some(state) => {
            buf.push(0x01);
            write_canonical_anonymous_writer_state(buf, state);
        }
        None => buf.push(0x00),
    }
}

impl GroupInviteBundleGetRequest {
    pub fn new(issuer_contact_did: impl Into<String>, invite_id: impl Into<String>) -> Self {
        Self {
            version: GROUP_INVITE_BUNDLE_VERSION,
            issuer_contact_did: issuer_contact_did.into(),
            invite_id: invite_id.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != GROUP_INVITE_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported group invite bundle request version {}",
                self.version
            );
        }
        if !is_contact_did(&self.issuer_contact_did) {
            anyhow::bail!("Invalid Qypha DID format");
        }
        if self.invite_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle request missing invite_id");
        }
        Ok(())
    }
}

impl GroupInviteBundlePutRequest {
    pub fn new(issuer_contact_did: impl Into<String>, bundle: GroupInviteBundle) -> Self {
        Self {
            version: GROUP_INVITE_BUNDLE_VERSION,
            issuer_contact_did: issuer_contact_did.into(),
            bundle,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != GROUP_INVITE_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported group invite bundle publish version {}",
                self.version
            );
        }
        verify_group_invite_bundle(&self.issuer_contact_did, &self.bundle)
    }
}

impl GroupInviteBundleGetResponse {
    pub fn empty(issuer_contact_did: impl Into<String>, invite_id: impl Into<String>) -> Self {
        Self {
            version: GROUP_INVITE_BUNDLE_VERSION,
            issuer_contact_did: issuer_contact_did.into(),
            invite_id: invite_id.into(),
            bundle: None,
        }
    }

    pub fn with_bundle(
        issuer_contact_did: impl Into<String>,
        invite_id: impl Into<String>,
        bundle: GroupInviteBundle,
    ) -> Self {
        Self {
            version: GROUP_INVITE_BUNDLE_VERSION,
            issuer_contact_did: issuer_contact_did.into(),
            invite_id: invite_id.into(),
            bundle: Some(bundle),
        }
    }

    pub fn into_verified_bundle(self) -> Result<Option<GroupInviteBundle>> {
        if self.version != GROUP_INVITE_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported group invite bundle response version {}",
                self.version
            );
        }
        if !is_contact_did(&self.issuer_contact_did) {
            anyhow::bail!("Invalid Qypha DID format");
        }
        if self.invite_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle response missing invite_id");
        }
        match self.bundle {
            Some(bundle) => {
                verify_group_invite_bundle(&self.issuer_contact_did, &bundle)?;
                if bundle.invite_id != self.invite_id {
                    anyhow::bail!("Group invite bundle response invite_id mismatch");
                }
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }
}

impl GroupInviteBundle {
    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(768);
        data.extend_from_slice(GROUP_INVITE_BUNDLE_PREFIX);
        data.push(self.version);
        write_canonical_str(&mut data, &self.invite_id);
        write_canonical_str(&mut data, &self.group_id);
        write_canonical_opt_str(&mut data, self.group_name.as_deref());
        data.push(u8::from(self.anonymous_group));
        data.push(u8::from(self.join_locked));
        write_canonical_mailbox_descriptor(&mut data, &self.mailbox_descriptor);
        write_canonical_mailbox_capability(&mut data, &self.mailbox_capability);
        write_canonical_opt_group_content_crypto_state(
            &mut data,
            self.content_crypto_state.as_ref(),
        );
        write_canonical_opt_anonymous_writer_state(&mut data, self.anonymous_writer_state.as_ref());
        write_canonical_opt_str(&mut data, self.issuer_did.as_deref());
        write_canonical_bytes(&mut data, &self.issuer_verifying_key);
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        data
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_group_invite(
        signing_key: &ed25519_dalek::SigningKey,
        invite: &GroupMailboxInvite,
        group_name: Option<&str>,
        join_locked: bool,
        mailbox_descriptor: MailboxDescriptor,
        mailbox_capability: MailboxCapability,
        content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
        anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
        issuer_did: Option<&str>,
    ) -> Result<Self> {
        if invite.group_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle requires group_id");
        }
        if invite.invite_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle requires invite_id");
        }
        if invite.anonymous_group && issuer_did.is_some() {
            anyhow::bail!("Anonymous group invite bundles must not embed issuer DID");
        }
        if invite.anonymous_group && join_locked {
            anyhow::bail!("Anonymous group invite bundles must not advertise join_locked");
        }
        if invite.anonymous_group
            && (content_crypto_state.is_some() != anonymous_writer_state.is_some())
        {
            anyhow::bail!(
                "Anonymous group invite bundles must embed content crypto state and anonymous writer state together"
            );
        }
        if !invite.anonymous_group && anonymous_writer_state.is_some() {
            anyhow::bail!("Identified group invite bundles must not embed anonymous writer state");
        }

        let mut bundle = Self {
            version: GROUP_INVITE_BUNDLE_VERSION,
            invite_id: invite.invite_id.clone(),
            group_id: invite.group_id.clone(),
            group_name: group_name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            anonymous_group: invite.anonymous_group,
            join_locked,
            mailbox_descriptor,
            mailbox_capability,
            content_crypto_state,
            anonymous_writer_state,
            issuer_did: issuer_did.map(str::to_string),
            issuer_verifying_key: invite.issuer_verifying_key,
            created_at: invite.created_at,
            expires_at: invite.expiry,
            signature: Vec::new(),
        };
        let signature = signing_key.sign(&bundle.signing_data());
        bundle.signature = signature.to_bytes().to_vec();
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<bool> {
        if self.version != GROUP_INVITE_BUNDLE_VERSION {
            anyhow::bail!("Unsupported group invite bundle version {}", self.version);
        }
        if self.group_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle missing group_id");
        }
        if self.invite_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle missing invite_id");
        }
        if self.mailbox_descriptor.namespace.trim().is_empty() {
            anyhow::bail!("Group invite bundle missing mailbox namespace");
        }
        let endpoint = self
            .mailbox_descriptor
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Group invite bundle missing mailbox endpoint"))?;
        parse_mailbox_service_endpoint(endpoint)?;
        if self.mailbox_descriptor.poll_interval_ms == 0 {
            anyhow::bail!("Group invite bundle poll interval must be greater than zero");
        }
        if self.mailbox_descriptor.max_payload_bytes == 0 {
            anyhow::bail!("Group invite bundle max payload must be greater than zero");
        }
        if self.mailbox_capability.capability_id.trim().is_empty() {
            anyhow::bail!("Group invite bundle missing capability id");
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.mailbox_capability.access_key_b64.as_bytes())
            .context("Group invite bundle access key is not valid base64")?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.mailbox_capability.auth_token_b64.as_bytes())
            .context("Group invite bundle auth token is not valid base64")?;
        if self.anonymous_group
            && (self.content_crypto_state.is_some() != self.anonymous_writer_state.is_some())
        {
            anyhow::bail!(
                "Anonymous group invite bundle must expose content crypto state and anonymous writer state together"
            );
        }
        if self.anonymous_group && self.issuer_did.is_some() {
            anyhow::bail!("Anonymous group invite bundle must not expose issuer DID");
        }
        if self.anonymous_group && self.join_locked {
            anyhow::bail!("Anonymous group invite bundle must not advertise join_locked");
        }
        if !self.anonymous_group && self.anonymous_writer_state.is_some() {
            anyhow::bail!("Identified group invite bundle must not expose anonymous writer state");
        }
        let bootstrap_token = self
            .mailbox_capability
            .bootstrap_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Group invite bundle missing bootstrap token"))?;
        verify_mailbox_bootstrap_token(
            bootstrap_token,
            Some(MailboxBootstrapScopeKind::Invite),
            &self.mailbox_descriptor.namespace,
            &self.mailbox_capability,
            true,
        )?;
        if bootstrap_token.scope_id != self.invite_id {
            anyhow::bail!("Group invite bundle bootstrap token invite_id mismatch");
        }
        if bootstrap_token.expires_at != self.expires_at {
            anyhow::bail!("Group invite bundle bootstrap token expiry mismatch");
        }
        if bootstrap_token.issuer_verifying_key_hex != hex::encode(self.issuer_verifying_key) {
            anyhow::bail!("Group invite bundle bootstrap token issuer mismatch");
        }

        let verifying_key = VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .context("Invalid Ed25519 verifying key")?;
        if let Some(ref issuer_did) = self.issuer_did {
            let expected_did =
                crate::crypto::identity::derive_did_from_verifying_key(&verifying_key);
            if issuer_did != &expected_did {
                anyhow::bail!(
                    "Group invite bundle DID/key mismatch: claimed DID '{}' does not match verifying key fingerprint '{}'",
                    issuer_did,
                    expected_did
                );
            }
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid group invite bundle signature format"))?;
        let verified = verifying_key
            .verify_strict(&self.signing_data(), &signature)
            .is_ok();
        if !verified {
            return Ok(false);
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if self.created_at > now + FUTURE_SKEW_TOLERANCE_SECS {
            anyhow::bail!(
                "Group invite bundle has future timestamp (clock skew {} seconds). Synchronize system clocks.",
                self.created_at - now
            );
        }
        if self.expires_at <= self.created_at {
            anyhow::bail!("Group invite bundle expiry must be after creation time");
        }
        if now > self.expires_at {
            anyhow::bail!("Group invite bundle EXPIRED. Generate a fresh invite.");
        }
        Ok(true)
    }

    pub fn resolve_against_token(
        &self,
        invite: &GroupMailboxInvite,
    ) -> Result<ResolvedGroupMailboxInvite> {
        if !self.verify()? {
            anyhow::bail!("Group invite bundle signature invalid");
        }
        if !invite.verify_with_expiry()? {
            anyhow::bail!("Group invite signature invalid");
        }
        if self.invite_id != invite.invite_id {
            anyhow::bail!("Group invite bundle invite_id mismatch");
        }
        if self.group_id != invite.group_id {
            anyhow::bail!("Group invite bundle group_id mismatch");
        }
        if self.anonymous_group != invite.anonymous_group {
            anyhow::bail!("Group invite bundle anonymity mismatch");
        }
        if self.issuer_verifying_key != invite.issuer_verifying_key {
            anyhow::bail!("Group invite bundle issuer key mismatch");
        }
        if self.expires_at != invite.expiry {
            anyhow::bail!("Group invite bundle expiry mismatch");
        }

        Ok(ResolvedGroupMailboxInvite {
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
            anonymous_group: self.anonymous_group,
            join_locked: self.join_locked,
            mailbox_descriptor: self.mailbox_descriptor.clone(),
            mailbox_capability: self.mailbox_capability.clone(),
            content_crypto_state: self.content_crypto_state.clone(),
            anonymous_writer_state: self.anonymous_writer_state.clone(),
            issuer_did: self.issuer_did.clone(),
            issuer_verifying_key_hex: hex::encode(self.issuer_verifying_key),
            invite_id: self.invite_id.clone(),
            expiry: self.expires_at,
        })
    }

    pub fn issuer_contact_did(&self) -> String {
        contact_did_from_verifying_key_bytes(self.issuer_verifying_key)
    }
}

pub fn verify_group_invite_bundle(
    issuer_contact_did: &str,
    bundle: &GroupInviteBundle,
) -> Result<()> {
    if !is_contact_did(issuer_contact_did) {
        anyhow::bail!("Invalid Qypha DID format");
    }
    let expected = contact_did_from_verifying_key_bytes(bundle.issuer_verifying_key);
    if issuer_contact_did != expected {
        anyhow::bail!(
            "Group invite bundle contact DID mismatch: expected '{}' but got '{}'",
            expected,
            issuer_contact_did
        );
    }
    if !bundle.verify()? {
        anyhow::bail!("Group invite bundle signature invalid");
    }
    Ok(())
}

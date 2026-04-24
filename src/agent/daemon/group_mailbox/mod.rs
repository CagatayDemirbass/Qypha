use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use aegis::aegis256::Aegis256;
use anyhow::{bail, Context, Result};
use base64::Engine;
use colored::Colorize;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroize;

use super::handshake_request_gate::{self, HandshakeOfferDecision, HandshakeRequestGate};
use crate::artifact::chunked_transfer::{self, ChunkedReceiveSession};
use crate::config::AppConfig;
use crate::control_plane::audit::{AuditLog, LogMode};
use crate::crypto::encryption::{
    hybrid_decrypt_message, hybrid_encrypt_message, EncryptedEnvelope,
};
use crate::crypto::identity::AgentKeyPair;
use crate::network::invite::{GroupMailboxInvite, INVITE_TTL_TOR_SECS};
use crate::network::mailbox_bootstrap::{
    issue_mailbox_bootstrap_token, verify_mailbox_bootstrap_token,
};
use crate::network::mailbox_service::{
    start_mailbox_service_background, start_memory_mailbox_service_background, MailboxServiceHandle,
};
use crate::network::mailbox_transport::{
    parse_mailbox_service_endpoint, MailboxPollRequest, MailboxPostReceipt, MailboxServiceEndpoint,
    MailboxTransport, MAILBOX_CURSOR_TAIL,
};
use crate::network::protocol::{
    AnonymousGroupWriterCredentialAdvertisedState, AnonymousGroupWriterCredentialSuite,
    ChunkTransferInitPayload, DirectHandshakeOfferPayload, GroupChatPayload,
    GroupChunkCapabilityPayload, GroupContentCryptoAdvertisedState, GroupContentCryptoSuite,
    GroupDisbandPayload, GroupFastFileAcceptPayload, GroupFastFileGrantPayload,
    GroupFastFileGrantSecret, GroupFastFileOfferPayload, GroupFastFileStatusPayload,
    GroupFileChunkCompletePayload, GroupFileChunkPayload, GroupFileManifestPayload,
    GroupKickNoticePayload, GroupMailboxMessage, GroupMailboxMessageKind,
    MailboxBootstrapScopeKind, MailboxCapability, MailboxDescriptor, MailboxRotationPayload,
    MailboxTransportKind, MembershipNoticePayload, MembershipNoticeState,
};
use crate::network::tor_mailbox::TorMailboxTransport;
use crate::os_adapter::secure_wipe::{secure_wipe_dir, secure_wipe_file};

use super::paths::{
    create_ghost_handoff_dir, emit_transfer_event_with_group, emit_transfer_event_with_handoff,
    emit_transfer_progress_event_with_group, ghost_secure_handoff_enabled, runtime_temp_path,
};
use super::receive_dir::{
    effective_receive_base_dir, ensure_private_receive_dir, ReceiveDirConfig,
};
use super::repl::print_async_notice;

mod invariants;
mod logging;
mod protocol;
mod registry;
mod runtime;
mod service;
mod transfers;
mod utils;

pub(crate) use self::invariants::*;
pub(crate) use self::logging::*;
pub(crate) use self::protocol::*;
pub(crate) use self::registry::*;
pub(crate) use self::runtime::*;
pub(crate) use self::service::*;
pub(crate) use self::transfers::*;

pub(crate) use self::utils::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMailboxPersistence {
    MemoryOnly,
    EncryptedDisk,
}

#[derive(Debug, Clone)]
pub struct GroupMailboxSession {
    pub group_id: String,
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    pub join_locked: bool,
    pub mailbox_descriptor: MailboxDescriptor,
    pub mailbox_capability: MailboxCapability,
    pub content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    pub anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
    pub local_member_id: Option<String>,
    pub owner_member_id: Option<String>,
    pub persistence: GroupMailboxPersistence,
    pub joined_at: u64,
    pub invite_id: String,
    pub owner_special_id: Option<String>,
    pub mailbox_epoch: u64,
    pub poll_cursor: Option<String>,
    next_cover_traffic_at: Option<u64>,
    last_real_activity_at: Option<u64>,
    known_members: HashMap<String, GroupMailboxMemberProfile>,
    local_posted_message_ids: HashSet<String>,
    seen_message_ids: HashMap<String, u64>,
    join_bridge_handles: Vec<GroupMailboxJoinBridgeHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMailboxMemberSummary {
    pub member_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMailboxSummary {
    pub group_id: String,
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    #[serde(default)]
    pub anonymous_security_state: Option<String>,
    pub join_locked: bool,
    pub persistence: GroupMailboxPersistence,
    pub local_member_id: Option<String>,
    pub owner_member_id: Option<String>,
    pub owner_special_id: Option<String>,
    #[serde(default)]
    pub known_members: Vec<GroupMailboxMemberSummary>,
    pub known_member_ids: Vec<String>,
    pub mailbox_epoch: u64,
    #[serde(default)]
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMailboxDelivery {
    pub group_id: String,
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    pub message_id: String,
    pub kind: GroupMailboxMessageKind,
    pub sender_member_id: Option<String>,
    pub chat_body: Option<String>,
    pub file_manifest: Option<GroupFileManifestPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMailboxUiEvent {
    pub kind: String,
    pub group_id: String,
    pub group_name: Option<String>,
    pub anonymous_group: bool,
    pub manifest_id: Option<String>,
    pub sender_member_id: Option<String>,
    pub message: Option<String>,
    pub filename: Option<String>,
    pub size_bytes: Option<u64>,
    pub member_id: Option<String>,
    pub member_display_name: Option<String>,
    pub invite_code: Option<String>,
    pub mailbox_epoch: Option<u64>,
    pub kicked_member_id: Option<String>,
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMailboxMemberProfile {
    pub member_id: String,
    pub display_name: String,
    pub verifying_key_hex: String,
    pub encryption_public_key_hex: String,
    pub kyber_public_key_hex: Option<String>,
}

#[derive(Debug, Default)]
pub struct GroupMailboxRegistry {
    sessions: HashMap<String, GroupMailboxSession>,
    tombstones: HashMap<String, GroupMailboxTombstone>,
    chunk_downloads: HashMap<String, GroupChunkDownloadState>,
    pending_file_offers: HashMap<String, GroupPendingFileOffer>,
    pending_handshake_offers: HashMap<String, GroupPendingHandshakeOffer>,
    pending_fast_file_offers: HashMap<String, GroupPendingFastFileOffer>,
    staged_fast_file_transfers: HashMap<String, GroupStagedFastFileTransfer>,
    pending_fast_file_grants: HashMap<String, GroupFastFileGrantState>,
    active_fast_file_sender_refs: HashMap<String, u32>,
    mailbox_transport_backoff: HashMap<String, MailboxTransportBackoffState>,
    mailbox_manual_refresh_at: HashMap<String, u64>,
    persist_path: Option<PathBuf>,
    persist_key: Option<[u8; 32]>,
}

pub(crate) struct ResolvedMailboxEndpoint {
    pub(crate) endpoint: String,
    pub(crate) auto_provisioned: bool,
    pub(crate) selected_from_pool: bool,
}

pub(crate) struct EmbeddedMailboxServiceState {
    endpoint: String,
    handle: MailboxServiceHandle,
    #[allow(dead_code)]
    ephemeral_root: Option<TempDir>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MailboxTransportBackoffState {
    failures: u32,
    next_attempt_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MailboxTransportFailureOutcome {
    pub(crate) failures: u32,
    pub(crate) next_retry_after_ms: u64,
    pub(crate) should_log: bool,
    pub(crate) degraded: bool,
}

pub(crate) const MAILBOX_TRANSPORT_DEGRADED_FAILURE_THRESHOLD: u32 = 3;
const MAILBOX_MANUAL_REFRESH_MIN_INTERVAL_MS: u64 = 1_000;
// Identified-group membership notices should survive long enough for peers that
// reconnect or resume polling slightly later than the join event. Keeping them
// aligned with the normal direct/group message TTL avoids owners missing a new
// member and then rejecting that member's authenticated chat/file traffic as
// "unknown sender".
pub(crate) const GROUP_IDENTIFIED_MEMBERSHIP_NOTICE_TTL_MS: u64 = 300_000;
pub(crate) const GROUP_DISBAND_NOTICE_TTL_MS: u64 = 300_000;
const GROUP_DISBAND_RELAY_GRACE_PERIOD_MS: u64 = 120_000;
// Keep identified-group join-bridge notices alive for the full invite lifetime so
// older-but-still-valid invites can resolve the current mailbox epoch after
// owner lock/unlock rotations instead of silently falling back to a stale epoch.
pub(crate) const GROUP_JOIN_BRIDGE_NOTICE_TTL_MS: u64 = INVITE_TTL_TOR_SECS * 1_000;
const GROUP_MAILBOX_JOIN_PREFLIGHT_POLL_LIMIT: usize = 128;
const GROUP_MAILBOX_JOIN_PREFLIGHT_MAX_ITEMS: usize = 4_096;

pub(crate) fn mailbox_transport_is_degraded(failures: u32) -> bool {
    failures >= MAILBOX_TRANSPORT_DEGRADED_FAILURE_THRESHOLD
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SealedGroupMailboxPayload {
    version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedGroupMailboxBlob {
    version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedGroupMailboxRegistry {
    version: u8,
    sessions: Vec<PersistedGroupMailboxSession>,
    #[serde(default)]
    tombstones: Vec<PersistedGroupMailboxTombstone>,
    #[serde(default)]
    chunk_downloads: Vec<GroupChunkDownloadState>,
    #[serde(default)]
    pending_file_offers: Vec<GroupPendingFileOffer>,
    #[serde(default)]
    pending_handshake_offers: Vec<GroupPendingHandshakeOffer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedGroupMailboxSession {
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    #[serde(default)]
    join_locked: bool,
    mailbox_descriptor: MailboxDescriptor,
    mailbox_capability: MailboxCapability,
    #[serde(default)]
    content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    #[serde(default)]
    anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
    local_member_id: Option<String>,
    owner_member_id: Option<String>,
    joined_at: u64,
    invite_id: String,
    owner_special_id: Option<String>,
    mailbox_epoch: u64,
    poll_cursor: Option<String>,
    known_members: Vec<GroupMailboxMemberProfile>,
    #[serde(default)]
    join_bridge_handles: Vec<GroupMailboxJoinBridgeHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupMailboxTombstone {
    group_id: String,
    mailbox_epoch: u64,
    join_locked: bool,
    disbanded: bool,
    left_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupMailboxJoinBridgeHandle {
    mailbox_epoch: u64,
    mailbox_descriptor: MailboxDescriptor,
    mailbox_capability: MailboxCapability,
    #[serde(default)]
    content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedGroupMailboxTombstone {
    group_id: String,
    mailbox_epoch: u64,
    #[serde(default)]
    join_locked: bool,
    #[serde(default)]
    disbanded: bool,
    left_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnonymousMailboxInnerKind {
    Chat,
    FileManifest,
    FileChunkData,
    FileChunkComplete,
    Cover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedGroupMailboxMessage {
    kind: Option<GroupMailboxMessageKind>,
    payload: Vec<u8>,
    authenticated_sender: Option<AuthenticatedGroupMailboxSender>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedGroupMailboxSender {
    member_id: String,
    verifying_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuthenticatedGroupMailboxPayload {
    version: u8,
    kind: GroupMailboxMessageKind,
    group_id: String,
    sender_member_id: String,
    sender_verifying_key_hex: String,
    mailbox_epoch: u64,
    message_id: String,
    created_at: u64,
    created_at_ms: u64,
    payload: Vec<u8>,
    #[serde(default)]
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AnonymousAuthenticatedMailboxPayload {
    version: u8,
    kind: GroupMailboxMessageKind,
    group_id: String,
    mailbox_epoch: u64,
    message_id: String,
    created_at: u64,
    created_at_ms: u64,
    payload: Vec<u8>,
    #[serde(default)]
    auth_tag: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct MailboxRotationSecret {
    group_id: String,
    mailbox_descriptor: MailboxDescriptor,
    mailbox_capability: MailboxCapability,
    #[serde(default)]
    content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    owner_member_id: String,
    new_mailbox_epoch: u64,
    #[serde(default)]
    join_locked: bool,
    #[serde(default)]
    join_bridge_handles: Vec<GroupMailboxJoinBridgeHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GroupChunkDownloadState {
    transfer_id: String,
    artifact_id: String,
    manifest_id: String,
    group_id: String,
    filename: String,
    sender_member_id: Option<String>,
    crypto_context: GroupMailboxCryptoContext,
    mailbox_descriptor: MailboxDescriptor,
    mailbox_capability: MailboxCapability,
    poll_cursor: Option<String>,
    persistence: GroupMailboxPersistence,
    recv: ChunkedReceiveSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupMailboxCryptoContext {
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    anonymous_group: bool,
    #[serde(default = "empty_mailbox_capability")]
    mailbox_capability: MailboxCapability,
    #[serde(default)]
    content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    #[serde(default)]
    anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GroupPendingFileOffer {
    manifest_id: String,
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    sender_member_id: Option<String>,
    persistence: GroupMailboxPersistence,
    crypto_context: GroupMailboxCryptoContext,
    manifest: GroupFileManifestPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupPendingFileOfferSummary {
    pub(crate) manifest_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) anonymous_group: bool,
    pub(crate) sender_member_id: Option<String>,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupPendingHandshakeOffer {
    sender_member_id: String,
    group_id: String,
    group_name: Option<String>,
    persistence: GroupMailboxPersistence,
    invite_code: String,
    received_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupPendingHandshakeOfferSummary {
    pub(crate) sender_member_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) received_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupPendingFastFileOffer {
    transfer_id: String,
    manifest_id: String,
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    sender_member_id: Option<String>,
    offer: GroupFastFileOfferPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupPendingFastFileOfferSummary {
    pub(crate) transfer_id: String,
    pub(crate) manifest_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) anonymous_group: bool,
    pub(crate) sender_member_id: Option<String>,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) relay_only: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupStagedFastFileTransfer {
    pub(crate) transfer_id: String,
    pub(crate) mailbox_transfer_id: String,
    pub(crate) manifest_id: String,
    pub(crate) group_id: String,
    pub(crate) group_name: Option<String>,
    pub(crate) sender_member_id: String,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) file_manifest_hash: String,
    pub(crate) plaintext_sha256: String,
    pub(crate) merkle_root: [u8; 32],
    pub(crate) total_chunks: usize,
    pub(crate) chunk_size: usize,
    pub(crate) relay_only: bool,
    pub(crate) endpoint_addr_json: String,
    pub(crate) endpoint_verifying_key_hex: String,
    pub(crate) expires_at: u64,
    pub(crate) packed_path: PathBuf,
    pub(crate) fast_session: chunked_transfer::TransferSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum GroupFastFileGrantEnvelope {
    Accept(GroupFastFileAcceptPayload),
    Grant(GroupFastFileGrantPayload),
    Status(GroupFastFileStatusPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupFastFileGrantState {
    transfer_id: String,
    grant_id: Option<String>,
    group_id: String,
    recipient_member_id: String,
    relay_only: bool,
    expires_at: u64,
    envelope: GroupFastFileGrantEnvelope,
    secret: Option<GroupFastFileGrantSecret>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedFastGroupTransfer {
    pub(crate) transfer_id: String,
    pub(crate) mailbox_transfer_id: String,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) plaintext_sha256: String,
    pub(crate) merkle_root: [u8; 32],
    pub(crate) total_chunks: usize,
    pub(crate) chunk_size: usize,
    pub(crate) relay_only: bool,
    pub(crate) expires_at: u64,
    pub(crate) packed_path: PathBuf,
    pub(crate) fast_session: chunked_transfer::TransferSession,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupPendingFastFileGrantLaunch {
    pub(crate) transfer_id: String,
    pub(crate) group_id: String,
    pub(crate) sender_member_id: String,
    pub(crate) sender_verifying_key_hex: String,
    pub(crate) secret: GroupFastFileGrantSecret,
}

const MAILBOX_MAX_CLOCK_SKEW_SECS: u64 = 10 * 60;
const MAILBOX_DEFAULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const MAILBOX_MAX_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAILBOX_RUNTIME_SEEN_MESSAGE_LIMIT: usize = 2048;
const GROUP_CHUNK_MIN_BYTES: usize = 16 * 1024;
const GROUP_CHUNK_MAX_BYTES: usize = 128 * 1024;
const GHOST_ANON_EPHEMERAL_MIN_RETENTION_MS: u64 = 5_000;
const GHOST_ANON_EPHEMERAL_MAX_RETENTION_MS: u64 = 15_000;
const GHOST_ANON_COVER_SLOT_MS: u64 = 6_000;
const GHOST_ANON_COVER_JITTER_MS: i64 = 750;
const MAILBOX_TRANSPORT_MIN_RETRY_MS: u64 = 5_000;
const MAILBOX_TRANSPORT_MAX_RETRY_MS: u64 = 60_000;
const MAILBOX_PRIVACY_DUMMY_POLLS_PER_TICK: usize = 1;
const GROUP_FAST_FILE_GRANT_TTL_SECS: u64 = 120;
const GHOST_ANON_PAD_BUCKETS: &[usize] = &[
    384, 512, 768, 1_024, 1_536, 2_048, 3_072, 4_096, 6_144, 8_192, 12_288, 16_384, 24_576, 32_768,
    40_960,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AgentConfig, AppConfig, LoggingConfig, NetworkConfig, RolesConfig, SecurityConfig,
        TransferConfig,
    };
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::mailbox_service::spawn_loopback_mailbox_service;
    use async_trait::async_trait;
    use base64::Engine as _;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn sample_app_config() -> AppConfig {
        AppConfig {
            agent: AgentConfig {
                name: "test-agent".to_string(),
                role: "agent".to_string(),
                did: "did:nxf:test-agent".to_string(),
            },
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            roles: RolesConfig::default(),
            transfer: TransferConfig::default(),
        }
    }

    fn blob_contains(haystack: &[u8], needle: &str) -> bool {
        let needle = needle.as_bytes();
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn sample_content_crypto_state(epoch: u64) -> GroupContentCryptoAdvertisedState {
        GroupContentCryptoAdvertisedState {
            version: 1,
            suite: GroupContentCryptoSuite::EpochAegis256,
            epoch,
            content_secret_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([42u8; 32]),
        }
    }

    fn sample_anonymous_writer_state(epoch: u64) -> AnonymousGroupWriterCredentialAdvertisedState {
        AnonymousGroupWriterCredentialAdvertisedState {
            version: 1,
            suite: AnonymousGroupWriterCredentialSuite::EpochHmacSha256,
            epoch,
            writer_secret_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([24u8; 32]),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_resolved_group_invite(
        signing_key: &ed25519_dalek::SigningKey,
        issuer_did: Option<&str>,
        group_id: &str,
        group_name: Option<&str>,
        anonymous_group: bool,
        join_locked: bool,
        mailbox_descriptor: MailboxDescriptor,
        mailbox_capability: MailboxCapability,
        content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
        anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
        expiry: u64,
    ) -> (
        GroupMailboxInvite,
        crate::network::group_invite_bundle::ResolvedGroupMailboxInvite,
    ) {
        let mut mailbox_capability = mailbox_capability;
        let invite = GroupMailboxInvite::generate_with_join_locked(
            signing_key,
            issuer_did,
            group_id,
            group_name,
            anonymous_group,
            join_locked,
            mailbox_descriptor.clone(),
            mailbox_capability.clone(),
            content_crypto_state.clone(),
            anonymous_writer_state.clone(),
            expiry,
        )
        .unwrap();
        issue_group_mailbox_bootstrap_token(
            signing_key,
            MailboxBootstrapScopeKind::Invite,
            &invite.invite_id,
            &mailbox_descriptor,
            &mut mailbox_capability,
            invite.expiry,
        )
        .unwrap();
        let bundle = crate::network::group_invite_bundle::GroupInviteBundle::from_group_invite(
            signing_key,
            &invite,
            group_name,
            join_locked,
            mailbox_descriptor,
            mailbox_capability,
            content_crypto_state,
            anonymous_writer_state,
            issuer_did,
        )
        .unwrap();
        let resolved = bundle.resolve_against_token(&invite).unwrap();
        (invite, resolved)
    }

    fn resolve_group_invite_from_session(
        signing_key: &ed25519_dalek::SigningKey,
        invite: &GroupMailboxInvite,
        session: &GroupMailboxSession,
    ) -> crate::network::group_invite_bundle::ResolvedGroupMailboxInvite {
        build_group_invite_bundle_from_session(signing_key, invite, session)
            .unwrap()
            .resolve_against_token(invite)
            .unwrap()
    }

    #[derive(Clone)]
    struct AckFailingMailboxTransport {
        inner: TorMailboxTransport,
    }

    #[async_trait]
    impl MailboxTransport for AckFailingMailboxTransport {
        async fn post_message(
            &self,
            descriptor: &MailboxDescriptor,
            capability: &MailboxCapability,
            message: &GroupMailboxMessage,
        ) -> Result<MailboxPostReceipt> {
            self.inner
                .post_message(descriptor, capability, message)
                .await
        }

        async fn poll_messages(
            &self,
            descriptor: &MailboxDescriptor,
            capability: &MailboxCapability,
            request: &MailboxPollRequest,
        ) -> Result<crate::network::mailbox_transport::MailboxPollResult> {
            self.inner
                .poll_messages(descriptor, capability, request)
                .await
        }

        async fn ack_messages(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            _envelope_ids: &[String],
        ) -> Result<()> {
            anyhow::bail!("synthetic ack failure");
        }
    }

    #[derive(Clone, Default)]
    struct RecordingMailboxTransport {
        poll_requests: Arc<tokio::sync::Mutex<Vec<MailboxPollRequest>>>,
    }

    #[async_trait]
    impl MailboxTransport for RecordingMailboxTransport {
        async fn post_message(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            _message: &GroupMailboxMessage,
        ) -> Result<MailboxPostReceipt> {
            Ok(MailboxPostReceipt {
                message_id: "dummy".to_string(),
                server_cursor: Some("0".to_string()),
            })
        }

        async fn poll_messages(
            &self,
            _descriptor: &MailboxDescriptor,
            _capability: &MailboxCapability,
            request: &MailboxPollRequest,
        ) -> Result<crate::network::mailbox_transport::MailboxPollResult> {
            self.poll_requests.lock().await.push(request.clone());
            Ok(crate::network::mailbox_transport::MailboxPollResult {
                items: Vec::new(),
                next_cursor: request.cursor.clone(),
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

    #[test]
    fn registry_tracks_joined_mailbox_group() {
        let keypair = AgentKeyPair::generate("MailboxOwner", "agent");
        let (_, resolved_invite) = create_resolved_group_invite(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_registry",
            Some("Registry"),
            false,
            false,
            build_mailbox_descriptor(
                "grp_registry",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            MailboxCapability {
                capability_id: "cap_registry".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([6u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::MemoryOnly,
                Some("did:nxf:member".to_string()),
            )
            .unwrap();

        let session = registry.get("grp_registry").unwrap();
        assert_eq!(session.group_name.as_deref(), Some("Registry"));
        assert_eq!(session.local_member_id.as_deref(), Some("did:nxf:member"));
        assert_eq!(registry.list_group_ids(), vec!["grp_registry".to_string()]);
        assert!(session.owner_special_id.is_none());
    }

    #[test]
    fn join_from_invite_uses_mailbox_epoch_from_namespace() {
        let keypair = AgentKeyPair::generate("MailboxOwner", "agent");
        let (_, resolved_invite) = create_resolved_group_invite(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_registry_epoch",
            Some("Registry Epoch"),
            false,
            false,
            MailboxDescriptor {
                transport: MailboxTransportKind::Tor,
                namespace: rotated_mailbox_namespace("grp_registry_epoch", 3),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_registry_epoch".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::MemoryOnly,
                Some("did:nxf:member".to_string()),
            )
            .unwrap();

        let session = registry.get("grp_registry_epoch").unwrap();
        assert_eq!(session.mailbox_epoch, 3);
    }

    #[test]
    fn build_mailbox_descriptor_uses_unpredictable_epoch_zero_namespace() {
        let descriptor_a = build_mailbox_descriptor(
            "grp_namespace_hardening",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let descriptor_b = build_mailbox_descriptor(
            "grp_namespace_hardening",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();

        assert_ne!(descriptor_a.namespace, descriptor_b.namespace);
        assert_eq!(
            mailbox_namespace_group_label(&descriptor_a.namespace),
            "grp_namespace_hardening"
        );
        assert_eq!(mailbox_namespace_epoch(&descriptor_a.namespace).unwrap(), 0);
    }

    #[test]
    fn join_from_invite_rejects_stale_locked_invite_after_leave() {
        let owner = AgentKeyPair::generate("MailboxOwner", "agent");
        let (_, resolved_invite) = create_resolved_group_invite(
            &owner.signing_key,
            Some(&owner.did),
            "grp_rejoin_locked",
            Some("Locked Rejoin"),
            false,
            false,
            build_mailbox_descriptor(
                "grp_rejoin_locked",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            MailboxCapability {
                capability_id: "cap_rejoin_locked".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([10u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:member".to_string()),
            )
            .unwrap();

        let mut session = registry.get_cloned("grp_rejoin_locked").unwrap();
        session.mailbox_epoch = 2;
        session.join_locked = true;
        session.mailbox_descriptor.namespace = rotated_mailbox_namespace("grp_rejoin_locked", 2);
        session.mailbox_capability = build_mailbox_capability();
        registry
            .sessions
            .insert(session.group_id.clone(), session.clone());

        let removed = registry.remove_group("grp_rejoin_locked").unwrap();
        assert!(removed.is_some());

        let error = registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:member".to_string()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("stale") || error.to_string().contains("locked"));
    }

    #[test]
    fn join_from_invite_rejects_invite_marked_join_locked() {
        let owner = AgentKeyPair::generate("MailboxOwner", "agent");
        let (_, resolved_invite) = create_resolved_group_invite(
            &owner.signing_key,
            Some(&owner.did),
            "grp_locked_invite",
            Some("Locked Invite"),
            false,
            true,
            build_mailbox_descriptor(
                "grp_locked_invite",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            MailboxCapability {
                capability_id: "cap_locked_invite".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([12u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        let mut registry = GroupMailboxRegistry::default();
        let error = registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:member".to_string()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("locked"));
    }

    #[test]
    fn join_from_invite_rejects_disbanded_group_at_same_epoch() {
        let owner = AgentKeyPair::generate("MailboxOwner", "agent");
        let (_, resolved_invite) = create_resolved_group_invite(
            &owner.signing_key,
            Some(&owner.did),
            "grp_rejoin_disbanded",
            Some("Disbanded Rejoin"),
            false,
            false,
            build_mailbox_descriptor(
                "grp_rejoin_disbanded",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            MailboxCapability {
                capability_id: "cap_rejoin_disbanded".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([12u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:member".to_string()),
            )
            .unwrap();
        registry
            .remove_group_as_disbanded("grp_rejoin_disbanded")
            .unwrap();

        let error = registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:member".to_string()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("disbanded"));
    }

    #[test]
    fn identified_group_creation_tracks_local_member_profile() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, invite) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_ops",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        assert!(!session.anonymous_group);
        assert_eq!(
            session.local_member_id.as_deref(),
            Some(keypair.did.as_str())
        );
        assert_eq!(session.known_members.len(), 1);
        assert!(session.known_members.contains_key(&keypair.did));
        let resolved_invite =
            resolve_group_invite_from_session(&keypair.signing_key, &invite, &session);
        assert_eq!(
            resolved_invite.issuer_did.as_deref(),
            Some(keypair.did.as_str())
        );
        assert!(invite.verify_with_expiry().unwrap());
    }

    #[test]
    fn session_validator_rejects_namespace_epoch_mismatch() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (mut session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_invariant_epoch",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();

        session.mailbox_descriptor.namespace = rotated_mailbox_namespace("grp_invariant_epoch", 7);

        let error = validate_group_mailbox_session(&session).unwrap_err();
        assert!(error.to_string().contains("namespace epoch"));
    }

    #[test]
    fn session_validator_rejects_anonymous_identity_fields() {
        let (mut session, _) = create_ghost_anonymous_group(
            Some("Ghost Invariant"),
            build_mailbox_descriptor(
                "grp_ghost_invariant",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        session.local_member_id = Some("did:nxf:leak".to_string());

        let error = validate_group_mailbox_session(&session).unwrap_err();
        assert!(error
            .to_string()
            .contains("must not store a local member id"));
    }

    #[test]
    fn registry_insert_session_rejects_invalid_endpoint_state() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (mut session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_invalid_insert",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();
        session.mailbox_descriptor.endpoint = None;

        let mut registry = GroupMailboxRegistry::default();
        let error = registry.insert_session(session).unwrap_err();
        assert!(error.to_string().contains("service endpoint"));
        assert!(registry.get("grp_invalid_insert").is_none());
    }

    #[test]
    fn ghost_anonymous_group_creation_hides_owner_identity() {
        let descriptor = build_mailbox_descriptor(
            "grp_ghost_ops",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, invite, bundle) = create_ghost_anonymous_group_with_id_and_bundle(
            "grp_ghost_ops",
            Some("Ghost Ops"),
            descriptor,
        )
        .unwrap();
        let resolved_invite = bundle.resolve_against_token(&invite).unwrap();

        assert_eq!(session.persistence, GroupMailboxPersistence::MemoryOnly);
        assert!(session.local_member_id.is_none());
        assert!(session.owner_special_id.is_some());
        assert!(invite.anonymous_group);
        assert!(session.content_crypto_state.is_some());
        assert!(session.anonymous_writer_state.is_some());
        assert!(resolved_invite.issuer_did.is_none());
        assert!(resolved_invite.content_crypto_state.is_some());
        assert!(resolved_invite.anonymous_writer_state.is_some());
        assert!(invite.verify_with_expiry().unwrap());
    }

    #[test]
    fn anonymous_group_join_starts_at_mailbox_tail() {
        let descriptor = build_mailbox_descriptor(
            "grp_ghost_tail",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (_, invite, bundle) = create_ghost_anonymous_group_with_id_and_bundle(
            "grp_ghost_tail",
            Some("Ghost Tail"),
            descriptor,
        )
        .unwrap();
        let resolved_invite = bundle.resolve_against_token(&invite).unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(&resolved_invite, GroupMailboxPersistence::MemoryOnly, None)
            .unwrap();

        let session = registry.get("grp_ghost_tail").unwrap();
        assert_eq!(session.poll_cursor.as_deref(), Some(MAILBOX_CURSOR_TAIL));
    }

    #[test]
    fn chat_message_roundtrip_uses_mailbox_sealing() {
        let keypair = AgentKeyPair::generate("GhostChat", "agent");
        let descriptor = build_ghost_anonymous_mailbox_descriptor(
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) =
            create_ghost_anonymous_group_with_id("grp_ghost_chat", Some("Ghost Chat"), descriptor)
                .unwrap();
        let message = build_chat_message(&session, &keypair, "hello mailbox", 5_000).unwrap();

        assert_eq!(message.kind, GroupMailboxMessageKind::AnonymousOpaque);
        assert!(message.sender_member_id.is_none());
        assert_ne!(message.group_id, session.group_id);
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let decoded: GroupChatPayload = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(decoded.body, "hello mailbox");
    }

    #[test]
    fn anonymous_v2_payload_fails_closed_without_writer_state() {
        let keypair = AgentKeyPair::generate("GhostChat", "agent");
        let descriptor = build_mailbox_descriptor(
            "grp_ghost_authz",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_ghost_anonymous_group_with_id(
            "grp_ghost_authz",
            Some("Ghost Authz"),
            descriptor,
        )
        .unwrap();
        let message =
            build_chat_message(&session, &keypair, "hello hardened ghost", 5_000).unwrap();

        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let decoded: GroupChatPayload = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(decoded.body, "hello hardened ghost");

        let missing_writer_context = GroupMailboxCryptoContext {
            anonymous_writer_state: None,
            ..crypto_context_for_session(&session)
        };
        assert!(
            decode_group_mailbox_message_with_context(&missing_writer_context, &message).is_err()
        );
    }

    #[tokio::test]
    async fn file_manifest_roundtrip_keeps_inline_ciphertext_encrypted() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("ghost.txt");
        std::fs::write(&file_path, b"secret").unwrap();
        let keypair = AgentKeyPair::generate("Ghost", "agent");
        let descriptor = build_ghost_anonymous_mailbox_descriptor(
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_ghost_anonymous_group_with_id(
            "grp_ghost_files",
            Some("Ghost Files"),
            descriptor,
        )
        .unwrap();

        let transport = TorMailboxTransport::default();
        let message = build_file_manifest_message(
            &transport,
            &session,
            &keypair,
            file_path.to_str().unwrap(),
            10_000,
            false,
        )
        .await
        .unwrap();
        assert_eq!(message.kind, GroupMailboxMessageKind::AnonymousOpaque);
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let manifest: GroupFileManifestPayload = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(manifest.filename, "ghost.txt");
        assert!(manifest.fast_transfer_id.is_none());
        assert!(manifest.fast_transfer_expires_at.is_none());
        let inline = manifest.inline_ciphertext.unwrap();
        let recovered = decode_group_inline_blob(&session, &inline).unwrap();
        assert_eq!(recovered, b"secret");
    }

    #[tokio::test]
    async fn large_group_file_manifest_uses_chunk_capability() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("large.bin");
        std::fs::write(&file_path, vec![7u8; 96 * 1024]).unwrap();
        let keypair = AgentKeyPair::generate("Large", "agent");
        let transport = TorMailboxTransport::new(temp.path().join("mailbox-client"));
        let descriptor = build_ghost_anonymous_mailbox_descriptor(
            &format!("http://127.0.0.1:{}", addr.port()),
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_ghost_anonymous_group_with_id(
            "grp_ghost_large",
            Some("Ghost Files"),
            descriptor,
        )
        .unwrap();

        let message = build_file_manifest_message(
            &transport,
            &session,
            &keypair,
            file_path.to_str().unwrap(),
            10_000,
            false,
        )
        .await
        .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let manifest: GroupFileManifestPayload = serde_json::from_slice(&plaintext).unwrap();
        assert!(manifest.inline_ciphertext.is_none());
        assert!(manifest.fast_transfer_id.is_none());
        assert!(manifest.fast_transfer_expires_at.is_none());
        let capability = decode_group_chunk_capability(
            manifest
                .chunk_capability
                .as_deref()
                .expect("chunk capability"),
        )
        .unwrap();
        assert!(capability.total_chunks >= 1);

        let result = transport
            .poll_messages(
                &capability.mailbox_descriptor,
                &capability.mailbox_capability,
                &MailboxPollRequest {
                    cursor: None,
                    limit: 256,
                },
            )
            .await
            .unwrap();
        assert!(!result.items.is_empty());
        let chunk_context = GroupMailboxCryptoContext {
            group_id: session.group_id.clone(),
            anonymous_group: true,
            mailbox_capability: capability.mailbox_capability.clone(),
            content_crypto_state: session.content_crypto_state.clone(),
            anonymous_writer_state: session.anonymous_writer_state.clone(),
        };
        assert!(result.items.iter().any(|item| {
            decode_group_mailbox_message_with_context(&chunk_context, &item.message)
                .ok()
                .and_then(|decoded| decoded.kind)
                == Some(GroupMailboxMessageKind::FileChunkComplete)
        }));
        handle.abort();
    }

    #[tokio::test]
    async fn identified_large_group_manifest_sets_fast_transfer_hints_when_enabled() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("large-fast.bin");
        std::fs::write(&file_path, vec![9u8; 96 * 1024]).unwrap();
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let transport = TorMailboxTransport::new(temp.path().join("mailbox-client"));
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let descriptor = build_mailbox_descriptor(
            "grp_fast_identified",
            &format!("http://127.0.0.1:{}", addr.port()),
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Ops"),
            descriptor,
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();

        let message = build_file_manifest_message(
            &transport,
            &session,
            &keypair,
            file_path.to_str().unwrap(),
            10_000,
            true,
        )
        .await
        .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let manifest: GroupFileManifestPayload = serde_json::from_slice(&plaintext).unwrap();
        assert!(manifest.chunk_capability.is_none());
        assert!(manifest.fast_transfer_id.is_some());
        assert!(manifest.fast_transfer_expires_at.is_some());
        assert!(manifest.fast_relay_only);
        handle.abort();
    }

    #[test]
    fn legacy_mailbox_payload_roundtrip_uses_v1_envelope() {
        let context = GroupMailboxCryptoContext {
            group_id: "grp_legacy_v1".to_string(),
            anonymous_group: false,
            mailbox_capability: build_mailbox_capability(),
            content_crypto_state: None,
            anonymous_writer_state: None,
        };
        let sealed = seal_bytes_with_context(&context, "message/chat", b"legacy").unwrap();
        let payload: SealedGroupMailboxPayload = serde_json::from_slice(&sealed).unwrap();
        assert_eq!(payload.version, 1);
        assert_eq!(
            open_bytes_with_context(&context, "message/chat", &sealed).unwrap(),
            b"legacy"
        );
    }

    #[test]
    fn content_crypto_state_roundtrip_uses_v2_envelope_and_fails_closed_without_state() {
        let context = GroupMailboxCryptoContext {
            group_id: "grp_v2".to_string(),
            anonymous_group: true,
            mailbox_capability: build_mailbox_capability(),
            content_crypto_state: Some(sample_content_crypto_state(7)),
            anonymous_writer_state: Some(sample_anonymous_writer_state(7)),
        };
        let sealed =
            seal_bytes_with_context(&context, "message/anonymous_opaque", b"ghost").unwrap();
        let payload: SealedGroupMailboxPayload = serde_json::from_slice(&sealed).unwrap();
        assert_eq!(payload.version, 2);
        assert_eq!(
            open_bytes_with_context(&context, "message/anonymous_opaque", &sealed).unwrap(),
            b"ghost"
        );

        let missing_state_context = GroupMailboxCryptoContext {
            content_crypto_state: None,
            anonymous_writer_state: None,
            ..context
        };
        assert!(open_bytes_with_context(
            &missing_state_context,
            "message/anonymous_opaque",
            &sealed,
        )
        .is_err());
    }

    #[test]
    fn persisted_session_roundtrip_preserves_optional_content_crypto_state() {
        let session = GroupMailboxSession {
            group_id: "grp_persist_v2".to_string(),
            group_name: Some("Persist".to_string()),
            anonymous_group: false,
            join_locked: false,
            mailbox_descriptor: MailboxDescriptor {
                transport: MailboxTransportKind::Tor,
                namespace: rotated_mailbox_namespace("grp_persist_v2", 3),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            mailbox_capability: build_mailbox_capability(),
            content_crypto_state: Some(sample_content_crypto_state(3)),
            anonymous_writer_state: None,
            local_member_id: Some("did:nxf:local".to_string()),
            owner_member_id: Some("did:nxf:local".to_string()),
            persistence: GroupMailboxPersistence::EncryptedDisk,
            joined_at: 123,
            invite_id: "invite_1".to_string(),
            owner_special_id: None,
            mailbox_epoch: 3,
            poll_cursor: Some("cursor".to_string()),
            next_cover_traffic_at: None,
            last_real_activity_at: None,
            known_members: HashMap::new(),
            local_posted_message_ids: HashSet::new(),
            seen_message_ids: HashMap::new(),
            join_bridge_handles: vec![GroupMailboxJoinBridgeHandle {
                mailbox_epoch: 2,
                mailbox_descriptor: MailboxDescriptor {
                    transport: MailboxTransportKind::Tor,
                    namespace: rotated_mailbox_namespace("grp_persist_v2", 2),
                    endpoint: Some(
                        "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                            .to_string(),
                    ),
                    poll_interval_ms: 5_000,
                    max_payload_bytes: 256 * 1024,
                },
                mailbox_capability: build_mailbox_capability(),
                content_crypto_state: Some(sample_content_crypto_state(2)),
            }],
        };

        let persisted = PersistedGroupMailboxSession::from_session(&session);
        let restored = persisted.into_session().unwrap();
        assert_eq!(restored.content_crypto_state, session.content_crypto_state);
        assert_eq!(
            restored.join_bridge_handles[0].content_crypto_state,
            session.join_bridge_handles[0].content_crypto_state
        );
    }

    #[test]
    fn fast_file_accept_message_roundtrip_verifies_signature() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_fast_accept",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();

        let message =
            build_fast_file_accept_message(&session, &keypair, "gft_123", 30_000).unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let payload: GroupFastFileAcceptPayload = serde_json::from_slice(&plaintext).unwrap();
        let recipient_member_id = decrypt_fast_file_accept_payload(
            &payload,
            message.sender_member_id.as_deref(),
            &session.group_id,
        )
        .unwrap();
        assert_eq!(recipient_member_id, keypair.did);
    }

    #[test]
    fn ghost_anonymous_cover_message_decodes_without_application_payload() {
        let descriptor = build_ghost_anonymous_mailbox_descriptor(
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_ghost_anonymous_group_with_id(
            "grp_ghost_cover",
            Some("Ghost Cover"),
            descriptor,
        )
        .unwrap();

        let message = build_ghost_anonymous_cover_message(&session).unwrap();
        let decoded = decode_group_mailbox_message_with_context(
            &crypto_context_for_session(&session),
            &message,
        )
        .unwrap();

        assert_eq!(message.kind, GroupMailboxMessageKind::AnonymousOpaque);
        assert!(decoded.kind.is_none());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn anonymous_invite_regeneration_rotates_epoch_and_invalidates_old_session_context() {
        let keypair = AgentKeyPair::generate("GhostRotate", "agent");
        let descriptor = build_mailbox_descriptor(
            "grp_ghost_rotate",
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
            5_000,
            256 * 1024,
        )
        .unwrap();
        let (session, _) = create_ghost_anonymous_group_with_id(
            "grp_ghost_rotate",
            Some("Ghost Rotate"),
            descriptor,
        )
        .unwrap();
        let old_content = session.content_crypto_state.clone();
        let old_writer = session.anonymous_writer_state.clone();

        let (rotated_session, invite, bundle) =
            regenerate_anonymous_group_invite_with_bundle(&session).unwrap();
        let resolved_invite = bundle.resolve_against_token(&invite).unwrap();
        assert_eq!(rotated_session.mailbox_epoch, session.mailbox_epoch + 1);
        assert_ne!(
            rotated_session.mailbox_descriptor,
            session.mailbox_descriptor
        );
        assert_ne!(
            rotated_session.mailbox_capability,
            session.mailbox_capability
        );
        assert_ne!(rotated_session.content_crypto_state, old_content);
        assert_ne!(rotated_session.anonymous_writer_state, old_writer);
        assert_eq!(
            resolved_invite.content_crypto_state,
            rotated_session.content_crypto_state
        );
        assert_eq!(
            resolved_invite.anonymous_writer_state,
            rotated_session.anonymous_writer_state
        );
        assert!(invite.verify_with_expiry().unwrap());

        let rotated_message =
            build_chat_message(&rotated_session, &keypair, "new epoch only", 5_000).unwrap();
        let rotated_plaintext =
            decode_group_mailbox_message_payload(&rotated_session, &rotated_message).unwrap();
        let decoded: GroupChatPayload = serde_json::from_slice(&rotated_plaintext).unwrap();
        assert_eq!(decoded.body, "new epoch only");
        assert!(decode_group_mailbox_message_payload(&session, &rotated_message).is_err());
    }

    #[test]
    fn membership_notice_roundtrip_verifies_sender_profile() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_membership",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        let message =
            build_membership_notice_message(&session, &keypair.signing_key, &local_profile, 5_000)
                .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let payload: MembershipNoticePayload = serde_json::from_slice(&plaintext).unwrap();
        let (verified, notice_state) =
            verify_membership_notice_payload(&payload, message.sender_member_id.as_deref())
                .unwrap();

        assert_eq!(verified.member_id, keypair.did);
        assert_eq!(verified.display_name, "Alice");
        assert_eq!(notice_state, MembershipNoticeState::Joined);
        assert_eq!(
            verified.kyber_public_key_hex.as_deref(),
            local_profile.kyber_public_key_hex.as_deref()
        );
    }

    #[test]
    fn membership_leave_notice_roundtrip_verifies_sender_profile() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_membership_leave",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        let message = build_membership_notice_message_with_state(
            &session,
            &keypair.signing_key,
            &local_profile,
            MembershipNoticeState::Left,
            5_000,
        )
        .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let payload: MembershipNoticePayload = serde_json::from_slice(&plaintext).unwrap();
        let (verified, notice_state) =
            verify_membership_notice_payload(&payload, message.sender_member_id.as_deref())
                .unwrap();

        assert_eq!(verified.member_id, keypair.did);
        assert_eq!(verified.display_name, "Alice");
        assert_eq!(notice_state, MembershipNoticeState::Left);
    }

    #[test]
    fn group_disband_message_roundtrip_verifies_owner() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_disband_notice",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();

        let message = build_group_disband_message(
            &session,
            &owner.signing_key,
            &owner_profile,
            GROUP_DISBAND_NOTICE_TTL_MS,
        )
        .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let payload: GroupDisbandPayload = serde_json::from_slice(&plaintext).unwrap();
        let sender_member_id = verify_group_disband_payload(
            &payload,
            message.sender_member_id.as_deref(),
            &session.group_id,
            session.owner_member_id.as_deref(),
        )
        .unwrap();

        assert_eq!(sender_member_id, owner.did);
        assert_eq!(payload.mailbox_epoch, session.mailbox_epoch);
    }

    #[test]
    fn legacy_join_membership_notice_still_verifies() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let created_at = current_unix_ts();
        let unsigned_payload = MembershipNoticePayload {
            group_id: "grp_legacy_notice".to_string(),
            member_id: keypair.did.clone(),
            display_name: "Alice".to_string(),
            verifying_key_hex: local_profile.verifying_key_hex.clone(),
            encryption_public_key_hex: local_profile.encryption_public_key_hex.clone(),
            kyber_public_key_hex: local_profile.kyber_public_key_hex.clone(),
            state: MembershipNoticeState::Joined,
            created_at,
            signature: Vec::new(),
        };
        let payload = MembershipNoticePayload {
            group_id: unsigned_payload.group_id.clone(),
            member_id: unsigned_payload.member_id.clone(),
            display_name: unsigned_payload.display_name.clone(),
            verifying_key_hex: unsigned_payload.verifying_key_hex.clone(),
            encryption_public_key_hex: unsigned_payload.encryption_public_key_hex.clone(),
            kyber_public_key_hex: unsigned_payload.kyber_public_key_hex.clone(),
            state: unsigned_payload.state,
            created_at,
            signature: keypair
                .signing_key
                .sign(&membership_notice_signing_data_v1(&unsigned_payload))
                .to_bytes()
                .to_vec(),
        };

        let (verified, notice_state) =
            verify_membership_notice_payload(&payload, Some(keypair.did.as_str())).unwrap();
        assert_eq!(verified.member_id, keypair.did);
        assert_eq!(notice_state, MembershipNoticeState::Joined);
    }

    #[tokio::test]
    async fn identified_membership_notice_is_reciprocated_for_late_joiners() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let late = AgentKeyPair::generate("agent3", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let late_profile = build_local_member_profile(&late, "agent3");
        let (owner_session, invite) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_late_joiner", &endpoint, 5_000, 256 * 1024).unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);

        let owner_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        owner_registry
            .lock()
            .await
            .insert_session(owner_session)
            .unwrap();

        let late_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        late_registry
            .lock()
            .await
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some(late.did.clone()),
            )
            .unwrap();
        announce_local_identified_membership(
            &late_registry,
            &transport,
            &late.signing_key,
            &late_profile,
            &invite.group_id,
        )
        .await
        .unwrap();

        let owner_audit_dir = tempdir().unwrap();
        let late_audit_dir = tempdir().unwrap();
        let owner_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                owner_audit_dir.path(),
                &owner.did,
                &[7u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let late_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(late_audit_dir.path(), &late.did, &[8u8; 32], LogMode::Safe).unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once(
            &owner_registry,
            &handshake_request_gate,
            &transport,
            &owner_audit,
            &owner.did,
            "owner",
            &owner,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;
        poll_group_mailboxes_once(
            &late_registry,
            &handshake_request_gate,
            &transport,
            &late_audit,
            &late.did,
            "late",
            &late,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        let late_summary = late_registry
            .lock()
            .await
            .summaries()
            .into_iter()
            .find(|group| group.group_id == invite.group_id)
            .unwrap();
        assert!(late_summary.known_member_ids.contains(&owner.did));
        assert!(late_summary.known_member_ids.contains(&late.did));

        handle.abort();
    }

    #[tokio::test]
    async fn preflight_group_join_rejects_locked_rotation_seen_in_old_mailbox_epoch() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let bob = AgentKeyPair::generate("agent2", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let bob_profile = build_local_member_profile(&bob, "agent2");
        let (mut owner_session, invite) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_locked_preflight", &endpoint, 5_000, 256 * 1024).unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile);
        let (_, rotation_messages) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();
        for (_, message) in &rotation_messages {
            transport
                .post_message(
                    &owner_session.mailbox_descriptor,
                    &owner_session.mailbox_capability,
                    message,
                )
                .await
                .unwrap();
        }

        let error = preflight_group_mailbox_join(&resolved_invite, &transport)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("locked"));
        handle.abort();
    }

    #[tokio::test]
    async fn preflight_group_join_reuses_old_invite_after_unlock_bridge_update() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let (owner_session, invite) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_unlock_bridge", &endpoint, 5_000, 256 * 1024).unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);

        let (locked_session, _) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();
        let lock_outcomes = publish_group_join_bridge_updates(
            &transport,
            &locked_session,
            &owner.signing_key,
            GROUP_JOIN_BRIDGE_NOTICE_TTL_MS,
        )
        .await;
        assert!(lock_outcomes.iter().all(|(_, outcome)| outcome.is_ok()));

        let (unlocked_session, _) =
            plan_owner_access_rotation(&locked_session, &owner.signing_key, false).unwrap();
        let unlock_outcomes = publish_group_join_bridge_updates(
            &transport,
            &unlocked_session,
            &owner.signing_key,
            GROUP_JOIN_BRIDGE_NOTICE_TTL_MS,
        )
        .await;
        assert!(unlock_outcomes.iter().all(|(_, outcome)| outcome.is_ok()));

        let resolved_invite = preflight_group_mailbox_join(&resolved_invite, &transport)
            .await
            .unwrap();
        assert_eq!(
            resolved_invite.mailbox_descriptor,
            unlocked_session.mailbox_descriptor
        );
        assert_eq!(
            resolved_invite.mailbox_capability,
            unlocked_session.mailbox_capability
        );

        let mut registry = GroupMailboxRegistry::default();
        registry
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some("did:nxf:late-joiner".to_string()),
            )
            .unwrap();
        let joined = registry.get("grp_unlock_bridge").unwrap();
        assert_eq!(joined.mailbox_epoch, unlocked_session.mailbox_epoch);
        handle.abort();
    }

    #[test]
    fn join_bridge_notice_ttl_covers_identified_invite_lifetime() {
        assert!(
            GROUP_JOIN_BRIDGE_NOTICE_TTL_MS >= INVITE_TTL_TOR_SECS * 1_000,
            "join-bridge notices must stay alive for at least the full invite lifetime"
        );
    }

    #[tokio::test]
    async fn identified_membership_leave_notice_removes_member_from_remote_roster() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let member = AgentKeyPair::generate("agent2", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let member_profile = build_local_member_profile(&member, "agent2");
        let (owner_session, invite) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_member_leave", &endpoint, 5_000, 256 * 1024).unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);

        let owner_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        owner_registry
            .lock()
            .await
            .insert_session(owner_session)
            .unwrap();

        let member_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        member_registry
            .lock()
            .await
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some(member.did.clone()),
            )
            .unwrap();
        announce_local_identified_membership(
            &member_registry,
            &transport,
            &member.signing_key,
            &member_profile,
            &invite.group_id,
        )
        .await
        .unwrap();

        let owner_audit_dir = tempdir().unwrap();
        let member_audit_dir = tempdir().unwrap();
        let owner_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                owner_audit_dir.path(),
                &owner.did,
                &[7u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let member_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                member_audit_dir.path(),
                &member.did,
                &[8u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once(
            &owner_registry,
            &handshake_request_gate,
            &transport,
            &owner_audit,
            &owner.did,
            "owner",
            &owner,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        let owner_summary = owner_registry
            .lock()
            .await
            .summaries()
            .into_iter()
            .find(|group| group.group_id == invite.group_id)
            .unwrap();
        assert!(owner_summary.known_member_ids.contains(&member.did));

        announce_local_identified_departure(
            &member_registry,
            &transport,
            &member.signing_key,
            &member_profile,
            &invite.group_id,
        )
        .await
        .unwrap();

        poll_group_mailboxes_once(
            &owner_registry,
            &handshake_request_gate,
            &transport,
            &owner_audit,
            &owner.did,
            "owner",
            &owner,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        let owner_summary = owner_registry
            .lock()
            .await
            .summaries()
            .into_iter()
            .find(|group| group.group_id == invite.group_id)
            .unwrap();
        assert!(!owner_summary.known_member_ids.contains(&member.did));

        poll_group_mailboxes_once(
            &member_registry,
            &handshake_request_gate,
            &transport,
            &member_audit,
            &member.did,
            "member",
            &member,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        handle.abort();
    }

    #[tokio::test]
    async fn identified_group_disband_notice_removes_group_from_remote_registry() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let member = AgentKeyPair::generate("agent2", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let owner_session = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_disband_remote", &endpoint, 5_000, 256 * 1024).unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap()
        .0;
        let invite =
            regenerate_identified_group_invite(&owner_session, &owner.signing_key, &owner.did)
                .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);

        let owner_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        owner_registry
            .lock()
            .await
            .insert_session(owner_session.clone())
            .unwrap();
        let member_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        member_registry
            .lock()
            .await
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some(member.did.clone()),
            )
            .unwrap();

        let disband = build_group_disband_message(
            &owner_session,
            &owner.signing_key,
            &owner_profile,
            GROUP_DISBAND_NOTICE_TTL_MS,
        )
        .unwrap();
        post_group_mailbox_message(&transport, &owner_session, &disband)
            .await
            .unwrap();

        let owner_audit_dir = tempdir().unwrap();
        let member_audit_dir = tempdir().unwrap();
        let owner_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                owner_audit_dir.path(),
                &owner.did,
                &[7u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let member_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                member_audit_dir.path(),
                &member.did,
                &[8u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once(
            &member_registry,
            &handshake_request_gate,
            &transport,
            &member_audit,
            &member.did,
            "member",
            &member,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        assert!(member_registry.lock().await.summaries().is_empty());

        poll_group_mailboxes_once(
            &owner_registry,
            &handshake_request_gate,
            &transport,
            &owner_audit,
            &owner.did,
            "owner",
            &owner,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        handle.abort();
    }

    #[tokio::test]
    async fn identified_group_kick_notice_removes_kicked_member_registry() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let owner = AgentKeyPair::generate("agent1", "agent");
        let member = AgentKeyPair::generate("agent2", "agent");
        let owner_profile = build_local_member_profile(&owner, "agent1");
        let owner_session = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor("grp_kick_notice_remote", &endpoint, 5_000, 256 * 1024)
                .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap()
        .0;
        let invite =
            regenerate_identified_group_invite(&owner_session, &owner.signing_key, &owner.did)
                .unwrap();
        let resolved_invite =
            resolve_group_invite_from_session(&owner.signing_key, &invite, &owner_session);

        let owner_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        owner_registry
            .lock()
            .await
            .insert_session(owner_session.clone())
            .unwrap();
        let member_registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        member_registry
            .lock()
            .await
            .join_from_invite(
                &resolved_invite,
                GroupMailboxPersistence::EncryptedDisk,
                Some(member.did.clone()),
            )
            .unwrap();

        let kick_notice = build_group_kick_notice_message(
            &owner_session,
            &owner.signing_key,
            &owner_profile,
            &build_local_member_profile(&member, "agent2"),
            1,
            60_000,
        )
        .unwrap();
        post_group_mailbox_message(&transport, &owner_session, &kick_notice)
            .await
            .unwrap();

        let owner_audit_dir = tempdir().unwrap();
        let member_audit_dir = tempdir().unwrap();
        let owner_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                owner_audit_dir.path(),
                &owner.did,
                &[7u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let member_audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(
                member_audit_dir.path(),
                &member.did,
                &[8u8; 32],
                LogMode::Safe,
            )
            .unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once(
            &member_registry,
            &handshake_request_gate,
            &transport,
            &member_audit,
            &member.did,
            "member",
            &member,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        assert!(member_registry.lock().await.summaries().is_empty());

        poll_group_mailboxes_once(
            &owner_registry,
            &handshake_request_gate,
            &transport,
            &owner_audit,
            &owner.did,
            "owner",
            &owner,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        handle.abort();
    }

    #[test]
    fn direct_handshake_offer_roundtrip_is_only_openable_by_target() {
        let sender = AgentKeyPair::generate("Alice", "agent");
        let recipient = AgentKeyPair::generate("Bob", "agent");
        let intruder = AgentKeyPair::generate("Mallory", "agent");
        let sender_profile = build_local_member_profile(&sender, "Alice");
        let recipient_profile = build_local_member_profile(&recipient, "Bob");
        let (mut session, _) = create_identified_group(
            &sender.signing_key,
            &sender.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_direct_offer",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            sender_profile.clone(),
        )
        .unwrap();
        session.known_members.insert(
            recipient_profile.member_id.clone(),
            recipient_profile.clone(),
        );

        let message = build_direct_handshake_offer_message(
            &session,
            &sender.signing_key,
            &sender_profile,
            &recipient_profile,
            "invite-code-123",
            5_000,
        )
        .unwrap();
        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let payload = decode_direct_handshake_offer_payload_bytes(&plaintext).unwrap();
        let decrypted = decrypt_direct_handshake_offer_payload(
            &payload,
            &recipient,
            message.sender_member_id.as_deref(),
            &recipient.did,
        )
        .unwrap();

        assert_eq!(decrypted.0, sender.did);
        assert_eq!(decrypted.1, "invite-code-123");
        assert!(decrypt_direct_handshake_offer_payload(
            &payload,
            &intruder,
            message.sender_member_id.as_deref(),
            &recipient.did,
        )
        .is_err());
    }

    #[test]
    fn legacy_json_direct_handshake_offer_payload_still_decrypts() {
        let sender = AgentKeyPair::generate("Alice", "agent");
        let recipient = AgentKeyPair::generate("Bob", "agent");
        let sender_profile = build_local_member_profile(&sender, "Alice");
        let recipient_profile = build_local_member_profile(&recipient, "Bob");
        let (mut session, _) = create_identified_group(
            &sender.signing_key,
            &sender.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_direct_offer_legacy",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            sender_profile.clone(),
        )
        .unwrap();
        session.known_members.insert(
            recipient_profile.member_id.clone(),
            recipient_profile.clone(),
        );

        let recipient_x25519 =
            parse_x25519_public_key_hex(&recipient_profile.encryption_public_key_hex).unwrap();
        let recipient_kyber = hex::decode(
            recipient_profile
                .kyber_public_key_hex
                .as_deref()
                .expect("recipient should have Kyber profile"),
        )
        .unwrap();
        let envelope = hybrid_encrypt_message(
            &recipient_x25519,
            Some(recipient_kyber.as_slice()),
            b"legacy-invite",
        )
        .unwrap();
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let mut payload = DirectHandshakeOfferPayload {
            offer_id: format!("goffer_{}", uuid::Uuid::new_v4().simple()),
            group_id: session.group_id.clone(),
            sender_member_id: sender_profile.member_id.clone(),
            sender_verifying_key_hex: sender_profile.verifying_key_hex.clone(),
            target_member_id: recipient_profile.member_id.clone(),
            encrypted_invite_envelope: envelope_bytes,
            created_at: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
        };
        payload.signature = sender
            .signing_key
            .sign(&direct_handshake_offer_signing_data(&payload))
            .to_bytes()
            .to_vec();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let (created_at, created_at_ms) = current_mailbox_message_timestamps();
        let message = GroupMailboxMessage {
            version: 1,
            message_id: format!("gmsg_{}", uuid::Uuid::new_v4().simple()),
            group_id: session.group_id.clone(),
            anonymous_group: false,
            sender_member_id: Some(sender_profile.member_id.clone()),
            kind: GroupMailboxMessageKind::DirectHandshakeOffer,
            created_at,
            created_at_ms,
            ttl_ms: 5_000,
            ciphertext: seal_bytes(&session, "message/direct_handshake_offer", &payload_bytes)
                .unwrap(),
        };

        let plaintext = decode_group_mailbox_message_payload(&session, &message).unwrap();
        let decoded = decode_direct_handshake_offer_payload_bytes(&plaintext).unwrap();
        let decrypted = decrypt_direct_handshake_offer_payload(
            &decoded,
            &recipient,
            message.sender_member_id.as_deref(),
            &recipient.did,
        )
        .unwrap();

        assert_eq!(decrypted.0, sender.did);
        assert_eq!(decrypted.1, "legacy-invite");
    }

    #[test]
    fn compact_direct_handshake_offer_stays_under_mailbox_limit_for_large_invite() {
        let sender = AgentKeyPair::generate("Alice", "agent");
        let recipient = AgentKeyPair::generate("Bob", "agent");
        let sender_profile = build_local_member_profile(&sender, "Alice");
        let recipient_profile = build_local_member_profile(&recipient, "Bob");
        let (mut session, _) = create_identified_group(
            &sender.signing_key,
            &sender.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_direct_offer_large",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            sender_profile.clone(),
        )
        .unwrap();
        session.known_members.insert(
            recipient_profile.member_id.clone(),
            recipient_profile.clone(),
        );

        let invite_code = "direct-invite-code-".repeat(512);
        let message = build_direct_handshake_offer_message(
            &session,
            &sender.signing_key,
            &sender_profile,
            &recipient_profile,
            &invite_code,
            5_000,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&message).unwrap();

        assert!(
            encoded.len() <= session.mailbox_descriptor.max_payload_bytes,
            "encoded direct handshake offer should fit in mailbox payload limit"
        );
    }

    #[test]
    fn owner_kick_rotation_only_reaches_remaining_members() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let charlie = AgentKeyPair::generate("Charlie", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let charlie_profile = build_local_member_profile(&charlie, "Charlie");
        let (mut owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_kick_rotation",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile.clone());
        owner_session
            .known_members
            .insert(charlie.did.clone(), charlie_profile.clone());

        let (rotated_session, kicked_profile, rotation_messages) =
            plan_owner_kick_rotation(&owner_session, &owner.signing_key, &bob.did).unwrap();

        assert_eq!(kicked_profile.member_id, bob.did);
        assert_eq!(rotated_session.mailbox_epoch, 1);
        assert!(!rotated_session.known_members.contains_key(&bob.did));
        assert!(rotated_session.known_members.contains_key(&charlie.did));
        assert_eq!(rotation_messages.len(), 1);
        assert_eq!(rotation_messages[0].0, charlie.did);

        let payload_bytes =
            decode_group_mailbox_message_payload(&owner_session, &rotation_messages[0].1).unwrap();
        let payload: MailboxRotationPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let (_, kicked_member_id, secret) = decrypt_mailbox_rotation_payload(
            &payload,
            &charlie,
            rotation_messages[0].1.sender_member_id.as_deref(),
            &charlie.did,
            &owner_session.group_id,
        )
        .unwrap();
        assert_eq!(kicked_member_id, bob.did);
        assert_eq!(secret.new_mailbox_epoch, rotated_session.mailbox_epoch);
        assert!(decrypt_mailbox_rotation_payload(
            &payload,
            &bob,
            rotation_messages[0].1.sender_member_id.as_deref(),
            &bob.did,
            &owner_session.group_id,
        )
        .is_err());

        let mut recipient_session = owner_session.clone();
        recipient_session.local_member_id = Some(charlie.did.clone());
        let applied =
            apply_mailbox_rotation(&recipient_session, &owner.did, &bob.did, secret).unwrap();
        assert_eq!(applied.mailbox_epoch, rotated_session.mailbox_epoch);
        assert_eq!(
            applied.mailbox_descriptor,
            rotated_session.mailbox_descriptor
        );
        assert_eq!(
            applied.mailbox_capability,
            rotated_session.mailbox_capability
        );
        assert!(!applied.known_members.contains_key(&bob.did));
    }

    #[test]
    fn owner_kick_rotation_clears_old_join_bridge_handles() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let (mut owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_kick_bridge_cleanup",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile.clone());
        owner_session
            .join_bridge_handles
            .push(GroupMailboxJoinBridgeHandle {
                mailbox_epoch: 0,
                mailbox_descriptor: owner_session.mailbox_descriptor.clone(),
                mailbox_capability: owner_session.mailbox_capability.clone(),
                content_crypto_state: owner_session.content_crypto_state.clone(),
            });

        let (rotated_session, _, _) =
            plan_owner_kick_rotation(&owner_session, &owner.signing_key, &bob.did).unwrap();

        assert!(rotated_session.join_bridge_handles.is_empty());
    }

    #[test]
    fn group_kick_notice_roundtrip_verifies_owner() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let (mut owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_kick_notice",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile.clone());

        let message = build_group_kick_notice_message(
            &owner_session,
            &owner.signing_key,
            &owner_profile,
            &bob_profile,
            1,
            60_000,
        )
        .unwrap();
        let payload_bytes = decode_group_mailbox_message_payload(&owner_session, &message).unwrap();
        let payload: GroupKickNoticePayload = serde_json::from_slice(&payload_bytes).unwrap();
        let owner_member_id = verify_group_kick_notice_payload(
            &payload,
            message.sender_member_id.as_deref(),
            &owner_session.group_id,
            owner_session.owner_member_id.as_deref(),
        )
        .unwrap();
        assert_eq!(owner_member_id, owner.did);
        assert_eq!(payload.kicked_member_id, bob.did);
        assert_eq!(payload.mailbox_epoch, 1);
    }

    #[test]
    fn owner_lock_rotation_sets_join_locked_and_reaches_all_other_members() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let charlie = AgentKeyPair::generate("Charlie", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let charlie_profile = build_local_member_profile(&charlie, "Charlie");
        let (mut owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_lock_rotation",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile.clone());
        owner_session
            .known_members
            .insert(charlie.did.clone(), charlie_profile.clone());

        let (rotated_session, rotation_messages) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();

        assert!(rotated_session.join_locked);
        assert_eq!(rotated_session.mailbox_epoch, 1);
        assert_eq!(rotation_messages.len(), 2);

        let bob_message = rotation_messages
            .iter()
            .find(|(member_id, _)| member_id == &bob.did)
            .unwrap();
        let payload_bytes =
            decode_group_mailbox_message_payload(&owner_session, &bob_message.1).unwrap();
        let payload: MailboxRotationPayload = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload.join_locked);
        let (_, kicked_member_id, secret) = decrypt_mailbox_rotation_payload(
            &payload,
            &bob,
            bob_message.1.sender_member_id.as_deref(),
            &bob.did,
            &owner_session.group_id,
        )
        .unwrap();
        assert!(kicked_member_id.is_empty());
        assert!(secret.join_locked);

        let mut recipient_session = owner_session.clone();
        recipient_session.local_member_id = Some(bob.did.clone());
        let applied =
            apply_mailbox_rotation(&recipient_session, &owner.did, &kicked_member_id, secret)
                .unwrap();
        assert!(applied.join_locked);
        assert_eq!(applied.mailbox_epoch, rotated_session.mailbox_epoch);
    }

    #[test]
    fn owner_unlock_rotation_clears_join_locked() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_unlock_rotation",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let (locked_session, _) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();
        let (unlocked_session, _) =
            plan_owner_access_rotation(&locked_session, &owner.signing_key, false).unwrap();
        assert!(locked_session.join_locked);
        assert!(!unlocked_session.join_locked);
        assert_eq!(unlocked_session.mailbox_epoch, 2);
    }

    #[test]
    fn member_rotation_secret_does_not_replicate_join_bridge_history() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let (mut owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_rotation_compact",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        owner_session
            .known_members
            .insert(bob.did.clone(), bob_profile.clone());
        owner_session
            .join_bridge_handles
            .push(GroupMailboxJoinBridgeHandle {
                mailbox_epoch: 0,
                mailbox_descriptor: owner_session.mailbox_descriptor.clone(),
                mailbox_capability: owner_session.mailbox_capability.clone(),
                content_crypto_state: owner_session.content_crypto_state.clone(),
            });

        let (rotated_session, rotation_messages) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();
        let bob_message = rotation_messages
            .iter()
            .find(|(member_id, _)| member_id == &bob.did)
            .unwrap();
        let payload_bytes =
            decode_group_mailbox_message_payload(&owner_session, &bob_message.1).unwrap();
        let payload: MailboxRotationPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let (_, kicked_member_id, secret) = decrypt_mailbox_rotation_payload(
            &payload,
            &bob,
            bob_message.1.sender_member_id.as_deref(),
            &bob.did,
            &owner_session.group_id,
        )
        .unwrap();
        assert!(kicked_member_id.is_empty());
        assert!(rotated_session.join_locked);
        assert!(secret.join_bridge_handles.is_empty());
    }

    #[test]
    fn regenerate_identified_group_invite_rejects_locked_group() {
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (owner_session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_locked_invite",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let (locked_session, _) =
            plan_owner_access_rotation(&owner_session, &owner.signing_key, true).unwrap();
        assert!(regenerate_identified_group_invite(
            &locked_session,
            &owner.signing_key,
            &owner.did
        )
        .is_err());
    }

    #[test]
    fn resolve_identified_handshake_target_rejects_ambiguous_member() {
        let alice = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let (session_a, _) = create_identified_group(
            &alice.signing_key,
            &alice.did,
            Some("Ops A"),
            build_mailbox_descriptor(
                "grp_ops_a",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            build_local_member_profile(&alice, "Alice"),
        )
        .unwrap();
        let (session_b, _) = create_identified_group(
            &alice.signing_key,
            &alice.did,
            Some("Ops B"),
            build_mailbox_descriptor(
                "grp_ops_b",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            build_local_member_profile(&alice, "Alice"),
        )
        .unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session_a).unwrap();
        registry.insert_session(session_b).unwrap();
        registry
            .observe_member_profile("grp_ops_a", bob_profile.clone())
            .unwrap();
        registry
            .observe_member_profile("grp_ops_b", bob_profile)
            .unwrap();

        assert!(registry
            .resolve_identified_handshake_target(&bob.did)
            .is_err());
    }

    #[test]
    fn encrypted_disk_registry_persist_roundtrip_restores_sessions() {
        let dir = tempdir().unwrap();
        let owner = AgentKeyPair::generate("Alice", "agent");
        let bob = AgentKeyPair::generate("Bob", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let bob_profile = build_local_member_profile(&bob, "Bob");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Persisted Ops"),
            build_mailbox_descriptor(
                "grp_persisted_ops",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile.clone(),
        )
        .unwrap();
        let persist_path = dir.path().join("group_mailboxes.bin");
        let persist_key = derive_group_mailbox_persist_key(&owner);

        let mut registry = GroupMailboxRegistry::default();
        registry.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        registry.insert_session(session).unwrap();
        registry
            .observe_member_profile("grp_persisted_ops", bob_profile.clone())
            .unwrap();
        registry
            .update_poll_cursor("grp_persisted_ops", Some("cursor-42".to_string()))
            .unwrap();
        registry.persist_now().unwrap();

        let mut restored = GroupMailboxRegistry::default();
        restored.configure_persistence(Some(persist_path), Some(persist_key));
        restored.load_persisted().unwrap();

        let summary = restored
            .summaries()
            .into_iter()
            .find(|summary| summary.group_id == "grp_persisted_ops")
            .unwrap();
        assert_eq!(summary.group_name.as_deref(), Some("Persisted Ops"));
        assert_eq!(summary.local_member_id.as_deref(), Some(owner.did.as_str()));
        let mut expected_member_ids = vec![bob.did.clone(), owner.did.clone()];
        expected_member_ids.sort();
        assert_eq!(summary.known_member_ids, expected_member_ids);
        let mut expected_known_members = vec![
            GroupMailboxMemberSummary {
                member_id: bob.did.clone(),
                display_name: bob_profile.display_name.clone(),
            },
            GroupMailboxMemberSummary {
                member_id: owner.did.clone(),
                display_name: owner_profile.display_name.clone(),
            },
        ];
        expected_known_members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        assert_eq!(summary.known_members, expected_known_members);

        let restored_session = restored.get("grp_persisted_ops").unwrap();
        assert_eq!(restored_session.poll_cursor.as_deref(), Some("cursor-42"));
        assert_eq!(
            restored
                .known_member_profile("grp_persisted_ops", &bob.did)
                .unwrap(),
            bob_profile
        );
    }

    #[test]
    fn memory_only_mailbox_sessions_do_not_write_persistence_blob() {
        let dir = tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Ghost", "agent");
        let persist_path = dir.path().join("group_mailboxes.bin");
        let persist_key = derive_group_mailbox_persist_key(&keypair);
        let (session, _) = create_ghost_anonymous_group(
            Some("Ghost Persist"),
            build_mailbox_descriptor(
                "grp_ghost_persist",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        registry.insert_session(session).unwrap();

        assert!(
            !persist_path.exists(),
            "memory-only mailbox sessions must not leave a persistence blob"
        );
    }

    #[test]
    fn persisted_mailbox_blob_hides_plaintext_group_metadata() {
        let dir = tempdir().unwrap();
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Sensitive Team"),
            build_mailbox_descriptor(
                "grp_sensitive_marker",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let persist_path = dir.path().join("group_mailboxes.bin");
        let persist_key = derive_group_mailbox_persist_key(&owner);
        let capability_marker = session.mailbox_capability.capability_id.clone();

        let mut registry = GroupMailboxRegistry::default();
        registry.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        registry.insert_session(session).unwrap();

        let blob = std::fs::read(&persist_path).unwrap();
        for marker in [
            "grp_sensitive_marker",
            "Sensitive Team",
            capability_marker.as_str(),
            owner.did.as_str(),
        ] {
            assert!(
                !blob_contains(&blob, marker),
                "plaintext marker leaked into mailbox persistence blob: {}",
                marker
            );
        }
    }

    #[test]
    fn corrupted_persisted_mailbox_blob_is_quarantined_and_chunk_staging_wiped() {
        let dir = tempdir().unwrap();
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_corrupt_ops",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let persist_path = dir.path().join("group_mailboxes.bin");
        let persist_key = derive_group_mailbox_persist_key(&owner);

        let mut registry = GroupMailboxRegistry::default();
        registry.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        registry.insert_session(session).unwrap();

        let staging_root =
            group_chunk_staging_root(dir.path(), &GroupMailboxPersistence::EncryptedDisk);
        let orphan = staging_root.join("dangling");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("chunk.bin"), b"orphaned").unwrap();

        let mut blob = std::fs::read(&persist_path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x44;
        std::fs::write(&persist_path, blob).unwrap();

        let mut restored = GroupMailboxRegistry::default();
        restored.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        let error = restored.load_persisted().unwrap_err();

        assert!(error.to_string().contains("securely deleted"));
        assert!(!persist_path.exists());
        assert!(!staging_root.exists());
        assert!(restored.summaries().is_empty());
    }

    #[test]
    fn unsupported_mailbox_persistence_version_is_not_quarantined() {
        let dir = tempdir().unwrap();
        let owner = AgentKeyPair::generate("Alice", "agent");
        let owner_profile = build_local_member_profile(&owner, "Alice");
        let (session, _) = create_identified_group(
            &owner.signing_key,
            &owner.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_version_ops",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            owner_profile,
        )
        .unwrap();
        let persist_path = dir.path().join("group_mailboxes.bin");
        let persist_key = derive_group_mailbox_persist_key(&owner);

        let mut registry = GroupMailboxRegistry::default();
        registry.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        registry.insert_session(session).unwrap();

        let mut blob: PersistedGroupMailboxBlob =
            bincode::deserialize(&std::fs::read(&persist_path).unwrap()).unwrap();
        blob.version = 99;
        std::fs::write(&persist_path, bincode::serialize(&blob).unwrap()).unwrap();

        let mut restored = GroupMailboxRegistry::default();
        restored.configure_persistence(Some(persist_path.clone()), Some(persist_key));
        let error = restored.load_persisted().unwrap_err();

        assert!(error
            .to_string()
            .contains("Unsupported mailbox group persistence version 99"));
        assert!(persist_path.exists());
    }

    #[test]
    fn kind_label_matches_protocol_variant_names() {
        assert_eq!(kind_label(&GroupMailboxMessageKind::Chat), "chat");
    }

    #[test]
    fn ghost_anonymous_cover_schedule_stays_within_slot_jitter_window() {
        let now_ms = 1_000_000;
        for _ in 0..128 {
            let scheduled = next_ghost_anonymous_cover_traffic_at(now_ms);
            let delay = scheduled - now_ms;
            assert!(
                ((GHOST_ANON_COVER_SLOT_MS - 750)..=(GHOST_ANON_COVER_SLOT_MS + 750))
                    .contains(&delay)
            );
        }
    }

    #[test]
    fn auto_mailbox_port_is_persisted_once_allocated() {
        let dir = tempdir().unwrap();
        let root = auto_mailbox_service_root(dir.path(), "grp_auto_mailbox");
        let first = load_or_create_auto_mailbox_service_port(&root).unwrap();
        let second = load_or_create_auto_mailbox_service_port(&root).unwrap();

        assert_eq!(first, second);
        assert!(auto_mailbox_service_port_path(&root).exists());
    }

    #[test]
    fn local_embedded_mailbox_restore_candidates_follow_service_state_not_owner_metadata() {
        let dir = tempdir().unwrap();
        let restore_root = auto_mailbox_service_root(dir.path(), "grp_restore_me");
        std::fs::create_dir_all(&restore_root).unwrap();
        std::fs::write(auto_mailbox_service_port_path(&restore_root), "57583\n").unwrap();
        std::fs::create_dir_all(restore_root.join("tor")).unwrap();
        std::fs::write(
            restore_root.join("tor").join("hostname"),
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion\n",
        )
        .unwrap();

        let sessions = vec![
            GroupMailboxSession {
                group_id: "grp_restore_me".to_string(),
                group_name: Some("Restore".to_string()),
                anonymous_group: false,
                join_locked: false,
                mailbox_descriptor: build_mailbox_descriptor(
                    "grp_restore_me",
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx:57583",
                    5_000,
                    256 * 1024,
                )
                .unwrap(),
                mailbox_capability: build_mailbox_capability(),
                content_crypto_state: None,
                anonymous_writer_state: None,
                local_member_id: Some("did:nxf:local".to_string()),
                owner_member_id: Some("did:nxf:someone-else".to_string()),
                persistence: GroupMailboxPersistence::EncryptedDisk,
                joined_at: 0,
                invite_id: String::new(),
                owner_special_id: None,
                mailbox_epoch: 0,
                poll_cursor: None,
                next_cover_traffic_at: None,
                last_real_activity_at: None,
                known_members: HashMap::new(),
                local_posted_message_ids: HashSet::new(),
                seen_message_ids: HashMap::new(),
                join_bridge_handles: Vec::new(),
            },
            GroupMailboxSession {
                group_id: "anon_legacy_drift".to_string(),
                group_name: Some("Legacy Drift".to_string()),
                anonymous_group: false,
                join_locked: false,
                mailbox_descriptor: MailboxDescriptor {
                    transport: MailboxTransportKind::Tor,
                    namespace: "mailbox:anon_legacy_drift".to_string(),
                    endpoint: Some(
                        "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx:57583"
                            .to_string(),
                    ),
                    poll_interval_ms: 5_000,
                    max_payload_bytes: 256 * 1024,
                },
                mailbox_capability: build_mailbox_capability(),
                content_crypto_state: None,
                anonymous_writer_state: None,
                local_member_id: Some("did:nxf:local".to_string()),
                owner_member_id: Some("did:nxf:local".to_string()),
                persistence: GroupMailboxPersistence::EncryptedDisk,
                joined_at: 0,
                invite_id: String::new(),
                owner_special_id: None,
                mailbox_epoch: 0,
                poll_cursor: None,
                next_cover_traffic_at: None,
                last_real_activity_at: None,
                known_members: HashMap::new(),
                local_posted_message_ids: HashSet::new(),
                seen_message_ids: HashMap::new(),
                join_bridge_handles: Vec::new(),
            },
            GroupMailboxSession {
                group_id: "grp_do_not_restore".to_string(),
                group_name: Some("No Relay".to_string()),
                anonymous_group: false,
                join_locked: false,
                mailbox_descriptor: build_mailbox_descriptor(
                    "grp_do_not_restore",
                    "tor://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:9444",
                    5_000,
                    256 * 1024,
                )
                .unwrap(),
                mailbox_capability: build_mailbox_capability(),
                content_crypto_state: None,
                anonymous_writer_state: None,
                local_member_id: Some("did:nxf:local".to_string()),
                owner_member_id: Some("did:nxf:local".to_string()),
                persistence: GroupMailboxPersistence::EncryptedDisk,
                joined_at: 0,
                invite_id: String::new(),
                owner_special_id: None,
                mailbox_epoch: 0,
                poll_cursor: None,
                next_cover_traffic_at: None,
                last_real_activity_at: None,
                known_members: HashMap::new(),
                local_posted_message_ids: HashSet::new(),
                seen_message_ids: HashMap::new(),
                join_bridge_handles: Vec::new(),
            },
        ];

        assert_eq!(
            local_embedded_mailbox_group_ids_to_restore(dir.path(), &sessions),
            vec!["grp_restore_me".to_string()]
        );
    }

    #[test]
    fn mailbox_transport_failures_back_off_and_reset_after_success() {
        let mut registry = GroupMailboxRegistry::default();
        let now_ms = 1_000_000;

        let first = registry.note_mailbox_transport_failure("grp_ops", 5_000, now_ms);
        assert_eq!(first.failures, 1);
        assert_eq!(first.next_retry_after_ms, 5_000);
        assert!(!first.should_log);
        assert!(!first.degraded);
        assert!(!registry.mailbox_transport_due("grp_ops", now_ms + 4_999));
        assert!(registry.mailbox_transport_due("grp_ops", now_ms + 5_000));

        let second = registry.note_mailbox_transport_failure("grp_ops", 5_000, now_ms + 5_000);
        assert_eq!(second.failures, 2);
        assert_eq!(second.next_retry_after_ms, 10_000);
        assert!(!second.should_log);
        assert!(!second.degraded);

        let third = registry.note_mailbox_transport_failure("grp_ops", 5_000, now_ms + 15_000);
        assert_eq!(third.failures, 3);
        assert_eq!(third.next_retry_after_ms, 20_000);
        assert!(third.should_log);
        assert!(third.degraded);

        registry.note_mailbox_transport_success("grp_ops");
        assert!(registry.mailbox_transport_due("grp_ops", now_ms + 15_001));
    }

    #[test]
    fn manual_mailbox_refresh_slots_are_throttled_per_group() {
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_manual_refresh",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();
        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session).unwrap();

        assert!(registry.take_manual_mailbox_refresh_slot("grp_manual_refresh", 1_000));
        assert!(!registry.take_manual_mailbox_refresh_slot("grp_manual_refresh", 1_999));
        assert!(registry.take_manual_mailbox_refresh_slot("grp_manual_refresh", 2_000));
    }

    #[tokio::test]
    async fn resolve_mailbox_endpoint_prefers_explicit_endpoint_over_pool() {
        let dir = tempdir().unwrap();
        let mut config = sample_app_config();
        config.network.mailbox.endpoint = Some(
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444".to_string(),
        );
        config.network.mailbox.pool_endpoints = vec![
            "tor://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:9444".to_string(),
        ];

        let resolved = resolve_mailbox_endpoint(&config, dir.path(), "grp_explicit")
            .await
            .unwrap();

        assert_eq!(
            resolved.endpoint,
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
        );
        assert!(!resolved.auto_provisioned);
        assert!(!resolved.selected_from_pool);
        assert!(!embedded_mailbox_service_exists(dir.path(), "grp_explicit"));
    }

    #[tokio::test]
    async fn resolve_mailbox_endpoint_uses_pool_before_embedded_fallback() {
        let dir = tempdir().unwrap();
        let mut config = sample_app_config();
        config.network.mailbox.pool_endpoints = vec![
            "tor://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:9444".to_string(),
            "tor://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:9444".to_string(),
        ];

        let resolved = resolve_mailbox_endpoint(&config, dir.path(), "grp_pool")
            .await
            .unwrap();

        assert!(config
            .network
            .mailbox
            .pool_endpoints
            .iter()
            .any(|endpoint| endpoint == &resolved.endpoint));
        assert!(!resolved.auto_provisioned);
        assert!(resolved.selected_from_pool);
        assert!(!embedded_mailbox_service_exists(dir.path(), "grp_pool"));
    }

    #[test]
    fn mailbox_requires_external_provider_is_disabled_for_all_modes() {
        let mut config = sample_app_config();
        assert!(!mailbox_requires_external_provider(&config));

        config.logging.mode = "safe".to_string();
        assert!(!mailbox_requires_external_provider(&config));

        config.logging.mode = "ghost".to_string();
        assert!(!mailbox_requires_external_provider(&config));
    }

    #[tokio::test]
    async fn pending_chunk_offer_requires_explicit_accept_before_download_queue() {
        let dir = tempdir().unwrap();
        let (session, _) = create_ghost_anonymous_group(
            Some("Ghost Files"),
            build_mailbox_descriptor(
                "grp_pending_chunk",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let plaintext_sha256 = hex::encode(Sha256::digest(b"chunk-offer"));
        let mut chunk_capability = GroupChunkCapabilityPayload {
            transfer_id: "transfer_pending_chunk".to_string(),
            artifact_id: "artifact_pending_chunk".to_string(),
            filename: "evidence.bin".to_string(),
            chunk_size: 4096,
            total_chunks: 2,
            total_size: 8_192,
            plaintext_sha256: plaintext_sha256.clone(),
            merkle_root: [7u8; 32],
            sender_verifying_key_hex: "11".repeat(32),
            mailbox_descriptor: build_group_chunk_descriptor(
                &session.group_id,
                session.mailbox_descriptor.endpoint.as_deref().unwrap(),
                session.mailbox_descriptor.poll_interval_ms,
                session.mailbox_descriptor.max_payload_bytes,
                "transfer_pending_chunk",
                session.anonymous_group,
            )
            .unwrap(),
            mailbox_capability: build_mailbox_capability(),
        };
        issue_group_mailbox_bootstrap_token(
            &ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            MailboxBootstrapScopeKind::ChunkTransfer,
            &chunk_capability.transfer_id,
            &chunk_capability.mailbox_descriptor,
            &mut chunk_capability.mailbox_capability,
            chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
        )
        .unwrap();
        let manifest = GroupFileManifestPayload {
            manifest_id: "manifest_pending_chunk".to_string(),
            filename: "evidence.bin".to_string(),
            size_bytes: 8_192,
            plaintext_sha256,
            chunk_capability: Some(encode_group_chunk_capability(&chunk_capability).unwrap()),
            inline_ciphertext: None,
            fast_transfer_id: None,
            fast_transfer_expires_at: None,
            fast_relay_only: true,
        };
        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        {
            let mut locked = registry.lock().await;
            locked.insert_session(session.clone()).unwrap();
            assert!(
                queue_pending_group_file_offer(&mut locked, &session, &manifest, None).unwrap()
            );
            assert_eq!(locked.pending_file_offers().len(), 1);
            assert!(!locked.chunk_download_exists(&chunk_capability.transfer_id));
        }

        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig {
            global_dir: Some(dir.path().join("receive")),
            per_peer_dirs: HashMap::new(),
        }));
        let outcome = approve_pending_group_file_offer(
            &registry,
            "manifest_pending_chunk",
            &receive_dir,
            &LogMode::Safe,
            dir.path(),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(matches!(
            outcome.action,
            GroupPendingFileOfferAction::ChunkDownloadQueued { .. }
        ));
        let locked = registry.lock().await;
        assert!(locked.pending_file_offers().is_empty());
        assert!(locked.chunk_download_exists(&chunk_capability.transfer_id));
    }

    #[tokio::test]
    async fn approving_inline_group_offer_materializes_file_only_after_accept() {
        let dir = tempdir().unwrap();
        let receive_root = dir.path().join("receive");
        let (session, _) = create_ghost_anonymous_group(
            Some("Ghost Files"),
            build_mailbox_descriptor(
                "grp_pending_inline",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let plaintext = b"top secret evidence";
        let manifest = GroupFileManifestPayload {
            manifest_id: "manifest_pending_inline".to_string(),
            filename: "evidence.txt".to_string(),
            size_bytes: plaintext.len() as u64,
            plaintext_sha256: hex::encode(Sha256::digest(plaintext)),
            chunk_capability: None,
            inline_ciphertext: Some(seal_bytes(&session, "inline-file", plaintext).unwrap()),
            fast_transfer_id: None,
            fast_transfer_expires_at: None,
            fast_relay_only: true,
        };
        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        {
            let mut locked = registry.lock().await;
            locked.insert_session(session.clone()).unwrap();
            assert!(
                queue_pending_group_file_offer(&mut locked, &session, &manifest, None).unwrap()
            );
        }

        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig {
            global_dir: Some(receive_root.clone()),
            per_peer_dirs: HashMap::new(),
        }));
        assert!(!receive_root.exists());

        let outcome = approve_pending_group_file_offer(
            &registry,
            "grp_pending_inline",
            &receive_dir,
            &LogMode::Safe,
            dir.path(),
        )
        .await
        .unwrap()
        .unwrap();

        let saved_path = match outcome.action {
            GroupPendingFileOfferAction::InlineSaved { path, .. } => path,
            _ => panic!("expected inline materialization"),
        };
        assert_eq!(std::fs::read(&saved_path).unwrap(), plaintext);
        let locked = registry.lock().await;
        assert!(locked.pending_file_offers().is_empty());
    }

    #[tokio::test]
    async fn approving_fast_only_group_offer_requests_fast_relay_without_chunk_download() {
        let dir = tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Alice", "agent");
        let local_profile = build_local_member_profile(&keypair, "Alice");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_pending_fast",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();
        let manifest = GroupFileManifestPayload {
            manifest_id: "manifest_pending_fast".to_string(),
            filename: "archive.zip".to_string(),
            size_bytes: 42 * 1024 * 1024,
            plaintext_sha256: "deadbeef".repeat(8),
            chunk_capability: None,
            inline_ciphertext: None,
            fast_transfer_id: Some("gft_pending_fast".to_string()),
            fast_transfer_expires_at: Some(current_unix_ts() + 300),
            fast_relay_only: true,
        };
        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        {
            let mut locked = registry.lock().await;
            locked.insert_session(session.clone()).unwrap();
            assert!(
                queue_pending_group_file_offer(&mut locked, &session, &manifest, None).unwrap()
            );
            assert_eq!(locked.pending_file_offers().len(), 1);
        }

        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig {
            global_dir: Some(dir.path().join("receive")),
            per_peer_dirs: HashMap::new(),
        }));
        let outcome = approve_pending_group_file_offer(
            &registry,
            "grp_pending_fast",
            &receive_dir,
            &LogMode::Safe,
            dir.path(),
        )
        .await
        .unwrap()
        .unwrap();

        match outcome.action {
            GroupPendingFileOfferAction::FastRelayRequested { transfer_id } => {
                assert_eq!(transfer_id, "gft_pending_fast");
            }
            _ => panic!("expected fast relay request"),
        }
        assert_eq!(
            outcome.fast_transfer_id.as_deref(),
            Some("gft_pending_fast")
        );

        let locked = registry.lock().await;
        assert!(locked.pending_file_offers().is_empty());
    }

    #[tokio::test]
    async fn rejecting_pending_group_offer_discards_without_starting_download() {
        let dir = tempdir().unwrap();
        let (session, _) = create_ghost_anonymous_group(
            Some("Ghost Files"),
            build_mailbox_descriptor(
                "grp_pending_reject",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let manifest = GroupFileManifestPayload {
            manifest_id: "manifest_pending_reject".to_string(),
            filename: "discard.txt".to_string(),
            size_bytes: b"discard me".len() as u64,
            plaintext_sha256: hex::encode(Sha256::digest(b"discard me")),
            chunk_capability: None,
            inline_ciphertext: Some(seal_bytes(&session, "inline-file", b"discard me").unwrap()),
            fast_transfer_id: None,
            fast_transfer_expires_at: None,
            fast_relay_only: true,
        };
        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        {
            let mut locked = registry.lock().await;
            locked.insert_session(session.clone()).unwrap();
            assert!(
                queue_pending_group_file_offer(&mut locked, &session, &manifest, None).unwrap()
            );
        }

        let rejected = reject_pending_group_file_offer(&registry, "manifest_pending_reject")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(rejected.group_id, "grp_pending_reject");
        let locked = registry.lock().await;
        assert!(locked.pending_file_offers().is_empty());
        assert!(locked.chunk_downloads().is_empty());
        assert!(!dir.path().join("receive").exists());
    }

    #[test]
    fn ghost_mode_rejects_identified_mailbox_group() {
        let keypair = AgentKeyPair::generate("MailboxOwner", "agent");
        let invite = GroupMailboxInvite::generate(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_identified",
            Some("Identified"),
            false,
            build_mailbox_descriptor(
                "grp_identified",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            MailboxCapability {
                capability_id: "cap_identified".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();
        assert!(mailbox_join_allowed_for_mode("ghost", &invite).is_err());
    }

    #[test]
    fn safe_log_redaction_hashes_group_and_member_identifiers() {
        let group_a = log_group_id(&LogMode::Safe, "grp_alpha");
        let group_b = log_group_id(&LogMode::Safe, "grp_beta");
        let member = log_member_id(&LogMode::Safe, "did:nxf:alice");

        assert_ne!(group_a, "grp_alpha");
        assert_ne!(member, "did:nxf:alice");
        assert_ne!(group_a, group_b);
        assert!(group_a.starts_with("group#"));
        assert!(member.starts_with("member#"));
    }

    #[test]
    fn ghost_log_redaction_keeps_plain_identifiers() {
        assert_eq!(log_group_id(&LogMode::Ghost, "grp_alpha"), "grp_alpha");
        assert_eq!(
            log_member_id(&LogMode::Ghost, "did:nxf:alice"),
            "did:nxf:alice"
        );
    }

    #[test]
    fn removing_group_clears_staged_fast_file_state() {
        let keypair = AgentKeyPair::generate("FastOwner", "agent");
        let local_profile = GroupMailboxMemberProfile {
            member_id: keypair.did.clone(),
            display_name: "FastOwner".to_string(),
            verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(keypair.encryption_public),
            kyber_public_key_hex: Some(hex::encode(keypair.kyber_public.clone())),
        };
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Group"),
            build_mailbox_descriptor(
                "grp_fast_stage",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile,
        )
        .unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session.clone()).unwrap();
        assert!(
            registry.store_pending_fast_file_offer(GroupPendingFastFileOffer {
                transfer_id: "gft_offer_1".to_string(),
                manifest_id: "gmanifest_fast_1".to_string(),
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: false,
                sender_member_id: session.local_member_id.clone(),
                offer: GroupFastFileOfferPayload {
                    transfer_id: "gft_offer_1".to_string(),
                    manifest_id: "gmanifest_fast_1".to_string(),
                    filename: "archive.zip".to_string(),
                    size_bytes: 1024,
                    plaintext_sha256: "aa".to_string(),
                    merkle_root: [5u8; 32],
                    sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
                    relay_only: true,
                    created_at: 1,
                    expires_at: current_unix_ts().saturating_add(3600),
                },
            })
        );
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: "gft_offer_1".to_string(),
            grant_id: Some("grant_1".to_string()),
            group_id: session.group_id.clone(),
            recipient_member_id: "did:nxf:recipient".to_string(),
            relay_only: true,
            expires_at: current_unix_ts().saturating_add(3600),
            envelope: GroupFastFileGrantEnvelope::Accept(GroupFastFileAcceptPayload {
                transfer_id: "gft_offer_1".to_string(),
                group_id: session.group_id.clone(),
                recipient_member_id: "did:nxf:recipient".to_string(),
                recipient_verifying_key_hex: "bb".repeat(32),
                created_at: 1,
                signature: Vec::new(),
            }),
            secret: None,
        });
        let packed_dir = tempdir().unwrap();
        let packed_path = packed_dir.path().join("archive.zip");
        std::fs::write(&packed_path, b"fast-path-test-data").unwrap();
        let fast_session = chunked_transfer::prepare_session_streaming(
            &keypair,
            "group:recipient",
            "archive.zip",
            "group_fast_relay",
            &packed_path,
            4096,
        )
        .unwrap();
        registry.stage_fast_file_transfer(GroupStagedFastFileTransfer {
            transfer_id: "gft_offer_1".to_string(),
            mailbox_transfer_id: "mailbox_transfer_1".to_string(),
            manifest_id: "gmanifest_fast_1".to_string(),
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            sender_member_id: session.local_member_id.clone().unwrap(),
            filename: "archive.zip".to_string(),
            size_bytes: 1024,
            file_manifest_hash: "cc".repeat(32),
            plaintext_sha256: "aa".to_string(),
            merkle_root: [5u8; 32],
            total_chunks: 8,
            chunk_size: 4096,
            relay_only: true,
            endpoint_addr_json: "{\"relay_url\":\"https://relay.example.test\"}".to_string(),
            endpoint_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            expires_at: current_unix_ts().saturating_add(3600),
            packed_path,
            fast_session,
        });

        assert_eq!(registry.pending_fast_file_offers().len(), 1);
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_1", "did:nxf:recipient")
            .is_some());
        assert!(registry
            .staged_fast_file_transfer_cloned("gft_offer_1")
            .is_some());

        registry.remove_group(&session.group_id).unwrap();

        assert!(registry.pending_fast_file_offers().is_empty());
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_1", "did:nxf:recipient")
            .is_none());
        assert!(registry
            .clear_staged_fast_file_transfer("gft_offer_1")
            .is_none());
    }

    #[test]
    fn fast_file_grant_is_short_lived_and_single_use() {
        let keypair = AgentKeyPair::generate("FastOwner", "agent");
        let recipient = AgentKeyPair::generate("FastRecipient", "agent");
        let local_profile = GroupMailboxMemberProfile {
            member_id: keypair.did.clone(),
            display_name: "FastOwner".to_string(),
            verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(keypair.encryption_public),
            kyber_public_key_hex: Some(hex::encode(keypair.kyber_public.clone())),
        };
        let recipient_profile = GroupMailboxMemberProfile {
            member_id: recipient.did.clone(),
            display_name: "FastRecipient".to_string(),
            verifying_key_hex: hex::encode(recipient.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(recipient.encryption_public),
            kyber_public_key_hex: Some(hex::encode(recipient.kyber_public.clone())),
        };
        let (mut session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Group"),
            build_mailbox_descriptor(
                "grp_fast_grant",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();
        session.known_members.insert(
            recipient_profile.member_id.clone(),
            recipient_profile.clone(),
        );

        let packed_dir = tempdir().unwrap();
        let packed_path = packed_dir.path().join("archive.zip");
        std::fs::write(&packed_path, b"fast-path-test-data").unwrap();
        let staged = GroupStagedFastFileTransfer {
            transfer_id: "gft_offer_single_use".to_string(),
            mailbox_transfer_id: "mailbox_transfer_single_use".to_string(),
            manifest_id: "gmanifest_fast_single_use".to_string(),
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            sender_member_id: local_profile.member_id.clone(),
            filename: "archive.zip".to_string(),
            size_bytes: 1024,
            file_manifest_hash: "cc".repeat(32),
            plaintext_sha256: "aa".to_string(),
            merkle_root: [5u8; 32],
            total_chunks: 8,
            chunk_size: 4096,
            relay_only: true,
            endpoint_addr_json: "{\"relay_url\":\"https://relay.example.test\"}".to_string(),
            endpoint_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            expires_at: current_unix_ts().saturating_add(3600),
            packed_path: packed_path.clone(),
            fast_session: chunked_transfer::prepare_session_streaming(
                &keypair,
                "group:recipient",
                "archive.zip",
                "group_fast_relay",
                &packed_path,
                4096,
            )
            .unwrap(),
        };

        let sender_profile = session
            .known_members
            .get(&local_profile.member_id)
            .unwrap()
            .clone();
        let (message, payload, secret) = build_fast_file_grant_message(
            &session,
            &keypair.signing_key,
            &sender_profile,
            &recipient_profile,
            &staged,
            30_000,
        )
        .unwrap();

        assert!(payload.expires_at < staged.expires_at);
        assert_eq!(payload.expires_at, secret.expires_at);
        assert!(
            payload.expires_at
                <= current_unix_ts().saturating_add(GROUP_FAST_FILE_GRANT_TTL_SECS + 1)
        );
        let encoded_message = serde_json::to_vec(&message).unwrap();
        assert!(encoded_message.len() <= session.mailbox_descriptor.max_payload_bytes);

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session).unwrap();
        registry.stage_fast_file_transfer(staged);
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: secret.transfer_id.clone(),
            grant_id: Some(payload.grant_id.clone()),
            group_id: secret.group_id.clone(),
            recipient_member_id: secret.recipient_did.clone(),
            relay_only: secret.relay_only,
            expires_at: secret.expires_at,
            envelope: GroupFastFileGrantEnvelope::Grant(payload),
            secret: Some(secret.clone()),
        });

        let first = registry.consume_fast_transfer_open_authorization(
            &secret.transfer_id,
            &secret.recipient_did,
            current_unix_ts(),
        );
        assert!(first.is_some());
        let second = registry.consume_fast_transfer_open_authorization(
            &secret.transfer_id,
            &secret.recipient_did,
            current_unix_ts(),
        );
        assert!(second.is_none());
    }

    #[test]
    fn fast_file_recipient_cleanup_keeps_staged_transfer_for_other_members() {
        let keypair = AgentKeyPair::generate("FastOwner", "agent");
        let recipient_a = AgentKeyPair::generate("FastRecipientA", "agent");
        let recipient_b = AgentKeyPair::generate("FastRecipientB", "agent");
        let local_profile = GroupMailboxMemberProfile {
            member_id: keypair.did.clone(),
            display_name: "FastOwner".to_string(),
            verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(keypair.encryption_public),
            kyber_public_key_hex: Some(hex::encode(keypair.kyber_public.clone())),
        };
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Group"),
            build_mailbox_descriptor(
                "grp_fast_recipient_cleanup",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        let packed_dir = tempdir().unwrap();
        let packed_path = packed_dir.path().join("archive.zip");
        std::fs::write(&packed_path, b"fast-path-test-data").unwrap();
        let staged = GroupStagedFastFileTransfer {
            transfer_id: "gft_offer_multi_recipient".to_string(),
            mailbox_transfer_id: "mailbox_transfer_multi_recipient".to_string(),
            manifest_id: "gmanifest_fast_multi_recipient".to_string(),
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            sender_member_id: local_profile.member_id.clone(),
            filename: "archive.zip".to_string(),
            size_bytes: 1024,
            file_manifest_hash: "cc".repeat(32),
            plaintext_sha256: "aa".to_string(),
            merkle_root: [5u8; 32],
            total_chunks: 8,
            chunk_size: 4096,
            relay_only: true,
            endpoint_addr_json: "{\"relay_url\":\"https://relay.example.test\"}".to_string(),
            endpoint_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            expires_at: current_unix_ts().saturating_add(3600),
            packed_path: packed_path.clone(),
            fast_session: chunked_transfer::prepare_session_streaming(
                &keypair,
                "group:recipient",
                "archive.zip",
                "group_fast_relay",
                &packed_path,
                4096,
            )
            .unwrap(),
        };

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session).unwrap();
        registry.stage_fast_file_transfer(staged);
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: "gft_offer_multi_recipient".to_string(),
            grant_id: Some("grant_a".to_string()),
            group_id: "grp_fast_recipient_cleanup".to_string(),
            recipient_member_id: recipient_a.did.clone(),
            relay_only: true,
            expires_at: current_unix_ts().saturating_add(600),
            envelope: GroupFastFileGrantEnvelope::Accept(GroupFastFileAcceptPayload {
                transfer_id: "gft_offer_multi_recipient".to_string(),
                group_id: "grp_fast_recipient_cleanup".to_string(),
                recipient_member_id: recipient_a.did.clone(),
                recipient_verifying_key_hex: hex::encode(recipient_a.verifying_key.as_bytes()),
                created_at: current_unix_ts(),
                signature: Vec::new(),
            }),
            secret: None,
        });
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: "gft_offer_multi_recipient".to_string(),
            grant_id: Some("grant_b".to_string()),
            group_id: "grp_fast_recipient_cleanup".to_string(),
            recipient_member_id: recipient_b.did.clone(),
            relay_only: true,
            expires_at: current_unix_ts().saturating_add(600),
            envelope: GroupFastFileGrantEnvelope::Accept(GroupFastFileAcceptPayload {
                transfer_id: "gft_offer_multi_recipient".to_string(),
                group_id: "grp_fast_recipient_cleanup".to_string(),
                recipient_member_id: recipient_b.did.clone(),
                recipient_verifying_key_hex: hex::encode(recipient_b.verifying_key.as_bytes()),
                created_at: current_unix_ts(),
                signature: Vec::new(),
            }),
            secret: None,
        });

        let removed = registry
            .clear_fast_file_grant_for_recipient("gft_offer_multi_recipient", &recipient_a.did);
        assert!(removed.is_some());
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_multi_recipient", &recipient_a.did)
            .is_none());
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_multi_recipient", &recipient_b.did)
            .is_some());
        assert!(registry
            .staged_fast_file_transfer_cloned("gft_offer_multi_recipient")
            .is_some());
        assert!(packed_path.exists());
    }

    #[test]
    fn expired_fast_file_state_is_pruned_and_wiped() {
        let keypair = AgentKeyPair::generate("FastOwner", "agent");
        let local_profile = GroupMailboxMemberProfile {
            member_id: keypair.did.clone(),
            display_name: "FastOwner".to_string(),
            verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(keypair.encryption_public),
            kyber_public_key_hex: Some(hex::encode(keypair.kyber_public.clone())),
        };
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Group"),
            build_mailbox_descriptor(
                "grp_fast_prune",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        let packed_dir = tempdir().unwrap();
        let packed_path = packed_dir.path().join("archive.zip");
        std::fs::write(&packed_path, b"fast-path-test-data").unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session.clone()).unwrap();
        assert!(
            registry.store_pending_fast_file_offer(GroupPendingFastFileOffer {
                transfer_id: "gft_offer_expired".to_string(),
                manifest_id: "gmanifest_fast_expired".to_string(),
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: false,
                sender_member_id: session.local_member_id.clone(),
                offer: GroupFastFileOfferPayload {
                    transfer_id: "gft_offer_expired".to_string(),
                    manifest_id: "gmanifest_fast_expired".to_string(),
                    filename: "archive.zip".to_string(),
                    size_bytes: 1024,
                    plaintext_sha256: "aa".to_string(),
                    merkle_root: [5u8; 32],
                    sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
                    relay_only: true,
                    created_at: 1,
                    expires_at: current_unix_ts().saturating_add(600),
                },
            })
        );
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: "gft_offer_expired".to_string(),
            grant_id: Some("grant_expired".to_string()),
            group_id: session.group_id.clone(),
            recipient_member_id: "did:nxf:recipient".to_string(),
            relay_only: true,
            expires_at: current_unix_ts().saturating_add(600),
            envelope: GroupFastFileGrantEnvelope::Accept(GroupFastFileAcceptPayload {
                transfer_id: "gft_offer_expired".to_string(),
                group_id: session.group_id.clone(),
                recipient_member_id: "did:nxf:recipient".to_string(),
                recipient_verifying_key_hex: "bb".repeat(32),
                created_at: 1,
                signature: Vec::new(),
            }),
            secret: None,
        });
        registry.stage_fast_file_transfer(GroupStagedFastFileTransfer {
            transfer_id: "gft_offer_expired".to_string(),
            mailbox_transfer_id: "mailbox_transfer_expired".to_string(),
            manifest_id: "gmanifest_fast_expired".to_string(),
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            sender_member_id: local_profile.member_id.clone(),
            filename: "archive.zip".to_string(),
            size_bytes: 1024,
            file_manifest_hash: "cc".repeat(32),
            plaintext_sha256: "aa".to_string(),
            merkle_root: [5u8; 32],
            total_chunks: 8,
            chunk_size: 4096,
            relay_only: true,
            endpoint_addr_json: "{\"relay_url\":\"https://relay.example.test\"}".to_string(),
            endpoint_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            expires_at: current_unix_ts().saturating_sub(1),
            packed_path: packed_path.clone(),
            fast_session: chunked_transfer::prepare_session_streaming(
                &keypair,
                "group:recipient",
                "archive.zip",
                "group_fast_relay",
                &packed_path,
                4096,
            )
            .unwrap(),
        });

        registry.prune_expired_fast_file_state(current_unix_ts());

        assert!(!packed_path.exists());
        assert!(registry
            .staged_fast_file_transfer_cloned("gft_offer_expired")
            .is_none());
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_expired", "did:nxf:recipient")
            .is_none());
        assert!(registry.pending_fast_file_offers().is_empty());
    }

    #[test]
    fn expired_fast_file_state_waits_for_active_sender_before_wiping() {
        let keypair = AgentKeyPair::generate("FastOwner", "agent");
        let local_profile = GroupMailboxMemberProfile {
            member_id: keypair.did.clone(),
            display_name: "FastOwner".to_string(),
            verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            encryption_public_key_hex: hex::encode(keypair.encryption_public),
            kyber_public_key_hex: Some(hex::encode(keypair.kyber_public.clone())),
        };
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Fast Group"),
            build_mailbox_descriptor(
                "grp_fast_active_prune",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::EncryptedDisk,
            local_profile.clone(),
        )
        .unwrap();

        let packed_dir = tempdir().unwrap();
        let packed_path = packed_dir.path().join("archive.zip");
        std::fs::write(&packed_path, b"fast-path-test-data").unwrap();

        let mut registry = GroupMailboxRegistry::default();
        registry.insert_session(session.clone()).unwrap();
        assert!(
            registry.store_pending_fast_file_offer(GroupPendingFastFileOffer {
                transfer_id: "gft_offer_active".to_string(),
                manifest_id: "gmanifest_fast_active".to_string(),
                group_id: session.group_id.clone(),
                group_name: session.group_name.clone(),
                anonymous_group: false,
                sender_member_id: session.local_member_id.clone(),
                offer: GroupFastFileOfferPayload {
                    transfer_id: "gft_offer_active".to_string(),
                    manifest_id: "gmanifest_fast_active".to_string(),
                    filename: "archive.zip".to_string(),
                    size_bytes: 1024,
                    plaintext_sha256: "aa".to_string(),
                    merkle_root: [5u8; 32],
                    sender_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
                    relay_only: true,
                    created_at: 1,
                    expires_at: current_unix_ts().saturating_add(30),
                },
            })
        );
        registry.track_fast_file_grant(GroupFastFileGrantState {
            transfer_id: "gft_offer_active".to_string(),
            grant_id: Some("grant_active".to_string()),
            group_id: session.group_id.clone(),
            recipient_member_id: "did:nxf:recipient".to_string(),
            relay_only: true,
            expires_at: current_unix_ts().saturating_add(30),
            envelope: GroupFastFileGrantEnvelope::Accept(GroupFastFileAcceptPayload {
                transfer_id: "gft_offer_active".to_string(),
                group_id: session.group_id.clone(),
                recipient_member_id: "did:nxf:recipient".to_string(),
                recipient_verifying_key_hex: "bb".repeat(32),
                created_at: 1,
                signature: Vec::new(),
            }),
            secret: None,
        });
        registry.stage_fast_file_transfer(GroupStagedFastFileTransfer {
            transfer_id: "gft_offer_active".to_string(),
            mailbox_transfer_id: "mailbox_transfer_active".to_string(),
            manifest_id: "gmanifest_fast_active".to_string(),
            group_id: session.group_id.clone(),
            group_name: session.group_name.clone(),
            sender_member_id: local_profile.member_id.clone(),
            filename: "archive.zip".to_string(),
            size_bytes: 1024,
            file_manifest_hash: "cc".repeat(32),
            plaintext_sha256: "aa".to_string(),
            merkle_root: [5u8; 32],
            total_chunks: 8,
            chunk_size: 4096,
            relay_only: true,
            endpoint_addr_json: "{\"relay_url\":\"https://relay.example.test\"}".to_string(),
            endpoint_verifying_key_hex: hex::encode(keypair.verifying_key.as_bytes()),
            expires_at: current_unix_ts().saturating_add(30),
            packed_path: packed_path.clone(),
            fast_session: chunked_transfer::prepare_session_streaming(
                &keypair,
                "group:recipient",
                "archive.zip",
                "group_fast_relay",
                &packed_path,
                4096,
            )
            .unwrap(),
        });

        registry.mark_staged_fast_file_transfer_active("gft_offer_active");
        registry
            .staged_fast_file_transfers
            .get_mut("gft_offer_active")
            .unwrap()
            .expires_at = current_unix_ts().saturating_sub(1);
        registry.prune_expired_fast_file_state(current_unix_ts());

        assert!(packed_path.exists());
        assert!(registry
            .staged_fast_file_transfer_cloned("gft_offer_active")
            .is_some());
        assert!(registry
            .fast_file_grant_state_cloned("gft_offer_active", "did:nxf:recipient")
            .is_none());
        assert!(registry.pending_fast_file_offers().is_empty());

        registry.mark_staged_fast_file_transfer_inactive("gft_offer_active");
        registry.prune_expired_fast_file_state(current_unix_ts());

        assert!(!packed_path.exists());
        assert!(registry
            .staged_fast_file_transfer_cloned("gft_offer_active")
            .is_none());
    }

    #[tokio::test]
    async fn mailbox_poll_progress_does_not_depend_on_ack_requests() {
        let relay_dir = tempdir().unwrap();
        let (addr, handle) =
            spawn_loopback_mailbox_service(relay_dir.path().to_path_buf(), 256 * 1024)
                .await
                .unwrap();
        let keypair = AgentKeyPair::generate("AckFail", "agent");
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let descriptor =
            build_ghost_anonymous_mailbox_descriptor(&endpoint, 5_000, 256 * 1024).unwrap();
        let (session, _) =
            create_ghost_anonymous_group_with_id("grp_ack_fail", Some("Ack Fail"), descriptor)
                .unwrap();
        let healthy_transport = TorMailboxTransport::new(relay_dir.path().join("mailbox-client"));
        let failing_transport = AckFailingMailboxTransport {
            inner: healthy_transport.clone(),
        };
        let message = build_chat_message(&session, &keypair, "hello mailbox", 60_000).unwrap();
        post_group_mailbox_message(&healthy_transport, &session, &message)
            .await
            .unwrap();

        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        registry
            .lock()
            .await
            .insert_session(session.clone())
            .unwrap();

        let actor = AgentKeyPair::generate("MailboxActor", "agent");
        let audit_dir = tempdir().unwrap();
        let audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(audit_dir.path(), &actor.did, &[3u8; 32], LogMode::Safe).unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once_with_transport(
            &registry,
            &handshake_request_gate,
            &failing_transport,
            &audit,
            &actor.did,
            "actor",
            &actor,
            &receive_dir,
            &LogMode::Safe,
            relay_dir.path(),
        )
        .await;

        let locked = registry.lock().await;
        let session_after = locked.get("grp_ack_fail").unwrap();
        assert_eq!(session_after.poll_cursor.as_deref(), Some("1"));
        drop(locked);

        let result = healthy_transport
            .poll_messages(
                &session.mailbox_descriptor,
                &session.mailbox_capability,
                &MailboxPollRequest {
                    cursor: Some("1".to_string()),
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert!(result.items.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn privacy_runtime_emits_dummy_tail_poll_when_no_mailbox_is_due() {
        let keypair = AgentKeyPair::generate("DummyPoll", "agent");
        let local_profile = build_local_member_profile(&keypair, "Dummy Poll");
        let (session, _) = create_identified_group(
            &keypair.signing_key,
            &keypair.did,
            Some("Ops"),
            build_mailbox_descriptor(
                "grp_dummy_poll",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                60_000,
                256 * 1024,
            )
            .unwrap(),
            GroupMailboxPersistence::MemoryOnly,
            local_profile,
        )
        .unwrap();

        let registry = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        registry
            .lock()
            .await
            .insert_session(session.clone())
            .unwrap();
        {
            let mut locked = registry.lock().await;
            locked.note_mailbox_transport_failure(
                &session.group_id,
                session.mailbox_descriptor.poll_interval_ms,
                current_unix_ts_ms(),
            );
        }

        let transport = RecordingMailboxTransport::default();
        let actor = AgentKeyPair::generate("DummyActor", "agent");
        let audit_dir = tempdir().unwrap();
        let audit = Arc::new(tokio::sync::Mutex::new(
            AuditLog::new(audit_dir.path(), &actor.did, &[9u8; 32], LogMode::Safe).unwrap(),
        ));
        let receive_dir = Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));

        poll_group_mailboxes_once_with_transport(
            &registry,
            &handshake_request_gate,
            &transport,
            &audit,
            &actor.did,
            "actor",
            &actor,
            &receive_dir,
            &LogMode::Safe,
            audit_dir.path(),
        )
        .await;

        let recorded = transport.poll_requests.lock().await.clone();
        assert_eq!(recorded.len(), MAILBOX_PRIVACY_DUMMY_POLLS_PER_TICK);
        assert_eq!(recorded[0].cursor.as_deref(), Some(MAILBOX_CURSOR_TAIL));
        assert_eq!(recorded[0].limit, 1);
    }
}

use serde::{Deserialize, Serialize};

/// Message types for the agent protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageKind {
    /// Initial handshake: exchange DIDs, Ed25519 verifying keys, X25519 encryption keys
    Handshake,
    /// Encrypted first-contact request resolved from a DID profile
    ContactRequest,
    /// Encrypted acceptance for a first-contact request
    ContactAccept,
    /// Encrypted rejection for a first-contact request
    ContactReject,
    /// Encrypted text message between agents
    Chat,
    /// Task assignment
    TaskRequest,
    /// Encrypted file/artifact transfer (full data inline for files < threshold)
    FileTransfer,
    /// File/artifact transfer notification (legacy, kept for compat)
    ArtifactShare,
    /// Heartbeat ping
    Heartbeat,
    /// Peer intentionally closed session; receiver should not auto-reconnect.
    DisconnectNotice,
    // ── Chunked transfer protocol ────────────────────────────────────────
    /// Initiate a chunked transfer (sends session metadata + Merkle root)
    ChunkTransferInit,
    /// Individual chunk payload (encrypted + signed)
    ChunkData,
    /// Acknowledgment of a received chunk
    ChunkAck,
    /// Request to resume an interrupted transfer
    TransferResume,
    /// Receiver explicitly rejected a transfer request
    TransferReject,
    /// Receiver acknowledged inline transfer state back to sender
    TransferStatus,
    /// Notification that all chunks have been sent
    TransferComplete,
    /// Transfer-only fast-path session open for group file downloads.
    FastTransferOpen,
    /// Key rotation announcement
    KeyRotation,
    // No transport-specific application messages are required here.
}

/// Request sent between agents over the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    /// Unique message ID for deduplication
    #[serde(default)]
    pub message_id: String,
    pub sender_did: String,
    pub sender_name: String,
    pub sender_role: String,
    pub msg_type: MessageKind,
    /// Payload semantics vary by message type
    pub payload: Vec<u8>,
    /// Ed25519 signature over (msg_type || payload || nonce || timestamp)
    pub signature: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
    /// Time-to-live in milliseconds (0 = no expiry)
    #[serde(default)]
    pub ttl_ms: u64,
}

/// Handshake payload — carries encryption public key for future file transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    /// X25519 public key (32 bytes) — used to encrypt artifact keys for this agent
    pub x25519_public_key: [u8; 32],
    /// Agent role
    pub role: String,
    /// Tor v3 onion address (56-char base32, no .onion suffix)
    /// Present only if agent is running in Tor mode
    #[serde(default)]
    pub onion_address: Option<String>,
    /// Kyber-1024 post-quantum public key (hex, 3136 chars = 1568 bytes).
    /// Current Qypha bootstrap requires this, but the field still defaults for
    /// backward-compatible decoding so older payloads can be rejected cleanly.
    #[serde(default)]
    pub kyber_public_key_hex: String,
    /// Ed25519 verifying key (hex, 64 chars = 32 bytes)
    /// Used for cryptographic signature verification of all messages from this peer.
    /// Without this, message authenticity cannot be verified (critical security field).
    #[serde(default)]
    pub verifying_key_hex: Option<String>,
    /// Whether this agent requires PQC (Kyber-1024) for all encrypted communications.
    /// When true, peers MUST use hybrid encryption — classical-only downgrade is rejected.
    #[serde(default)]
    pub pqc_enforced: bool,
    /// Hybrid ratchet KDF suite for direct-chat session bootstrap.
    /// Present when the sender is advertising a post-quantum ratchet init path.
    #[serde(default)]
    pub ratchet_hybrid_kdf_suite: Option<String>,
    /// Kyber ciphertext used to seed the direct-chat hybrid ratchet session.
    /// The lexicographically smaller DID acts as the ratchet initiator.
    #[serde(default)]
    pub ratchet_hybrid_kyber_ciphertext_hex: Option<String>,
    /// Double Ratchet initial DH public key (hex, 64 chars = 32 bytes).
    /// When present, peers will establish a ratcheted E2EE session for chat.
    #[serde(default)]
    pub ratchet_dh_public_hex: Option<String>,
    /// Whether this agent supports AEGIS-256 cascade AEAD (v1 envelopes).
    /// Used for capability negotiation during handshake.
    #[serde(default)]
    pub aegis_supported: bool,
    /// Optional invite proof code used when connecting via /connect <invite>.
    /// Receiver validates and consumes this to enforce issuer-side one-time invites.
    #[serde(default)]
    pub invite_code: Option<String>,
    /// Optional serialized iroh EndpointAddr JSON for Internet-mode reconnect.
    /// Present only on iroh handshakes; allows the remote peer to rebuild a reconnect path
    /// even when the original session was inbound.
    #[serde(default)]
    pub iroh_endpoint_addr: Option<String>,
    /// Optional acknowledgment of the peer's most recent live-session handshake message_id.
    /// Used by iroh reconnect sequencing to prove the remote side processed our handshake
    /// before we send internal ratchet bootstrap traffic.
    #[serde(default)]
    pub ack_handshake_message_id: Option<String>,
}

/// File transfer payload — everything the receiver needs to decrypt and verify
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferPayload {
    pub artifact_id: String,
    pub filename: String,
    pub classification: String,
    pub plaintext_sha256: String,
    pub encrypted_size: u64,
    pub key_envelope: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_signature: Vec<u8>,
    pub sender_verifying_key_hex: String,
}

// ─── Chunked transfer payloads ──────────────────────────────────────────────

/// Payload for ChunkTransferInit — sent before any chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkTransferInitPayload {
    pub session_id: String,
    pub artifact_id: String,
    pub filename: String,
    pub classification: String,
    pub total_size: u64,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub merkle_root: [u8; 32],
    pub plaintext_sha256: String,
    pub sender_verifying_key_hex: String,
    /// Protocol version: 1 = plaintext init, 2 = sealed metadata (fields above are dummies)
    #[serde(default = "default_init_version")]
    pub version: u8,
    /// Sender requires the receiver to explicitly accept this init again before
    /// any chunk streaming continues. Used after receiver-side session loss/restart.
    #[serde(default)]
    pub requires_reapproval: bool,
    /// Sender is attempting to continue an already-started transfer after a reconnect.
    /// When the receiver still has a live session with the same continuity token,
    /// it may auto-resume without prompting again.
    #[serde(default)]
    pub resume_requested: bool,
    /// Opaque continuity token bound to one transfer session. Lets the receiver
    /// distinguish a legitimate reconnect from a fresh, unrelated init.
    #[serde(default)]
    pub resume_token: String,
}

fn default_init_version() -> u8 {
    1
}

/// Sealed init payload — version 2 only sends non-sensitive fields.
/// Sensitive metadata (filename, classification, total_size) is encrypted
/// and embedded in chunk[0]'s sealed_metadata field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedInitPayload {
    pub session_id: String,
    pub total_chunks: usize,
    pub merkle_root: [u8; 32],
    pub sender_verifying_key_hex: String,
    pub version: u8,
}

/// Encrypted metadata blob — decrypted by recipient from chunk[0].
/// Contains all sensitive transfer metadata that observers must not see.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedMetadata {
    pub artifact_id: String,
    pub filename: String,
    pub classification: String,
    pub total_size: u64,
    pub chunk_size: usize,
    pub plaintext_sha256: String,
}

/// Payload for ChunkData — a single encrypted chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkDataPayload {
    pub session_id: String,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub encrypted_data: Vec<u8>,
    pub key_envelope: Vec<u8>,
    pub signature: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub chunk_sha256: [u8; 32],
    /// Actual size of encrypted data before padding (0 = no padding, backward compat)
    #[serde(default)]
    pub actual_encrypted_size: usize,
    /// Encrypted metadata blob (only in chunk[0], sealed init mode)
    #[serde(default)]
    pub sealed_metadata: Option<Vec<u8>>,
    /// Key envelope for sealed metadata decryption (only in chunk[0])
    #[serde(default)]
    pub sealed_metadata_key_envelope: Option<Vec<u8>>,
}

/// Payload for ChunkAck — acknowledges a single chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAckPayload {
    pub session_id: String,
    pub chunk_index: usize,
    pub verified: bool,
    pub error: Option<String>,
}

/// Payload for TransferResume — request to resume from a specific chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResumePayload {
    pub session_id: String,
    pub received_chunks: Vec<usize>,
}

/// Payload for TransferReject — explicit receiver-side rejection signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRejectPayload {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub request_message_id: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// Sender-facing status update for inline file transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStatusPayload {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub request_message_id: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Payload for TransferComplete — all chunks sent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompletePayload {
    pub session_id: String,
    pub artifact_id: String,
    pub total_chunks: usize,
    pub merkle_root: [u8; 32],
}

/// Transfer-only fast-path open request for a mailbox-granted group file download.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FastTransferOpenPayload {
    pub transfer_id: String,
    pub group_id: String,
    pub recipient_did: String,
    pub recipient_verifying_key_hex: String,
    pub ticket_id: String,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MailboxTransportKind {
    Tor,
}

impl Default for MailboxTransportKind {
    fn default() -> Self {
        Self::Tor
    }
}

fn default_mailbox_poll_interval_ms() -> u64 {
    5_000
}

fn default_mailbox_max_payload_bytes() -> usize {
    256 * 1024
}

fn default_fast_transfer_relay_only() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxDescriptor {
    #[serde(default)]
    pub transport: MailboxTransportKind,
    pub namespace: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_mailbox_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_mailbox_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MailboxBootstrapScopeKind {
    #[default]
    Invite,
    EpochRotation,
    ChunkTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxBootstrapToken {
    pub version: u8,
    #[serde(default)]
    pub scope_kind: MailboxBootstrapScopeKind,
    pub scope_id: String,
    pub namespace: String,
    pub capability_id: String,
    pub access_key_sha256: String,
    pub auth_token_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer_verifying_key_hex: String,
    #[serde(default)]
    pub pow_difficulty_bits: u8,
    #[serde(default)]
    pub pow_nonce_hex: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxCapability {
    pub capability_id: String,
    pub access_key_b64: String,
    pub auth_token_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<MailboxBootstrapToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMailboxMessageKind {
    AnonymousOpaque,
    Chat,
    FileManifest,
    FileChunkData,
    FileChunkComplete,
    FastFileOffer,
    FastFileAccept,
    FastFileGrant,
    FastFileStatus,
    DirectHandshakeOffer,
    MembershipNotice,
    KickNotice,
    GroupDisband,
    MailboxRotation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MembershipNoticeState {
    #[default]
    Joined,
    Left,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMailboxMessage {
    pub version: u8,
    pub message_id: String,
    pub group_id: String,
    pub anonymous_group: bool,
    #[serde(default)]
    pub sender_member_id: Option<String>,
    pub kind: GroupMailboxMessageKind,
    pub created_at: u64,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub ttl_ms: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupChatPayload {
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupContentCryptoSuite {
    EpochAegis256,
}

impl GroupContentCryptoSuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EpochAegis256 => "epoch_aegis256",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupContentCryptoAdvertisedState {
    pub version: u8,
    pub suite: GroupContentCryptoSuite,
    pub epoch: u64,
    pub content_secret_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousGroupWriterCredentialSuite {
    EpochHmacSha256,
}

impl AnonymousGroupWriterCredentialSuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EpochHmacSha256 => "epoch_hmac_sha256",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymousGroupWriterCredentialAdvertisedState {
    pub version: u8,
    pub suite: AnonymousGroupWriterCredentialSuite,
    pub epoch: u64,
    pub writer_secret_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileManifestPayload {
    pub manifest_id: String,
    pub filename: String,
    pub size_bytes: u64,
    pub plaintext_sha256: String,
    #[serde(default)]
    pub chunk_capability: Option<String>,
    #[serde(default)]
    pub inline_ciphertext: Option<Vec<u8>>,
    #[serde(default)]
    pub fast_transfer_id: Option<String>,
    #[serde(default)]
    pub fast_transfer_expires_at: Option<u64>,
    #[serde(default = "default_fast_transfer_relay_only")]
    pub fast_relay_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupChunkCapabilityPayload {
    pub transfer_id: String,
    pub artifact_id: String,
    pub filename: String,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub total_size: u64,
    pub plaintext_sha256: String,
    pub merkle_root: [u8; 32],
    pub sender_verifying_key_hex: String,
    pub mailbox_descriptor: MailboxDescriptor,
    pub mailbox_capability: MailboxCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileChunkPayload {
    pub transfer_id: String,
    pub artifact_id: String,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub chunk_sha256: [u8; 32],
    pub chunk_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileChunkCompletePayload {
    pub transfer_id: String,
    pub artifact_id: String,
    pub total_chunks: usize,
}

/// Group-scoped fast-transfer offer metadata.
///
/// Sent on the mailbox control plane to advertise that a large file can be
/// downloaded over a transfer-only fast path once a recipient explicitly
/// accepts it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFastFileOfferPayload {
    pub transfer_id: String,
    pub manifest_id: String,
    pub filename: String,
    pub size_bytes: u64,
    pub plaintext_sha256: String,
    pub merkle_root: [u8; 32],
    pub sender_verifying_key_hex: String,
    #[serde(default = "default_fast_transfer_relay_only")]
    pub relay_only: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

/// Recipient-side explicit acceptance for a fast group file transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFastFileAcceptPayload {
    pub transfer_id: String,
    pub group_id: String,
    pub recipient_member_id: String,
    pub recipient_verifying_key_hex: String,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Recipient-targeted grant wrapper distributed over the mailbox control plane.
///
/// The mailbox payload itself is visible to all joined members, so the actual
/// fast-transfer ticket must be wrapped inside `encrypted_grant_envelope`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFastFileGrantPayload {
    pub grant_id: String,
    pub transfer_id: String,
    pub group_id: String,
    pub sender_member_id: String,
    pub recipient_member_id: String,
    pub sender_verifying_key_hex: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub encrypted_grant_envelope: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Recipient-specific secret carried inside a `GroupFastFileGrantPayload`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFastFileGrantSecret {
    pub transfer_id: String,
    pub group_id: String,
    pub mailbox_transfer_id: String,
    pub recipient_did: String,
    pub ticket_id: String,
    #[serde(default = "default_fast_transfer_relay_only")]
    pub relay_only: bool,
    pub endpoint_addr_json: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupFastFileStatusKind {
    Started,
    Completed,
    Aborted,
    Expired,
}

/// Group-visible lifecycle event for a fast file transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFastFileStatusPayload {
    pub transfer_id: String,
    pub group_id: String,
    pub sender_member_id: String,
    pub recipient_member_id: String,
    pub status: GroupFastFileStatusKind,
    pub created_at: u64,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectHandshakeOfferPayload {
    pub offer_id: String,
    pub group_id: String,
    pub sender_member_id: String,
    pub sender_verifying_key_hex: String,
    pub target_member_id: String,
    pub encrypted_invite_envelope: Vec<u8>,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipNoticePayload {
    pub group_id: String,
    pub member_id: String,
    pub display_name: String,
    pub verifying_key_hex: String,
    pub encryption_public_key_hex: String,
    #[serde(default)]
    pub kyber_public_key_hex: Option<String>,
    #[serde(default)]
    pub state: MembershipNoticeState,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupDisbandPayload {
    pub group_id: String,
    pub owner_member_id: String,
    pub owner_verifying_key_hex: String,
    pub mailbox_epoch: u64,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKickNoticePayload {
    pub group_id: String,
    pub owner_member_id: String,
    pub owner_verifying_key_hex: String,
    pub kicked_member_id: String,
    #[serde(default)]
    pub kicked_display_name: String,
    pub mailbox_epoch: u64,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxRotationPayload {
    pub rotation_id: String,
    pub group_id: String,
    pub sender_member_id: String,
    pub sender_verifying_key_hex: String,
    pub target_member_id: String,
    pub kicked_member_id: String,
    pub new_mailbox_epoch: u64,
    #[serde(default)]
    pub join_locked: bool,
    #[serde(default)]
    pub public_mailbox_descriptor: Option<MailboxDescriptor>,
    #[serde(default)]
    pub public_mailbox_capability: Option<MailboxCapability>,
    #[serde(default)]
    pub public_content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
    pub encrypted_session_bundle_b64: String,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_payload_roundtrip_preserves_optional_iroh_endpoint_addr() {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(101);
        let payload = HandshakePayload {
            x25519_public_key: [7u8; 32],
            role: "agent".to_string(),
            onion_address: None,
            kyber_public_key_hex: "ab".repeat(32),
            verifying_key_hex: Some("cd".repeat(32)),
            pqc_enforced: true,
            ratchet_hybrid_kdf_suite: Some("qypha/x25519+kyber1024/ratchet-init/v1".to_string()),
            ratchet_hybrid_kyber_ciphertext_hex: Some("aa".repeat(1568)),
            ratchet_dh_public_hex: Some("ef".repeat(32)),
            aegis_supported: true,
            invite_code: Some("invite-token".to_string()),
            iroh_endpoint_addr: Some(endpoint_json.clone()),
            ack_handshake_message_id: Some("hs_ack_1".to_string()),
        };

        let encoded = serde_json::to_vec(&payload).unwrap();
        let decoded: HandshakePayload = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(
            decoded.iroh_endpoint_addr.as_deref(),
            Some(endpoint_json.as_str())
        );
        assert_eq!(
            decoded.ack_handshake_message_id.as_deref(),
            Some("hs_ack_1")
        );
        assert_eq!(
            decoded.ratchet_hybrid_kdf_suite.as_deref(),
            Some("qypha/x25519+kyber1024/ratchet-init/v1")
        );
        assert_eq!(
            decoded
                .ratchet_hybrid_kyber_ciphertext_hex
                .as_deref()
                .map(str::len),
            Some(3136)
        );
    }

    #[test]
    fn handshake_payload_backward_compat_defaults_missing_iroh_endpoint_addr() {
        let encoded = serde_json::json!({
            "x25519_public_key": vec![0u8; 32],
            "role": "agent",
            "aegis_supported": true,
            "pqc_enforced": false
        });
        let decoded: HandshakePayload = serde_json::from_value(encoded).unwrap();
        assert!(decoded.kyber_public_key_hex.is_empty());
        assert!(decoded.iroh_endpoint_addr.is_none());
        assert!(decoded.ack_handshake_message_id.is_none());
        assert!(decoded.ratchet_hybrid_kdf_suite.is_none());
        assert!(decoded.ratchet_hybrid_kyber_ciphertext_hex.is_none());
    }

    #[test]
    fn mailbox_descriptor_defaults_are_applied() {
        let encoded = serde_json::json!({
            "namespace": "mailbox:ops"
        });
        let decoded: MailboxDescriptor = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.transport, MailboxTransportKind::Tor);
        assert_eq!(decoded.poll_interval_ms, 5_000);
        assert_eq!(decoded.max_payload_bytes, 256 * 1024);
    }

    #[test]
    fn group_mailbox_message_roundtrip_preserves_sender_identity_hint() {
        let message = GroupMailboxMessage {
            version: 1,
            message_id: "msg-123".to_string(),
            group_id: "grp_ops".to_string(),
            anonymous_group: false,
            sender_member_id: Some("did:nxf:member".to_string()),
            kind: GroupMailboxMessageKind::Chat,
            created_at: 1234,
            created_at_ms: 1_234_000,
            ttl_ms: 5000,
            ciphertext: vec![1, 2, 3, 4],
        };

        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded: GroupMailboxMessage = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.group_id, "grp_ops");
        assert_eq!(decoded.sender_member_id.as_deref(), Some("did:nxf:member"));
        assert_eq!(decoded.kind, GroupMailboxMessageKind::Chat);
    }

    #[test]
    fn chunk_transfer_init_defaults_reapproval_to_false() {
        let encoded = serde_json::json!({
            "session_id": "sess_test",
            "artifact_id": "art_test",
            "filename": "file.bin",
            "classification": "confidential",
            "total_size": 1024,
            "chunk_size": 512,
            "total_chunks": 2,
            "merkle_root": vec![0u8; 32],
            "plaintext_sha256": "00",
            "sender_verifying_key_hex": "ab",
            "version": 1
        });

        let decoded: ChunkTransferInitPayload = serde_json::from_value(encoded).unwrap();
        assert!(!decoded.requires_reapproval);
    }

    #[test]
    fn group_fast_file_offer_defaults_relay_only_to_true() {
        let encoded = serde_json::json!({
            "transfer_id": "gft_x",
            "manifest_id": "gmanifest_x",
            "filename": "archive.zip",
            "size_bytes": 1024,
            "plaintext_sha256": "aa",
            "merkle_root": vec![7u8; 32],
            "sender_verifying_key_hex": "ab",
            "created_at": 1,
            "expires_at": 2
        });

        let decoded: GroupFastFileOfferPayload = serde_json::from_value(encoded).unwrap();
        assert!(decoded.relay_only);
    }

    #[test]
    fn group_fast_file_grant_secret_roundtrip_preserves_endpoint_addr() {
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(102);
        let secret = GroupFastFileGrantSecret {
            transfer_id: "gft_x".to_string(),
            group_id: "grp_fast".to_string(),
            mailbox_transfer_id: "sess_mailbox_x".to_string(),
            recipient_did: "did:nxf:recipient".to_string(),
            ticket_id: "ticket_x".to_string(),
            relay_only: true,
            endpoint_addr_json: endpoint_json,
            expires_at: 99,
        };

        let encoded = serde_json::to_vec(&secret).unwrap();
        let decoded: GroupFastFileGrantSecret = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.endpoint_addr_json, secret.endpoint_addr_json);
        assert!(decoded.relay_only);
    }

    #[test]
    fn fast_transfer_open_payload_roundtrip() {
        let payload = FastTransferOpenPayload {
            transfer_id: "gft_x".to_string(),
            group_id: "grp_fast".to_string(),
            recipient_did: "did:nxf:recipient".to_string(),
            recipient_verifying_key_hex: "ab".repeat(32),
            ticket_id: "ticket_x".to_string(),
            created_at: 123,
            signature: vec![7u8; 64],
        };

        let encoded = serde_json::to_vec(&payload).unwrap();
        let decoded: FastTransferOpenPayload = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}

// ── Ratcheted E2EE payloads ─────────────────────────────────────────────────

/// Ratcheted chat payload — Double Ratchet header + AEGIS-256 encrypted message.
///
/// Used with magic byte 0x02 prefix in chat payloads.
/// Provides per-message forward secrecy via Signal Double Ratchet protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetChatPayload {
    /// Ratchet header (DH public key + chain counters)
    pub header: crate::crypto::RatchetHeader,
    /// Encrypted message: nonce(32) || aegis_ct || aegis_tag(32)
    pub ciphertext: Vec<u8>,
}

/// Response to an agent request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub success: bool,
    pub message: String,
}

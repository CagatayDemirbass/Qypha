//! Invite system for direct peers and mailbox-backed groups.
//!
//! Direct peer invites and mailbox group invites are intentionally separate
//! formats. Group invites must not smuggle direct transport reachability.

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::identity::AgentKeyPair;
use crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json;
use crate::network::protocol::{
    AnonymousGroupWriterCredentialAdvertisedState, AnonymousGroupWriterCredentialSuite,
    GroupContentCryptoAdvertisedState, MailboxBootstrapScopeKind, MailboxCapability,
    MailboxDescriptor,
};

/// Default TTL for Tor invite codes (24 hours).
/// Tor invites are harder to re-generate (requires .onion stability), so longer TTL.
pub const INVITE_TTL_TOR_SECS: u64 = 86400;

/// Default TTL for TCP/Internet invite codes (1 hour).
/// TCP invites contain IP addresses which change more frequently.
pub const INVITE_TTL_TCP_SECS: u64 = 3600;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    PeerDirect,
    GroupMailbox,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum EncodedInvite {
    PeerDirect(PeerInvite),
    GroupMailbox(GroupMailboxInvite),
}

#[derive(Debug, Clone)]
pub enum DecodedInvite {
    Peer(PeerInvite),
    GroupMailbox(GroupMailboxInvite),
}

impl DecodedInvite {
    pub fn from_code(code: &str) -> Result<Self> {
        let bytes = decode_invite_bytes(code)?;
        if let Ok(encoded) = bincode::deserialize::<EncodedInvite>(&bytes) {
            return Ok(match encoded {
                EncodedInvite::PeerDirect(invite) => Self::Peer(invite),
                EncodedInvite::GroupMailbox(invite) => Self::GroupMailbox(invite),
            });
        }
        Err(anyhow::anyhow!("Invalid invite encoding"))
    }

    pub fn to_code(&self) -> Result<String> {
        let encoded = match self {
            Self::Peer(invite) => EncodedInvite::PeerDirect(invite.clone()),
            Self::GroupMailbox(invite) => EncodedInvite::GroupMailbox(invite.clone()),
        };
        encode_invite_bytes(&encoded)
    }

    pub fn kind(&self) -> InviteKind {
        match self {
            Self::Peer(_) => InviteKind::PeerDirect,
            Self::GroupMailbox(_) => InviteKind::GroupMailbox,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupInviteScope {
    GroupMailbox,
}

impl Default for GroupInviteScope {
    fn default() -> Self {
        Self::GroupMailbox
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupMailboxInvite {
    pub version: u8,
    pub group_id: String,
    pub anonymous_group: bool,
    pub created_at: u64,
    pub expiry: u64,
    pub issuer_verifying_key: [u8; 32],
    #[serde(default)]
    pub invite_id: String,
    #[serde(default)]
    pub nonce: [u8; 16],
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// A signed invite containing everything a peer needs to connect
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInvite {
    /// Invite format version
    pub version: u8,
    /// Optional identity hint retained for backward compatibility.
    /// Modern invites leave this empty and derive identity from `verifying_key`.
    #[serde(default)]
    pub did: String,
    /// libp2p PeerId (base58)
    pub peer_id: String,
    /// .onion v3 address (56 chars, no ".onion" suffix)
    #[serde(default)]
    pub onion_address: Option<String>,
    /// TCP multiaddr for LAN mode (e.g., "/ip4/192.168.1.100/tcp/9090")
    #[serde(default)]
    pub tcp_address: Option<String>,
    /// Serialized iroh EndpointAddr JSON (Internet mode over iroh)
    #[serde(default)]
    pub iroh_endpoint_addr: Option<String>,
    /// Onion service port
    #[serde(default = "default_onion_port")]
    pub onion_port: u16,
    /// Ed25519 verifying key (raw bytes; invite authenticity depends on it).
    pub verifying_key: [u8; 32],
    /// Timestamp of creation (UNIX seconds)
    pub created_at: u64,
    /// Unique random invite id to guarantee per-invite uniqueness.
    #[serde(default)]
    pub invite_id: [u8; 16],
    /// Ed25519 signature over the canonical invite bytes.
    #[serde(default)]
    pub signature: Vec<u8>,
}

fn default_onion_port() -> u16 {
    9090
}

fn encode_invite_bytes<T: Serialize>(value: &T) -> Result<String> {
    let encoded = bincode::serialize(value).context("Failed to serialize invite")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encoded))
}

fn decode_invite_bytes(code: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code.trim())
        .context("Invalid base64 invite code")
}

fn derive_did_from_vk(vk: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk.as_bytes());
    let hash = hasher.finalize();
    format!("did:nxf:{}", hex::encode(hash))
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
        None => buf.push(0x00),
        Some(value) => {
            buf.push(0x01);
            write_canonical_str(buf, value);
        }
    }
}

fn write_canonical_opt_group_content_crypto_state(
    buf: &mut Vec<u8>,
    value: Option<&GroupContentCryptoAdvertisedState>,
) {
    match value {
        None => buf.push(0x00),
        Some(value) => {
            buf.push(0x01);
            buf.push(value.version);
            write_canonical_str(buf, value.suite.as_str());
            buf.extend_from_slice(&value.epoch.to_le_bytes());
            write_canonical_str(buf, &value.content_secret_b64);
        }
    }
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

fn write_canonical_opt_mailbox_bootstrap_token(
    buf: &mut Vec<u8>,
    value: Option<&crate::network::protocol::MailboxBootstrapToken>,
) {
    match value {
        None => buf.push(0x00),
        Some(value) => {
            buf.push(0x01);
            write_canonical_mailbox_bootstrap_token(buf, value);
        }
    }
}

fn write_canonical_opt_anonymous_writer_state(
    buf: &mut Vec<u8>,
    value: Option<&AnonymousGroupWriterCredentialAdvertisedState>,
) {
    match value {
        None => buf.push(0x00),
        Some(value) => {
            buf.push(0x01);
            buf.push(value.version);
            write_canonical_str(buf, value.suite.as_str());
            buf.extend_from_slice(&value.epoch.to_le_bytes());
            write_canonical_str(buf, &value.writer_secret_b64);
        }
    }
}

/// Validate a Tor v3 onion address (without ".onion" suffix).
pub fn is_valid_onion_v3(addr: &str) -> bool {
    addr.len() == 56 && addr.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

impl PeerInvite {
    /// DID must be cryptographically bound to the Ed25519 verifying key.
    /// Format: did:nxf:<SHA256(verifying_key) as hex> (64 hex chars, 256-bit).
    fn derive_did_from_vk(vk: &VerifyingKey) -> String {
        derive_did_from_vk(vk)
    }

    pub fn canonical_did(&self) -> Result<String> {
        let verifying_key = VerifyingKey::from_bytes(&self.verifying_key)
            .context("Invalid Ed25519 verifying key")?;
        Ok(Self::derive_did_from_vk(&verifying_key))
    }

    pub fn shareable_did(&self) -> String {
        crate::network::contact_did::contact_did_from_verifying_key_bytes(self.verifying_key)
    }

    /// Build canonical signing data — deterministic bytes independent of JSON.
    ///
    /// Format: magic prefix + length-prefixed fields in fixed order.
    /// This ensures signature verification works across binary versions
    /// even when new optional fields are added to the struct.
    fn signing_data(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(512);
        // Domain separation prefix
        d.extend_from_slice(b"NXF_INVITE_v1:");
        d.push(self.version);

        write_canonical_str(&mut d, &self.did);
        write_canonical_str(&mut d, &self.peer_id);
        write_canonical_opt_str(&mut d, self.onion_address.as_deref());
        write_canonical_opt_str(&mut d, self.tcp_address.as_deref());
        write_canonical_opt_str(&mut d, self.iroh_endpoint_addr.as_deref());
        d.extend_from_slice(&self.onion_port.to_le_bytes());
        write_canonical_bytes(&mut d, &self.verifying_key);
        d.extend_from_slice(&self.created_at.to_le_bytes());
        write_canonical_bytes(&mut d, &self.invite_id);
        d
    }

    /// Generate a signed invite from our identity and network state.
    pub fn generate(
        keypair: &AgentKeyPair,
        peer_id: &str,
        onion_address: Option<&str>,
        tcp_address: Option<&str>,
        onion_port: u16,
        iroh_endpoint_addr: Option<&str>,
    ) -> Result<Self> {
        let version = 7;
        let iroh_endpoint_addr = iroh_endpoint_addr
            .map(sanitize_relay_only_iroh_endpoint_addr_json)
            .transpose()?;
        let (onion_address, tcp_address) = if iroh_endpoint_addr.is_some() {
            (None, None)
        } else if onion_address.is_some() {
            (onion_address.map(String::from), None)
        } else {
            (None, tcp_address.map(String::from))
        };

        let mut invite = Self {
            version,
            did: String::new(),
            peer_id: peer_id.to_string(),
            onion_address,
            tcp_address,
            iroh_endpoint_addr,
            onion_port,
            verifying_key: keypair.verifying_key.to_bytes(),
            created_at: chrono::Utc::now().timestamp() as u64,
            invite_id: rand::random::<[u8; 16]>(),
            signature: Vec::new(),
        };

        // Sign canonical representation (not JSON — resilient to field changes)
        let data = invite.signing_data();
        let sig = keypair.signing_key.sign(&data);
        invite.signature = sig.to_bytes().to_vec();

        Ok(invite)
    }

    /// Encode to a compact, shareable base64url string.
    pub fn to_code(&self) -> Result<String> {
        DecodedInvite::Peer(self.clone()).to_code()
    }

    /// Decode from a base64url invite code.
    pub fn from_code(code: &str) -> Result<Self> {
        match DecodedInvite::from_code(code)? {
            DecodedInvite::Peer(invite) => Ok(invite),
            DecodedInvite::GroupMailbox(_) => Err(anyhow::anyhow!(
                "Invite is a mailbox-backed group invite, not a direct peer invite"
            )),
        }
    }

    /// Verify the Ed25519 signature on this invite.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.verifying_key)
            .context("Invalid Ed25519 verifying key")?;

        // Identity binding check: when a DID hint is present, it must match
        // the verifying key fingerprint. Modern invites intentionally omit it.
        let expected_did = Self::derive_did_from_vk(&verifying_key);
        let expected_shareable_did =
            crate::network::contact_did::contact_did_from_verifying_key(&verifying_key);
        if !self.did.is_empty() && self.did != expected_did && self.did != expected_shareable_did {
            return Err(anyhow::anyhow!(
                "Invite DID/key mismatch: claimed DID '{}' does not match verifying key fingerprint '{}'",
                self.did,
                expected_did
            ));
        }

        // Verify against canonical signing data (not JSON)
        let data = self.signing_data();

        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;

        Ok(verifying_key.verify_strict(&data, &sig).is_ok())
    }

    /// Verify the signature AND check that the invite has not expired.
    ///
    /// TTL is determined by invite type:
    /// - Tor invites (.onion present): 24 hours
    /// - TCP/Internet invites: 1 hour
    /// - Custom TTL can be provided to override defaults
    ///
    /// Returns Ok(true) if valid and not expired.
    pub fn verify_with_expiry(&self, custom_ttl_secs: Option<u64>) -> Result<bool> {
        // 1. Verify cryptographic signature
        if !self.verify()? {
            return Ok(false);
        }

        // 1b. Validate critical address fields to prevent malformed input abuse.
        if let Some(ref onion) = self.onion_address {
            if !is_valid_onion_v3(onion) {
                return Err(anyhow::anyhow!(
                    "Invite has invalid onion address format (expected 56-char v3 address without suffix)"
                ));
            }
        }
        if let Some(ref endpoint_json) = self.iroh_endpoint_addr {
            sanitize_relay_only_iroh_endpoint_addr_json(endpoint_json).map_err(|e| {
                anyhow::anyhow!(
                    "Invite has invalid or non-relay iroh endpoint payload: {}",
                    e
                )
            })?;
        }
        if self.version >= 4 && self.invite_id == [0u8; 16] {
            return Err(anyhow::anyhow!(
                "Invite missing invite_id (v4+ invites require unique id)"
            ));
        }

        // 2. Check expiry
        let now = chrono::Utc::now().timestamp() as u64;
        let ttl = custom_ttl_secs.unwrap_or_else(|| {
            // If invite contains any non-onion routable address, apply the
            // shorter TTL. Mixed-format legacy invites should not inherit
            // the longer Tor TTL.
            if self.has_tcp() {
                INVITE_TTL_TCP_SECS
            } else if self.has_iroh() {
                INVITE_TTL_TCP_SECS
            } else if self.has_onion() {
                INVITE_TTL_TOR_SECS
            } else {
                INVITE_TTL_TCP_SECS
            }
        });

        if now > self.created_at.saturating_add(ttl) {
            let age_secs = now.saturating_sub(self.created_at);
            return Err(anyhow::anyhow!(
                "Invite EXPIRED: created {} seconds ago (TTL={} seconds). \
                 Generate a fresh invite with /invite.",
                age_secs,
                ttl
            ));
        }

        // 3. Check for future timestamps (clock skew tolerance: 5 minutes)
        if self.created_at > now + 300 {
            return Err(anyhow::anyhow!(
                "Invite has future timestamp (clock skew {} seconds). \
                 Synchronize system clocks.",
                self.created_at - now
            ));
        }

        Ok(true)
    }

    /// Check if this invite has a .onion address (Tor mode)
    pub fn has_onion(&self) -> bool {
        self.onion_address.is_some()
    }

    /// Check if this invite has a TCP address (LAN mode)
    pub fn has_tcp(&self) -> bool {
        self.tcp_address.is_some()
    }

    /// Check if this invite has an iroh EndpointAddr payload (Internet mode)
    pub fn has_iroh(&self) -> bool {
        self.iroh_endpoint_addr.is_some()
    }
}

impl GroupMailboxInvite {
    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(b"QYPHA_GROUP_INVITE_TOKEN_V1:");
        data.push(self.version);
        write_canonical_str(&mut data, &self.group_id);
        data.push(u8::from(self.anonymous_group));
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.expiry.to_le_bytes());
        write_canonical_bytes(&mut data, &self.issuer_verifying_key);
        write_canonical_str(&mut data, &self.invite_id);
        write_canonical_bytes(&mut data, &self.nonce);
        data
    }

    pub fn generate(
        signing_key: &ed25519_dalek::SigningKey,
        issuer_did: Option<&str>,
        group_id: &str,
        group_name: Option<&str>,
        anonymous_group: bool,
        mailbox_descriptor: MailboxDescriptor,
        mailbox_capability: MailboxCapability,
        content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
        anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
        expiry: u64,
    ) -> Result<Self> {
        Self::generate_with_join_locked(
            signing_key,
            issuer_did,
            group_id,
            group_name,
            anonymous_group,
            false,
            mailbox_descriptor,
            mailbox_capability,
            content_crypto_state,
            anonymous_writer_state,
            expiry,
        )
    }

    pub fn generate_with_join_locked(
        signing_key: &ed25519_dalek::SigningKey,
        issuer_did: Option<&str>,
        group_id: &str,
        _group_name: Option<&str>,
        anonymous_group: bool,
        join_locked: bool,
        _mailbox_descriptor: MailboxDescriptor,
        _mailbox_capability: MailboxCapability,
        content_crypto_state: Option<GroupContentCryptoAdvertisedState>,
        anonymous_writer_state: Option<AnonymousGroupWriterCredentialAdvertisedState>,
        expiry: u64,
    ) -> Result<Self> {
        let created_at = chrono::Utc::now().timestamp() as u64;
        if group_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Group mailbox invite requires group_id"));
        }
        if expiry <= created_at {
            return Err(anyhow::anyhow!(
                "Group mailbox invite expiry must be in the future"
            ));
        }
        if anonymous_group && issuer_did.is_some() {
            return Err(anyhow::anyhow!(
                "Anonymous group invites must not embed issuer DID"
            ));
        }
        if anonymous_group && join_locked {
            return Err(anyhow::anyhow!(
                "Anonymous group invites must not advertise join_locked"
            ));
        }
        if anonymous_group && (content_crypto_state.is_some() != anonymous_writer_state.is_some()) {
            return Err(anyhow::anyhow!(
                "Anonymous group invites must embed content crypto state and anonymous writer state together"
            ));
        }
        if !anonymous_group && anonymous_writer_state.is_some() {
            return Err(anyhow::anyhow!(
                "Identified group invites must not embed anonymous writer state"
            ));
        }

        let invite_id = uuid::Uuid::new_v4().simple().to_string();
        let mut invite = Self {
            version: 1,
            group_id: group_id.to_string(),
            anonymous_group,
            created_at,
            expiry,
            issuer_verifying_key: signing_key.verifying_key().to_bytes(),
            invite_id,
            nonce: rand::random::<[u8; 16]>(),
            signature: Vec::new(),
        };

        let signature = signing_key.sign(&invite.signing_data());
        invite.signature = signature.to_bytes().to_vec();
        Ok(invite)
    }

    pub fn to_code(&self) -> Result<String> {
        DecodedInvite::GroupMailbox(self.clone()).to_code()
    }

    pub fn from_code(code: &str) -> Result<Self> {
        match DecodedInvite::from_code(code)? {
            DecodedInvite::GroupMailbox(invite) => Ok(invite),
            DecodedInvite::Peer(_) => Err(anyhow::anyhow!(
                "Invite is a direct peer invite, not a mailbox-backed group invite"
            )),
        }
    }

    pub fn verify(&self) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .context("Invalid Ed25519 verifying key")?;

        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data(), &signature)
            .is_ok())
    }

    pub fn verify_with_expiry(&self) -> Result<bool> {
        if !self.verify()? {
            return Ok(false);
        }
        if self.group_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Group mailbox invite missing group_id"));
        }
        if self.invite_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Group mailbox invite missing invite_id"));
        }
        if self.nonce == [0u8; 16] {
            return Err(anyhow::anyhow!("Group mailbox invite missing nonce"));
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if self.created_at > now + 300 {
            return Err(anyhow::anyhow!(
                "Group mailbox invite has future timestamp (clock skew {} seconds). Synchronize system clocks.",
                self.created_at - now
            ));
        }
        if self.expiry <= self.created_at {
            return Err(anyhow::anyhow!(
                "Group mailbox invite expiry must be after creation time"
            ));
        }
        if now > self.expiry {
            return Err(anyhow::anyhow!(
                "Group mailbox invite EXPIRED. Generate a fresh invite."
            ));
        }

        Ok(true)
    }

    pub fn issuer_contact_did(&self) -> String {
        crate::network::contact_did::contact_did_from_verifying_key_bytes(self.issuer_verifying_key)
    }

    pub fn issuer_verifying_key_hex(&self) -> String {
        hex::encode(self.issuer_verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_blob_contains(haystack: &[u8], needle: &str) -> bool {
        let needle = needle.as_bytes();
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[test]
    fn peer_invite_roundtrip_and_signature_verifies() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");

        let invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            None,
            9090,
            None,
        )
        .unwrap();

        let code = invite.to_code().unwrap();
        let decoded = PeerInvite::from_code(&code).unwrap();

        assert_eq!(decoded.version, 7);
        assert_eq!(decoded.did, invite.did);
        assert!(decoded.did.is_empty());
        assert_eq!(decoded.verifying_key, keypair.verifying_key.to_bytes());
        assert_eq!(decoded.canonical_did().unwrap(), keypair.did);
        assert_eq!(
            decoded.shareable_did(),
            crate::network::contact_did::contact_did_from_verifying_key_bytes(
                keypair.verifying_key.to_bytes()
            )
        );
        assert_eq!(
            decoded.onion_address.as_deref(),
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx")
        );
        assert_eq!(decoded.onion_port, 9090);
        assert!(decoded.verify().unwrap());
        assert!(decoded.verify_with_expiry(None).unwrap());
    }

    #[test]
    fn peer_invite_signature_verification_rejects_tamper() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");

        let invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("testaddress123456789012345678901234567890123456789012345"),
            None,
            9090,
            None,
        )
        .unwrap();

        assert!(invite.verify().unwrap());

        let mut tampered = invite.clone();
        tampered.peer_id = "12D3KooWForgedPeerId".to_string();
        assert!(!tampered.verify().unwrap());
    }

    #[test]
    fn peer_invite_expiry_expired() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");
        let mut invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            None,
            Some("/ip4/192.168.1.100/tcp/9090"),
            9090,
            None,
        )
        .unwrap();

        invite.created_at = chrono::Utc::now().timestamp() as u64 - 7200;
        invite.signature = keypair
            .signing_key
            .sign(&invite.signing_data())
            .to_bytes()
            .to_vec();

        let result = invite.verify_with_expiry(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EXPIRED"));
    }

    #[test]
    fn peer_invite_without_onion_roundtrips() {
        let keypair = AgentKeyPair::generate("LanAgent", "hr");

        let invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            None,
            Some("/ip4/192.168.1.100/tcp/9090"),
            9090,
            None,
        )
        .unwrap();

        assert!(!invite.has_onion());
        assert!(invite.has_tcp());

        let code = invite.to_code().unwrap();
        let decoded = PeerInvite::from_code(&code).unwrap();
        assert!(decoded.verify().unwrap());
    }

    #[test]
    fn peer_invite_generation_strips_non_relay_iroh_routes_and_fallbacks() {
        let keypair = AgentKeyPair::generate("RelayOnlyAgent", "ops");
        let endpoint_id = iroh::SecretKey::from_bytes(&[14u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 7777))),
                iroh::TransportAddr::Relay(
                    "https://relay.example.test"
                        .parse::<iroh::RelayUrl>()
                        .unwrap(),
                ),
            ],
        );
        let endpoint_json = serde_json::to_string(&endpoint_addr).unwrap();

        let invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            Some("/ip4/127.0.0.1/tcp/9090"),
            9090,
            Some(&endpoint_json),
        )
        .unwrap();

        assert!(invite.onion_address.is_none());
        assert!(invite.tcp_address.is_none());
        let parsed = serde_json::from_str::<iroh::EndpointAddr>(
            invite.iroh_endpoint_addr.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.ip_addrs().count(), 0);
        assert_eq!(parsed.relay_urls().count(), 1);
    }

    #[test]
    fn peer_invite_verify_rejects_direct_only_iroh_payload() {
        let keypair = AgentKeyPair::generate("RelayOnlyAgent", "ops");
        let endpoint_id = iroh::SecretKey::from_bytes(&[15u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [iroh::TransportAddr::Ip(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                7777,
            )))],
        );
        let endpoint_json = serde_json::to_string(&endpoint_addr).unwrap();
        let invite =
            PeerInvite::generate(&keypair, "12D3KooWTestPeerId", None, None, 9090, None).unwrap();
        let mut tampered = invite.clone();
        tampered.iroh_endpoint_addr = Some(endpoint_json);
        tampered.signature = keypair
            .signing_key
            .sign(&tampered.signing_data())
            .to_bytes()
            .to_vec();

        let result = tampered.verify_with_expiry(None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("non-relay iroh endpoint"));
    }

    #[test]
    fn peer_invite_invalid_onion_rejected() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");
        let mut invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            None,
            9090,
            None,
        )
        .unwrap();

        invite.onion_address = Some("short".to_string());
        invite.signature = keypair
            .signing_key
            .sign(&invite.signing_data())
            .to_bytes()
            .to_vec();

        let result = invite.verify_with_expiry(None);
        assert!(result.is_err(), "Malformed onion address must be rejected");
    }

    #[test]
    fn peer_invite_did_key_mismatch_rejected() {
        let keypair = AgentKeyPair::generate("Alice", "executive");
        let mut invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            None,
            9090,
            None,
        )
        .unwrap();

        invite.did =
            "did:nxf:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        invite.signature = keypair
            .signing_key
            .sign(&invite.signing_data())
            .to_bytes()
            .to_vec();

        assert!(invite.verify().is_err());
    }

    #[test]
    fn peer_invite_omits_explicit_did_string_from_payload() {
        let keypair = AgentKeyPair::generate("MinimalAgent", "agent");
        let invite = PeerInvite::generate(
            &keypair,
            "12D3KooWTestPeerId",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            None,
            9090,
            None,
        )
        .unwrap();
        let code = invite.to_code().unwrap();
        let encoded_bytes = decode_invite_bytes(&code).unwrap();
        let shareable_did = crate::network::contact_did::contact_did_from_verifying_key_bytes(
            keypair.verifying_key.to_bytes(),
        );

        assert!(invite.did.is_empty());
        assert!(
            !encoded_blob_contains(&encoded_bytes, &keypair.did),
            "invite payload must not embed canonical DID"
        );
        assert!(
            !encoded_blob_contains(&encoded_bytes, &shareable_did),
            "invite payload must not embed shareable DID"
        );
    }

    #[test]
    fn peer_invite_verify_accepts_legacy_canonical_did_hint() {
        let keypair = AgentKeyPair::generate("LegacyInvite", "agent");
        let mut invite =
            PeerInvite::generate(&keypair, "12D3KooWTestPeerId", None, None, 9090, None).unwrap();
        invite.did = keypair.did.clone();
        invite.signature = keypair
            .signing_key
            .sign(&invite.signing_data())
            .to_bytes()
            .to_vec();

        assert!(invite.verify().unwrap());
    }

    #[test]
    fn generated_peer_invites_are_unique() {
        let keypair = AgentKeyPair::generate("UniqueAgent", "finance");

        let invite1 =
            PeerInvite::generate(&keypair, "12D3KooWTestPeerId", None, None, 9090, None).unwrap();
        let invite2 =
            PeerInvite::generate(&keypair, "12D3KooWTestPeerId", None, None, 9090, None).unwrap();

        assert_eq!(invite1.version, 7);
        assert_eq!(invite2.version, 7);
        assert_ne!(invite1.invite_id, invite2.invite_id);
        assert_ne!(invite1.invite_id, [0u8; 16]);
        assert_ne!(invite2.invite_id, [0u8; 16]);

        let code1 = invite1.to_code().unwrap();
        let code2 = invite2.to_code().unwrap();
        assert_ne!(
            code1, code2,
            "Each /invite generation must produce a distinct code"
        );
    }

    #[test]
    fn group_mailbox_invite_roundtrip_and_verification() {
        let keypair = AgentKeyPair::generate("MailboxOwner", "agent");
        let endpoint = "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444";
        let invite = GroupMailboxInvite::generate_with_join_locked(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_mailbox_ops",
            Some("Ops"),
            false,
            true,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:ops".to_string(),
                endpoint: Some(endpoint.to_string()),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_ops".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();

        let code = invite.to_code().unwrap();
        let decoded = GroupMailboxInvite::from_code(&code).unwrap();
        let encoded_bytes = decode_invite_bytes(&code).unwrap();

        assert_eq!(decoded.group_id, "grp_mailbox_ops");
        assert!(!decoded.anonymous_group);
        assert_eq!(
            decoded.issuer_verifying_key,
            keypair.signing_key.verifying_key().to_bytes()
        );
        assert_eq!(decoded.issuer_contact_did(), invite.issuer_contact_did());
        assert!(
            !encoded_blob_contains(&encoded_bytes, endpoint),
            "minimal group invite token must not embed mailbox endpoint"
        );
        assert!(
            !encoded_blob_contains(&encoded_bytes, "mailbox:ops"),
            "minimal group invite token must not embed mailbox namespace"
        );
        assert!(
            !encoded_blob_contains(&encoded_bytes, "Ops"),
            "minimal group invite token must not embed group display name"
        );
        assert!(decoded.verify_with_expiry().unwrap());
    }

    #[test]
    fn minimal_group_mailbox_invite_code_is_not_larger_than_peer_invite_code() {
        let keypair = AgentKeyPair::generate("LegacyMailboxOwner", "agent");
        let peer_invite = PeerInvite::generate(
            &keypair,
            "12D3KooWLegacyPeer",
            Some("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"),
            None,
            9090,
            None,
        )
        .unwrap();
        let group_invite = GroupMailboxInvite::generate(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_mailbox_legacy",
            Some("Legacy"),
            false,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:legacy".to_string(),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_legacy".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();

        let peer_code = peer_invite.to_code().unwrap();
        let group_code = group_invite.to_code().unwrap();

        assert!(
            group_code.len() <= peer_code.len(),
            "minimal group invite token should stay comparable to direct invite length"
        );
    }

    #[test]
    fn decoded_invite_distinguishes_peer_and_group_mailbox_codes() {
        let keypair = AgentKeyPair::generate("DirectOwner", "agent");
        let peer_invite = PeerInvite::generate(
            &keypair,
            "12D3KooWDirectPeer",
            None,
            Some("/ip4/127.0.0.1/tcp/9090"),
            9090,
            None,
        )
        .unwrap();
        let group_invite = GroupMailboxInvite::generate(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_mailbox_direct",
            Some("Direct"),
            false,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:direct".to_string(),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_direct".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();

        match DecodedInvite::from_code(&peer_invite.to_code().unwrap()).unwrap() {
            DecodedInvite::Peer(_) => {}
            DecodedInvite::GroupMailbox(_) => panic!("expected peer invite"),
        }
        match DecodedInvite::from_code(&group_invite.to_code().unwrap()).unwrap() {
            DecodedInvite::GroupMailbox(_) => {}
            DecodedInvite::Peer(_) => panic!("expected group mailbox invite"),
        }
    }

    #[test]
    fn anonymous_group_mailbox_invite_rejects_embedded_issuer_did() {
        let keypair = AgentKeyPair::generate("AnonOwner", "agent");
        let result = GroupMailboxInvite::generate(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_anon",
            None,
            true,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:anon".to_string(),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_anon".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        assert!(result.is_err());
    }

    #[test]
    fn group_mailbox_invite_requires_valid_service_endpoint() {
        let keypair = AgentKeyPair::generate("MailboxOwner", "agent");
        let invite = GroupMailboxInvite::generate(
            &keypair.signing_key,
            Some(&keypair.did),
            "grp_missing_endpoint",
            Some("Missing Endpoint"),
            false,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:missing-endpoint".to_string(),
                endpoint: None,
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_missing_endpoint".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([10u8; 32]),
                bootstrap_token: None,
            },
            None,
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();

        assert!(invite.verify_with_expiry().unwrap());
    }

    #[test]
    fn anonymous_group_mailbox_invite_roundtrip_stays_minimal() {
        let keypair = AgentKeyPair::generate("AnonOwner", "agent");
        let content_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([33u8; 32]);
        let writer_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([34u8; 32]);
        let invite = GroupMailboxInvite::generate(
            &keypair.signing_key,
            None,
            "grp_anon_v2",
            Some("Ghost"),
            true,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:grp_anon_v2:epoch:4".to_string(),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_anon_v2".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([31u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([32u8; 32]),
                bootstrap_token: None,
            },
            Some(GroupContentCryptoAdvertisedState {
                version: 1,
                suite: crate::network::protocol::GroupContentCryptoSuite::EpochAegis256,
                epoch: 4,
                content_secret_b64: content_secret.clone(),
            }),
            Some(AnonymousGroupWriterCredentialAdvertisedState {
                version: 1,
                suite: AnonymousGroupWriterCredentialSuite::EpochHmacSha256,
                epoch: 4,
                writer_secret_b64: writer_secret.clone(),
            }),
            chrono::Utc::now().timestamp() as u64 + 3_600,
        )
        .unwrap();

        let code = invite.to_code().unwrap();
        let decoded = GroupMailboxInvite::from_code(&code).unwrap();
        let encoded_bytes = decode_invite_bytes(&code).unwrap();
        assert!(decoded.verify_with_expiry().unwrap());
        assert!(decoded.anonymous_group);
        assert!(
            !encoded_blob_contains(&encoded_bytes, "mailbox:grp_anon_v2:epoch:4"),
            "anonymous group invite token must not embed mailbox namespace"
        );
        assert!(
            !encoded_blob_contains(&encoded_bytes, &content_secret),
            "anonymous group invite token must not embed content crypto state"
        );
        assert!(
            !encoded_blob_contains(&encoded_bytes, &writer_secret),
            "anonymous group invite token must not embed anonymous writer state"
        );
    }

    #[test]
    fn anonymous_group_invite_rejects_content_state_without_writer_state() {
        let keypair = AgentKeyPair::generate("AnonOwner", "agent");
        let result = GroupMailboxInvite::generate(
            &keypair.signing_key,
            None,
            "grp_anon_invalid",
            Some("Ghost"),
            true,
            MailboxDescriptor {
                transport: crate::network::protocol::MailboxTransportKind::Tor,
                namespace: "mailbox:grp_anon_invalid".to_string(),
                endpoint: Some(
                    "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444"
                        .to_string(),
                ),
                poll_interval_ms: 5_000,
                max_payload_bytes: 256 * 1024,
            },
            MailboxCapability {
                capability_id: "cap_anon_invalid".to_string(),
                access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([41u8; 32]),
                auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([42u8; 32]),
                bootstrap_token: None,
            },
            Some(GroupContentCryptoAdvertisedState {
                version: 1,
                suite: crate::network::protocol::GroupContentCryptoSuite::EpochAegis256,
                epoch: 1,
                content_secret_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode([43u8; 32]),
            }),
            None,
            chrono::Utc::now().timestamp() as u64 + 3_600,
        );

        assert!(result.is_err());
    }
}

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::identity::derive_did_from_verifying_key;
use crate::crypto::signing;
use crate::network::protocol::{AgentRequest, MessageKind};

const CONTACT_MAILBOX_POST_PREFIX: &[u8] = b"QYPHA_CONTACT_MAILBOX_POST_V1:";
const CONTACT_MAILBOX_POLL_PREFIX: &[u8] = b"QYPHA_CONTACT_MAILBOX_POLL_V1:";
const CONTACT_MAILBOX_ACK_PREFIX: &[u8] = b"QYPHA_CONTACT_MAILBOX_ACK_V1:";
const CONTACT_MAILBOX_POW_PREFIX: &[u8] = b"QYPHA_CONTACT_MAILBOX_POW_V1:";
const DEFAULT_CONTACT_MAILBOX_POW_BITS: u8 = 12;
const MAX_CONTACT_MAILBOX_CLOCK_SKEW_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxPostRequest {
    pub version: u8,
    pub recipient_did: String,
    pub mailbox_namespace: String,
    pub sender_did: String,
    pub sender_verifying_key_hex: String,
    pub request: AgentRequest,
    pub created_at: u64,
    #[serde(default = "default_pow_bits")]
    pub pow_difficulty_bits: u8,
    #[serde(default)]
    pub pow_nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxPollRequest {
    pub version: u8,
    pub recipient_did: String,
    pub mailbox_namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub created_at: u64,
    pub verifying_key_hex: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxAckRequest {
    pub version: u8,
    pub recipient_did: String,
    pub mailbox_namespace: String,
    pub envelope_ids: Vec<String>,
    pub created_at: u64,
    pub verifying_key_hex: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxItem {
    pub envelope_id: String,
    pub sender_did: String,
    pub request: AgentRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxPollResult {
    pub items: Vec<ContactMailboxItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

fn default_pow_bits() -> u8 {
    DEFAULT_CONTACT_MAILBOX_POW_BITS
}

fn write_canonical_str(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
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

fn signing_data_for_request(request: &AgentRequest) -> Vec<u8> {
    let mt_bytes = serde_json::to_vec(&request.msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(mt_bytes.len() + request.payload.len() + 16);
    signed_data.extend_from_slice(&mt_bytes);
    signed_data.extend_from_slice(&request.payload);
    signed_data.extend_from_slice(&request.nonce.to_le_bytes());
    signed_data.extend_from_slice(&request.timestamp.to_le_bytes());
    signed_data
}

fn verify_contact_agent_request(
    request: &AgentRequest,
    sender_did: &str,
    sender_verifying_key_hex: &str,
) -> Result<()> {
    if !matches!(
        request.msg_type,
        MessageKind::ContactRequest | MessageKind::ContactAccept | MessageKind::ContactReject
    ) {
        anyhow::bail!(
            "Unsupported contact mailbox message kind {:?}",
            request.msg_type
        );
    }
    if request.sender_did != sender_did {
        anyhow::bail!("Contact mailbox sender DID mismatch");
    }
    let verifying_key_bytes = hex::decode(sender_verifying_key_hex)
        .context("Contact mailbox sender verifying key is not valid hex")?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Contact mailbox sender verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid contact mailbox sender verifying key")?;
    let expected_did = derive_did_from_verifying_key(&verifying_key);
    if expected_did != sender_did {
        anyhow::bail!("Contact mailbox sender DID does not match verifying key");
    }
    if !signing::verify_signature(
        &verifying_key,
        &signing_data_for_request(request),
        &request.signature,
    )? {
        anyhow::bail!("Contact mailbox outer request signature invalid");
    }
    Ok(())
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for byte in bytes {
        let zeros = byte.leading_zeros() as u8;
        count = count.saturating_add(zeros);
        if zeros != 8 {
            break;
        }
    }
    count
}

fn pow_digest(
    recipient_did: &str,
    sender_did: &str,
    request_message_id: &str,
    created_at: u64,
    nonce_hex: &str,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(CONTACT_MAILBOX_POW_PREFIX);
    write_canonical_str(&mut data, recipient_did);
    write_canonical_str(&mut data, sender_did);
    write_canonical_str(&mut data, request_message_id);
    data.extend_from_slice(&created_at.to_le_bytes());
    write_canonical_str(&mut data, nonce_hex);
    Sha256::digest(&data).to_vec()
}

fn verify_post_pow(post: &ContactMailboxPostRequest) -> Result<()> {
    if post.pow_difficulty_bits == 0 {
        return Ok(());
    }
    if post.pow_nonce_hex.is_empty() || !post.pow_nonce_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("Contact mailbox PoW nonce is invalid");
    }
    let digest = pow_digest(
        &post.recipient_did,
        &post.sender_did,
        &post.request.message_id,
        post.created_at,
        &post.pow_nonce_hex,
    );
    if leading_zero_bits(&digest) < post.pow_difficulty_bits {
        anyhow::bail!("Contact mailbox PoW verification failed");
    }
    Ok(())
}

fn signable_poll_bytes(
    prefix: &[u8],
    recipient_did: &str,
    mailbox_namespace: &str,
    cursor: Option<&str>,
    envelope_ids: &[String],
    created_at: u64,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(prefix);
    write_canonical_str(&mut data, recipient_did);
    write_canonical_str(&mut data, mailbox_namespace);
    write_canonical_opt_str(&mut data, cursor);
    data.extend_from_slice(&(envelope_ids.len() as u32).to_le_bytes());
    for envelope_id in envelope_ids {
        write_canonical_str(&mut data, envelope_id);
    }
    data.extend_from_slice(&created_at.to_le_bytes());
    data
}

fn verify_recipient_auth(
    recipient_did: &str,
    verifying_key_hex: &str,
    signature_b64: &str,
    signing_data: &[u8],
) -> Result<()> {
    let verifying_key_bytes = hex::decode(verifying_key_hex)
        .context("Contact mailbox recipient verifying key is not valid hex")?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Contact mailbox recipient verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .context("Invalid contact mailbox recipient verifying key")?;
    let expected_did = derive_did_from_verifying_key(&verifying_key);
    if expected_did != recipient_did {
        anyhow::bail!("Contact mailbox recipient DID does not match verifying key");
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .context("Contact mailbox signature is not valid base64")?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Contact mailbox signature is malformed"))?;
    verifying_key
        .verify_strict(signing_data, &signature)
        .map_err(|_| anyhow::anyhow!("Contact mailbox recipient signature invalid"))?;
    Ok(())
}

impl ContactMailboxPostRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("Unsupported contact mailbox post version {}", self.version);
        }
        if self.recipient_did.trim().is_empty() || self.sender_did.trim().is_empty() {
            anyhow::bail!("Contact mailbox DID fields must not be empty");
        }
        if self.mailbox_namespace.trim().is_empty() {
            anyhow::bail!("Contact mailbox namespace must not be empty");
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if self.created_at > now.saturating_add(MAX_CONTACT_MAILBOX_CLOCK_SKEW_SECS) {
            anyhow::bail!("Contact mailbox post timestamp is in the future");
        }
        verify_contact_agent_request(
            &self.request,
            &self.sender_did,
            &self.sender_verifying_key_hex,
        )?;
        verify_post_pow(self)?;
        Ok(())
    }
}

impl ContactMailboxPollRequest {
    pub fn sign(
        recipient_did: String,
        mailbox_namespace: String,
        cursor: Option<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let created_at = chrono::Utc::now().timestamp().max(0) as u64;
        let signing_data = signable_poll_bytes(
            CONTACT_MAILBOX_POLL_PREFIX,
            &recipient_did,
            &mailbox_namespace,
            cursor.as_deref(),
            &[],
            created_at,
        );
        let signature_b64 = URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_data).to_bytes());
        Self {
            version: 1,
            recipient_did,
            mailbox_namespace,
            cursor,
            created_at,
            verifying_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signature_b64,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("Unsupported contact mailbox poll version {}", self.version);
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if self.created_at > now.saturating_add(MAX_CONTACT_MAILBOX_CLOCK_SKEW_SECS) {
            anyhow::bail!("Contact mailbox poll timestamp is in the future");
        }
        let signing_data = signable_poll_bytes(
            CONTACT_MAILBOX_POLL_PREFIX,
            &self.recipient_did,
            &self.mailbox_namespace,
            self.cursor.as_deref(),
            &[],
            self.created_at,
        );
        verify_recipient_auth(
            &self.recipient_did,
            &self.verifying_key_hex,
            &self.signature_b64,
            &signing_data,
        )
    }
}

impl ContactMailboxAckRequest {
    pub fn sign(
        recipient_did: String,
        mailbox_namespace: String,
        envelope_ids: Vec<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let created_at = chrono::Utc::now().timestamp().max(0) as u64;
        let signing_data = signable_poll_bytes(
            CONTACT_MAILBOX_ACK_PREFIX,
            &recipient_did,
            &mailbox_namespace,
            None,
            &envelope_ids,
            created_at,
        );
        let signature_b64 = URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_data).to_bytes());
        Self {
            version: 1,
            recipient_did,
            mailbox_namespace,
            envelope_ids,
            created_at,
            verifying_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signature_b64,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("Unsupported contact mailbox ack version {}", self.version);
        }
        if self.envelope_ids.is_empty() {
            anyhow::bail!("Contact mailbox ack requires at least one envelope id");
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if self.created_at > now.saturating_add(MAX_CONTACT_MAILBOX_CLOCK_SKEW_SECS) {
            anyhow::bail!("Contact mailbox ack timestamp is in the future");
        }
        let signing_data = signable_poll_bytes(
            CONTACT_MAILBOX_ACK_PREFIX,
            &self.recipient_did,
            &self.mailbox_namespace,
            None,
            &self.envelope_ids,
            self.created_at,
        );
        verify_recipient_auth(
            &self.recipient_did,
            &self.verifying_key_hex,
            &self.signature_b64,
            &signing_data,
        )
    }
}

pub fn build_contact_mailbox_post_request(
    recipient_did: String,
    mailbox_namespace: String,
    sender_verifying_key_hex: String,
    request: AgentRequest,
) -> ContactMailboxPostRequest {
    let created_at = chrono::Utc::now().timestamp().max(0) as u64;
    let pow_difficulty_bits = DEFAULT_CONTACT_MAILBOX_POW_BITS;
    let mut pow_nonce_hex = String::new();
    if pow_difficulty_bits > 0 {
        let seed = rand::random::<u64>();
        for counter in 0u64.. {
            let nonce_hex = format!("{:016x}", seed.wrapping_add(counter));
            let digest = pow_digest(
                &recipient_did,
                &request.sender_did,
                &request.message_id,
                created_at,
                &nonce_hex,
            );
            if leading_zero_bits(&digest) >= pow_difficulty_bits {
                pow_nonce_hex = nonce_hex;
                break;
            }
        }
    }

    ContactMailboxPostRequest {
        version: 1,
        recipient_did,
        mailbox_namespace,
        sender_did: request.sender_did.clone(),
        sender_verifying_key_hex,
        request,
        created_at,
        pow_difficulty_bits,
        pow_nonce_hex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_request::build_contact_request_agent_request;
    use crate::network::did_profile::DidContactService;
    use crate::network::did_profile::DidProfile;
    use crate::network::direct_invite_token::DirectInviteTransportPolicy;
    use serde_json::json;

    fn test_config_for(did: &str, name: &str) -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": name,
                "role": "agent",
                "did": did
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false,
                "transport_mode": "tor"
            },
            "security": {
                "require_mtls": false,
                "max_message_size_bytes": 65536,
                "nonce_window_size": 64,
                "shadow_mode_enabled": false,
                "message_ttl_ms": 60000
            }
        }))
        .unwrap()
    }

    fn tor_profile_for(keypair: &AgentKeyPair) -> DidProfile {
        DidProfile::generate(
            keypair,
            vec![DidContactService::TorMailbox {
                onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                    .to_string(),
                mailbox_namespace: "contact:test".to_string(),
                port: 9444,
            }],
            None,
        )
    }

    #[test]
    fn contact_mailbox_post_request_validates_signed_contact_request() {
        let sender = AgentKeyPair::generate("sender", "agent");
        let recipient = AgentKeyPair::generate("recipient", "agent");
        let sender_config = test_config_for(&sender.did, "sender");
        let request = build_contact_request_agent_request(
            &sender_config,
            &sender.signing_key,
            &sender,
            tor_profile_for(&sender),
            &tor_profile_for(&recipient),
            Some("hello".to_string()),
            None,
            DirectInviteTransportPolicy::TorOnly,
        )
        .unwrap();

        let post = build_contact_mailbox_post_request(
            recipient.did.clone(),
            "contact:test".to_string(),
            hex::encode(sender.verifying_key.as_bytes()),
            request,
        );

        post.validate().unwrap();
    }

    #[test]
    fn signed_poll_request_verifies() {
        let recipient = AgentKeyPair::generate("recipient", "agent");
        let request = ContactMailboxPollRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            Some("10".to_string()),
            &recipient.signing_key,
        );
        request.validate().unwrap();
    }
}

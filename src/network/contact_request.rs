use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::crypto::encryption::{
    hybrid_decrypt_message, hybrid_encrypt_message, EncryptedEnvelope,
};
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::signing;
use crate::network::did_profile::DidProfile;
use crate::network::direct_invite_token::DirectInviteTransportPolicy;
use crate::network::protocol::{AgentRequest, MessageKind};

const CONTACT_REQUEST_PREFIX: &[u8] = b"QYPHA_CONTACT_REQUEST_V1:";
const CONTACT_ACCEPT_PREFIX: &[u8] = b"QYPHA_CONTACT_ACCEPT_V1:";
const CONTACT_REJECT_PREFIX: &[u8] = b"QYPHA_CONTACT_REJECT_V1:";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedContactMessage {
    pub version: u8,
    pub recipient_did: String,
    pub sender_did_hint: String,
    pub envelope: EncryptedEnvelope,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactRequestPayload {
    pub version: u8,
    pub request_id: String,
    pub sender_profile: DidProfile,
    #[serde(default)]
    pub intro_message: Option<String>,
    #[serde(default)]
    pub invite_token: Option<String>,
    pub transport_policy: DirectInviteTransportPolicy,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactAcceptPayload {
    pub version: u8,
    pub request_id: String,
    pub responder_profile: DidProfile,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactRejectPayload {
    pub version: u8,
    pub request_id: String,
    pub responder_profile: DidProfile,
    #[serde(default)]
    pub reason: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedContactRequestPayload<'a> {
    version: u8,
    request_id: &'a str,
    sender_profile: &'a DidProfile,
    intro_message: Option<&'a str>,
    invite_token: Option<&'a str>,
    transport_policy: DirectInviteTransportPolicy,
    created_at: u64,
}

#[derive(Serialize)]
struct UnsignedContactAcceptPayload<'a> {
    version: u8,
    request_id: &'a str,
    responder_profile: &'a DidProfile,
    created_at: u64,
}

#[derive(Serialize)]
struct UnsignedContactRejectPayload<'a> {
    version: u8,
    request_id: &'a str,
    responder_profile: &'a DidProfile,
    reason: Option<&'a str>,
    created_at: u64,
}

impl ContactRequestPayload {
    fn signing_data(&self) -> Result<Vec<u8>> {
        let unsigned = UnsignedContactRequestPayload {
            version: self.version,
            request_id: &self.request_id,
            sender_profile: &self.sender_profile,
            intro_message: self.intro_message.as_deref(),
            invite_token: self.invite_token.as_deref(),
            transport_policy: self.transport_policy,
            created_at: self.created_at,
        };
        let mut data = CONTACT_REQUEST_PREFIX.to_vec();
        data.extend(
            bincode::serialize(&unsigned)
                .context("Failed to serialize unsigned contact request")?,
        );
        Ok(data)
    }

    pub fn generate(
        sign_key: &ed25519_dalek::SigningKey,
        sender_profile: DidProfile,
        intro_message: Option<String>,
        invite_token: Option<String>,
        transport_policy: DirectInviteTransportPolicy,
    ) -> Result<Self> {
        let mut payload = Self {
            version: 1,
            request_id: uuid::Uuid::new_v4().to_string(),
            sender_profile,
            intro_message,
            invite_token,
            transport_policy,
            created_at: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
        };
        let signature = sign_key.sign(&payload.signing_data()?);
        payload.signature = signature.to_bytes().to_vec();
        Ok(payload)
    }

    pub fn verify(&self) -> Result<bool> {
        if !self.sender_profile.verify()? {
            return Ok(false);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.sender_profile.verifying_key)
            .context("Invalid sender DID profile verifying key")?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid contact request signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data()?, &signature)
            .is_ok())
    }
}

impl ContactAcceptPayload {
    fn signing_data(&self) -> Result<Vec<u8>> {
        let unsigned = UnsignedContactAcceptPayload {
            version: self.version,
            request_id: &self.request_id,
            responder_profile: &self.responder_profile,
            created_at: self.created_at,
        };
        let mut data = CONTACT_ACCEPT_PREFIX.to_vec();
        data.extend(
            bincode::serialize(&unsigned).context("Failed to serialize unsigned contact accept")?,
        );
        Ok(data)
    }

    pub fn generate(
        sign_key: &ed25519_dalek::SigningKey,
        responder_profile: DidProfile,
        request_id: String,
    ) -> Result<Self> {
        let mut payload = Self {
            version: 1,
            request_id,
            responder_profile,
            created_at: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
        };
        let signature = sign_key.sign(&payload.signing_data()?);
        payload.signature = signature.to_bytes().to_vec();
        Ok(payload)
    }

    pub fn verify(&self) -> Result<bool> {
        if !self.responder_profile.verify()? {
            return Ok(false);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.responder_profile.verifying_key)
            .context("Invalid responder DID profile verifying key")?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid contact accept signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data()?, &signature)
            .is_ok())
    }
}

impl ContactRejectPayload {
    fn signing_data(&self) -> Result<Vec<u8>> {
        let unsigned = UnsignedContactRejectPayload {
            version: self.version,
            request_id: &self.request_id,
            responder_profile: &self.responder_profile,
            reason: self.reason.as_deref(),
            created_at: self.created_at,
        };
        let mut data = CONTACT_REJECT_PREFIX.to_vec();
        data.extend(
            bincode::serialize(&unsigned).context("Failed to serialize unsigned contact reject")?,
        );
        Ok(data)
    }

    pub fn generate(
        sign_key: &ed25519_dalek::SigningKey,
        responder_profile: DidProfile,
        request_id: String,
        reason: Option<String>,
    ) -> Result<Self> {
        let mut payload = Self {
            version: 1,
            request_id,
            responder_profile,
            reason,
            created_at: chrono::Utc::now().timestamp() as u64,
            signature: Vec::new(),
        };
        let signature = sign_key.sign(&payload.signing_data()?);
        payload.signature = signature.to_bytes().to_vec();
        Ok(payload)
    }

    pub fn verify(&self) -> Result<bool> {
        if !self.responder_profile.verify()? {
            return Ok(false);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.responder_profile.verifying_key)
            .context("Invalid responder DID profile verifying key")?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid contact reject signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data()?, &signature)
            .is_ok())
    }
}

fn profile_kyber_public(profile: &DidProfile) -> Result<Vec<u8>> {
    if profile.kyber_public_key_hex.is_empty() {
        anyhow::bail!("Recipient DID profile is missing the required Kyber public key");
    }
    let kyber_public =
        hex::decode(&profile.kyber_public_key_hex).context("Invalid Kyber public key hex")?;
    if kyber_public.len() != pqc_kyber::KYBER_PUBLICKEYBYTES {
        anyhow::bail!(
            "Recipient DID profile Kyber public key has invalid length {} (expected {})",
            kyber_public.len(),
            pqc_kyber::KYBER_PUBLICKEYBYTES
        );
    }
    Ok(kyber_public)
}

fn build_signed_agent_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    expected_sender_did: &str,
    msg_type: MessageKind,
    payload: Vec<u8>,
) -> Result<AgentRequest> {
    if config.agent.did != expected_sender_did {
        anyhow::bail!(
            "Config DID '{}' does not match sender DID '{}'",
            config.agent.did,
            expected_sender_did
        );
    }

    let nonce = crate::crypto::next_request_nonce();
    let mt_bytes = serde_json::to_vec(&msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(mt_bytes.len() + payload.len() + 16);
    signed_data.extend_from_slice(&mt_bytes);
    signed_data.extend_from_slice(&payload);
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    signed_data.extend_from_slice(&nonce.to_le_bytes());
    let signature = signing::sign_data(sign_key, &signed_data);

    Ok(AgentRequest {
        message_id: uuid::Uuid::new_v4().to_string(),
        sender_did: config.agent.did.clone(),
        sender_name: config.agent.name.clone(),
        sender_role: config.agent.role.clone(),
        msg_type,
        payload,
        signature,
        nonce,
        timestamp: nonce,
        ttl_ms: config.security.message_ttl_ms,
    })
}

fn verify_outer_agent_request(
    request: &AgentRequest,
    expected_msg_type: MessageKind,
    profile: &DidProfile,
) -> Result<bool> {
    if request.msg_type != expected_msg_type {
        anyhow::bail!(
            "Unexpected message kind: expected {:?}, got {:?}",
            expected_msg_type,
            request.msg_type
        );
    }
    if request.sender_did != profile.did {
        anyhow::bail!(
            "Outer sender DID '{}' does not match profile DID '{}'",
            request.sender_did,
            profile.did
        );
    }
    let verifying_key = VerifyingKey::from_bytes(&profile.verifying_key)
        .context("Invalid outer request verifying key")?;
    let mt_bytes = serde_json::to_vec(&request.msg_type).unwrap_or_default();
    let mut signed_data = Vec::with_capacity(mt_bytes.len() + request.payload.len() + 16);
    signed_data.extend_from_slice(&mt_bytes);
    signed_data.extend_from_slice(&request.payload);
    signed_data.extend_from_slice(&request.nonce.to_le_bytes());
    signed_data.extend_from_slice(&request.timestamp.to_le_bytes());
    signing::verify_signature(&verifying_key, &signed_data, &request.signature)
}

fn encrypt_for_profile(
    recipient_profile: &DidProfile,
    plaintext: &[u8],
) -> Result<SealedContactMessage> {
    let recipient_kyber = profile_kyber_public(recipient_profile)?;
    let envelope = hybrid_encrypt_message(
        &recipient_profile.x25519_public_key,
        Some(recipient_kyber.as_slice()),
        plaintext,
    )?;
    Ok(SealedContactMessage {
        version: 1,
        recipient_did: recipient_profile.did.clone(),
        sender_did_hint: String::new(),
        envelope,
    })
}

fn decrypt_contact_message(
    recipient_keypair: &AgentKeyPair,
    request_payload: &[u8],
) -> Result<SealedContactMessage> {
    let sealed: SealedContactMessage =
        bincode::deserialize(request_payload).context("Invalid sealed contact message encoding")?;
    if sealed.recipient_did != recipient_keypair.did {
        anyhow::bail!(
            "Sealed contact message was addressed to '{}' not '{}'",
            sealed.recipient_did,
            recipient_keypair.did
        );
    }
    Ok(sealed)
}

pub fn build_contact_request_agent_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    sender_keypair: &AgentKeyPair,
    sender_profile: DidProfile,
    recipient_profile: &DidProfile,
    intro_message: Option<String>,
    invite_token: Option<String>,
    transport_policy: DirectInviteTransportPolicy,
) -> Result<AgentRequest> {
    let payload = ContactRequestPayload::generate(
        sign_key,
        sender_profile,
        intro_message,
        invite_token,
        transport_policy,
    )?;
    let plaintext =
        bincode::serialize(&payload).context("Failed to serialize contact request payload")?;
    let mut sealed = encrypt_for_profile(recipient_profile, &plaintext)?;
    sealed.sender_did_hint = sender_keypair.did.clone();
    let request_payload =
        bincode::serialize(&sealed).context("Failed to serialize sealed contact request")?;
    build_signed_agent_request(
        config,
        sign_key,
        &sender_keypair.did,
        MessageKind::ContactRequest,
        request_payload,
    )
}

pub fn open_contact_request_agent_request(
    recipient_keypair: &AgentKeyPair,
    request: &AgentRequest,
) -> Result<ContactRequestPayload> {
    let sealed = decrypt_contact_message(recipient_keypair, &request.payload)?;
    let plaintext = hybrid_decrypt_message(
        &recipient_keypair.x25519_secret_key_bytes(),
        Some(recipient_keypair.kyber_secret.as_slice()),
        &sealed.envelope,
    )?;
    let payload: ContactRequestPayload =
        bincode::deserialize(&plaintext).context("Invalid contact request payload")?;
    if sealed.sender_did_hint != payload.sender_profile.did {
        anyhow::bail!("Sender DID hint mismatch in sealed contact request");
    }
    if !payload.verify()? {
        anyhow::bail!("Contact request payload signature invalid");
    }
    if !verify_outer_agent_request(
        request,
        MessageKind::ContactRequest,
        &payload.sender_profile,
    )? {
        anyhow::bail!("Outer contact request signature invalid");
    }
    Ok(payload)
}

pub fn build_contact_accept_agent_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    responder_keypair: &AgentKeyPair,
    responder_profile: DidProfile,
    requester_profile: &DidProfile,
    request_id: String,
) -> Result<AgentRequest> {
    let payload = ContactAcceptPayload::generate(sign_key, responder_profile, request_id)?;
    let plaintext =
        bincode::serialize(&payload).context("Failed to serialize contact accept payload")?;
    let mut sealed = encrypt_for_profile(requester_profile, &plaintext)?;
    sealed.sender_did_hint = responder_keypair.did.clone();
    let request_payload =
        bincode::serialize(&sealed).context("Failed to serialize sealed contact accept")?;
    build_signed_agent_request(
        config,
        sign_key,
        &responder_keypair.did,
        MessageKind::ContactAccept,
        request_payload,
    )
}

pub fn open_contact_accept_agent_request(
    recipient_keypair: &AgentKeyPair,
    request: &AgentRequest,
) -> Result<ContactAcceptPayload> {
    let sealed = decrypt_contact_message(recipient_keypair, &request.payload)?;
    let plaintext = hybrid_decrypt_message(
        &recipient_keypair.x25519_secret_key_bytes(),
        Some(recipient_keypair.kyber_secret.as_slice()),
        &sealed.envelope,
    )?;
    let payload: ContactAcceptPayload =
        bincode::deserialize(&plaintext).context("Invalid contact accept payload")?;
    if sealed.sender_did_hint != payload.responder_profile.did {
        anyhow::bail!("Sender DID hint mismatch in sealed contact accept");
    }
    if !payload.verify()? {
        anyhow::bail!("Contact accept payload signature invalid");
    }
    if !verify_outer_agent_request(
        request,
        MessageKind::ContactAccept,
        &payload.responder_profile,
    )? {
        anyhow::bail!("Outer contact accept signature invalid");
    }
    Ok(payload)
}

pub fn build_contact_reject_agent_request(
    config: &AppConfig,
    sign_key: &ed25519_dalek::SigningKey,
    responder_keypair: &AgentKeyPair,
    responder_profile: DidProfile,
    requester_profile: &DidProfile,
    request_id: String,
    reason: Option<String>,
) -> Result<AgentRequest> {
    let payload = ContactRejectPayload::generate(sign_key, responder_profile, request_id, reason)?;
    let plaintext =
        bincode::serialize(&payload).context("Failed to serialize contact reject payload")?;
    let mut sealed = encrypt_for_profile(requester_profile, &plaintext)?;
    sealed.sender_did_hint = responder_keypair.did.clone();
    let request_payload =
        bincode::serialize(&sealed).context("Failed to serialize sealed contact reject")?;
    build_signed_agent_request(
        config,
        sign_key,
        &responder_keypair.did,
        MessageKind::ContactReject,
        request_payload,
    )
}

pub fn open_contact_reject_agent_request(
    recipient_keypair: &AgentKeyPair,
    request: &AgentRequest,
) -> Result<ContactRejectPayload> {
    let sealed = decrypt_contact_message(recipient_keypair, &request.payload)?;
    let plaintext = hybrid_decrypt_message(
        &recipient_keypair.x25519_secret_key_bytes(),
        Some(recipient_keypair.kyber_secret.as_slice()),
        &sealed.envelope,
    )?;
    let payload: ContactRejectPayload =
        bincode::deserialize(&plaintext).context("Invalid contact reject payload")?;
    if sealed.sender_did_hint != payload.responder_profile.did {
        anyhow::bail!("Sender DID hint mismatch in sealed contact reject");
    }
    if !payload.verify()? {
        anyhow::bail!("Contact reject payload signature invalid");
    }
    if !verify_outer_agent_request(
        request,
        MessageKind::ContactReject,
        &payload.responder_profile,
    )? {
        anyhow::bail!("Outer contact reject signature invalid");
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::did_profile::DidContactService;
    use serde_json::json;

    fn test_config(name: &str, did: &str) -> AppConfig {
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
                "enable_kademlia": false
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

    fn iroh_profile_for(keypair: &AgentKeyPair, topic: &str) -> DidProfile {
        DidProfile::generate(
            keypair,
            vec![DidContactService::IrohRelay {
                relay_urls: vec!["https://relay.example.com".to_string()],
                mailbox_topic: topic.to_string(),
                endpoint_addr_json: None,
            }],
            None,
        )
    }

    #[test]
    fn contact_request_roundtrip_encrypts_and_verifies() {
        let sender = AgentKeyPair::generate("Alice", "agent");
        let recipient = AgentKeyPair::generate("Bob", "agent");
        let sender_profile = iroh_profile_for(&sender, "alice-topic");
        let recipient_profile = iroh_profile_for(&recipient, "bob-topic");
        let config = test_config("Alice", &sender.did);

        let request = build_contact_request_agent_request(
            &config,
            &sender.signing_key,
            &sender,
            sender_profile.clone(),
            &recipient_profile,
            Some("hello from did".to_string()),
            Some("invite-token".to_string()),
            DirectInviteTransportPolicy::IrohOnly,
        )
        .unwrap();

        let opened = open_contact_request_agent_request(&recipient, &request).unwrap();
        assert_eq!(opened.sender_profile.did, sender.did);
        assert_eq!(opened.intro_message.as_deref(), Some("hello from did"));
        assert_eq!(opened.invite_token.as_deref(), Some("invite-token"));
        assert_eq!(
            opened.transport_policy,
            DirectInviteTransportPolicy::IrohOnly
        );
    }

    #[test]
    fn contact_accept_roundtrip_encrypts_and_verifies() {
        let requester = AgentKeyPair::generate("Alice", "agent");
        let responder = AgentKeyPair::generate("Bob", "agent");
        let requester_profile = iroh_profile_for(&requester, "alice-topic");
        let responder_profile = iroh_profile_for(&responder, "bob-topic");
        let config = test_config("Bob", &responder.did);

        let request = build_contact_accept_agent_request(
            &config,
            &responder.signing_key,
            &responder,
            responder_profile.clone(),
            &requester_profile,
            "req-123".to_string(),
        )
        .unwrap();

        let opened = open_contact_accept_agent_request(&requester, &request).unwrap();
        assert_eq!(opened.request_id, "req-123");
        assert_eq!(opened.responder_profile.did, responder.did);
    }

    #[test]
    fn contact_reject_roundtrip_encrypts_and_verifies() {
        let requester = AgentKeyPair::generate("Alice", "agent");
        let responder = AgentKeyPair::generate("Bob", "agent");
        let requester_profile = iroh_profile_for(&requester, "alice-topic");
        let responder_profile = iroh_profile_for(&responder, "bob-topic");
        let config = test_config("Bob", &responder.did);

        let request = build_contact_reject_agent_request(
            &config,
            &responder.signing_key,
            &responder,
            responder_profile.clone(),
            &requester_profile,
            "req-456".to_string(),
            Some("busy".to_string()),
        )
        .unwrap();

        let opened = open_contact_reject_agent_request(&requester, &request).unwrap();
        assert_eq!(opened.request_id, "req-456");
        assert_eq!(opened.reason.as_deref(), Some("busy"));
        assert_eq!(opened.responder_profile.did, responder.did);
    }

    #[test]
    fn tampered_contact_request_signature_is_rejected() {
        let sender = AgentKeyPair::generate("Alice", "agent");
        let recipient = AgentKeyPair::generate("Bob", "agent");
        let sender_profile = iroh_profile_for(&sender, "alice-topic");
        let recipient_profile = iroh_profile_for(&recipient, "bob-topic");
        let config = test_config("Alice", &sender.did);

        let mut request = build_contact_request_agent_request(
            &config,
            &sender.signing_key,
            &sender,
            sender_profile,
            &recipient_profile,
            Some("hello from did".to_string()),
            None,
            DirectInviteTransportPolicy::Any,
        )
        .unwrap();
        request.signature[0] ^= 0xAA;

        let result = open_contact_request_agent_request(&recipient, &request);
        assert!(result.is_err());
    }
}

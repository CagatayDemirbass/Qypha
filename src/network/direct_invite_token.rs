use crate::crypto::identity::{derive_did_from_verifying_key, AgentKeyPair};
use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const DIRECT_INVITE_TOKEN_PREFIX: &[u8] = b"QYPHA_DIRECT_INVITE_TOKEN_V1:";
const FUTURE_SKEW_TOLERANCE_SECS: u64 = 300;
const DEFAULT_DIRECT_INVITE_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectInviteTransportPolicy {
    Any,
    IrohOnly,
    TorOnly,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DirectInviteToken {
    pub version: u8,
    pub issuer_did: String,
    pub verifying_key: [u8; 32],
    pub transport_policy: DirectInviteTransportPolicy,
    pub created_at: u64,
    pub expires_at: u64,
    pub invite_id: [u8; 16],
    pub nonce: [u8; 16],
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl DirectInviteToken {
    fn write_canonical_str(buf: &mut Vec<u8>, value: &str) {
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
    }

    fn write_canonical_bytes(buf: &mut Vec<u8>, value: &[u8]) {
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value);
    }

    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(DIRECT_INVITE_TOKEN_PREFIX);
        data.push(self.version);
        Self::write_canonical_str(&mut data, &self.issuer_did);
        Self::write_canonical_bytes(&mut data, &self.verifying_key);
        data.push(match self.transport_policy {
            DirectInviteTransportPolicy::Any => 0x00,
            DirectInviteTransportPolicy::IrohOnly => 0x01,
            DirectInviteTransportPolicy::TorOnly => 0x02,
        });
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        Self::write_canonical_bytes(&mut data, &self.invite_id);
        Self::write_canonical_bytes(&mut data, &self.nonce);
        data
    }

    pub fn generate(
        keypair: &AgentKeyPair,
        transport_policy: DirectInviteTransportPolicy,
        ttl_secs: Option<u64>,
    ) -> Result<Self> {
        let created_at = chrono::Utc::now().timestamp() as u64;
        let expires_at =
            created_at.saturating_add(ttl_secs.unwrap_or(DEFAULT_DIRECT_INVITE_TOKEN_TTL_SECS));

        let mut token = Self {
            version: 1,
            issuer_did: keypair.did.clone(),
            verifying_key: keypair.verifying_key.to_bytes(),
            transport_policy,
            created_at,
            expires_at,
            invite_id: rand::random::<[u8; 16]>(),
            nonce: rand::random::<[u8; 16]>(),
            signature: Vec::new(),
        };

        let signature = keypair.signing_key.sign(&token.signing_data());
        token.signature = signature.to_bytes().to_vec();
        Ok(token)
    }

    pub fn to_code(&self) -> Result<String> {
        let encoded =
            bincode::serialize(self).context("Failed to serialize direct invite token")?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
    }

    pub fn from_code(code: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(code.trim())
            .context("Invalid direct invite token base64")?;
        bincode::deserialize(&bytes).context("Invalid direct invite token encoding")
    }

    pub fn verify(&self) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.verifying_key)
            .context("Invalid Ed25519 verifying key")?;
        let expected_did = derive_did_from_verifying_key(&verifying_key);
        if self.issuer_did != expected_did {
            return Err(anyhow::anyhow!(
                "Direct invite token DID/key mismatch: claimed DID '{}' does not match verifying key fingerprint '{}'",
                self.issuer_did,
                expected_did
            ));
        }
        if self.invite_id == [0u8; 16] {
            return Err(anyhow::anyhow!("Direct invite token missing invite_id"));
        }
        if self.nonce == [0u8; 16] {
            return Err(anyhow::anyhow!("Direct invite token missing nonce"));
        }

        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data(), &sig)
            .is_ok())
    }

    pub fn verify_with_expiry(&self) -> Result<bool> {
        if !self.verify()? {
            return Ok(false);
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if self.created_at > now + FUTURE_SKEW_TOLERANCE_SECS {
            return Err(anyhow::anyhow!(
                "Direct invite token has future timestamp (clock skew {} seconds). Synchronize system clocks.",
                self.created_at - now
            ));
        }
        if self.expires_at <= self.created_at {
            return Err(anyhow::anyhow!(
                "Direct invite token expiry must be after creation time"
            ));
        }
        if now > self.expires_at {
            return Err(anyhow::anyhow!(
                "Direct invite token EXPIRED. Generate a fresh invite."
            ));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_invite_token_roundtrip_and_signature_verifies() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");
        let token = DirectInviteToken::generate(
            &keypair,
            DirectInviteTransportPolicy::IrohOnly,
            Some(3600),
        )
        .unwrap();

        let code = token.to_code().unwrap();
        let decoded = DirectInviteToken::from_code(&code).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.issuer_did, keypair.did);
        assert_eq!(
            decoded.transport_policy,
            DirectInviteTransportPolicy::IrohOnly
        );
        assert_eq!(decoded.verifying_key, keypair.verifying_key.to_bytes());
        assert!(decoded.verify().unwrap());
        assert!(decoded.verify_with_expiry().unwrap());
        let json = serde_json::to_string(&decoded).unwrap();
        assert!(!json.contains("onion_address"));
        assert!(!json.contains("tcp_address"));
        assert!(!json.contains("iroh_endpoint_addr"));
    }

    #[test]
    fn direct_invite_token_signature_rejects_tamper() {
        let keypair = AgentKeyPair::generate("TestAgent", "finance");
        let mut token =
            DirectInviteToken::generate(&keypair, DirectInviteTransportPolicy::Any, None).unwrap();
        token.transport_policy = DirectInviteTransportPolicy::TorOnly;
        assert!(!token.verify().unwrap());
    }

    #[test]
    fn direct_invite_token_rejects_did_key_mismatch() {
        let keypair = AgentKeyPair::generate("Alice", "executive");
        let mut token =
            DirectInviteToken::generate(&keypair, DirectInviteTransportPolicy::Any, None).unwrap();
        token.issuer_did =
            "did:nxf:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        token.signature = keypair
            .signing_key
            .sign(&token.signing_data())
            .to_bytes()
            .to_vec();
        assert!(token.verify().is_err());
    }

    #[test]
    fn direct_invite_token_expiry_is_enforced() {
        let keypair = AgentKeyPair::generate("Expired", "ops");
        let mut token =
            DirectInviteToken::generate(&keypair, DirectInviteTransportPolicy::Any, Some(60))
                .unwrap();
        token.created_at = chrono::Utc::now().timestamp() as u64 - 7200;
        token.expires_at = token.created_at + 60;
        token.signature = keypair
            .signing_key
            .sign(&token.signing_data())
            .to_bytes()
            .to_vec();

        let result = token.verify_with_expiry();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EXPIRED"));
    }

    #[test]
    fn direct_invite_tokens_are_unique_even_for_same_identity() {
        let keypair = AgentKeyPair::generate("UniqueAgent", "finance");
        let token1 =
            DirectInviteToken::generate(&keypair, DirectInviteTransportPolicy::Any, None).unwrap();
        let token2 =
            DirectInviteToken::generate(&keypair, DirectInviteTransportPolicy::Any, None).unwrap();

        assert_ne!(token1.invite_id, token2.invite_id);
        assert_ne!(token1.nonce, token2.nonce);
        assert_ne!(token1.to_code().unwrap(), token2.to_code().unwrap());
    }
}

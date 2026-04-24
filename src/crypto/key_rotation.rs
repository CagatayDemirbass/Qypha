use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Key rotation announcement — signed by both old and new keys.
///
/// Process:
///   1. Agent generates new Ed25519 + X25519 keypair
///   2. Signs rotation announcement with OLD key (proves ownership)
///   3. Signs again with NEW key (proves possession of new key)
///   4. Broadcasts to all peers
///   5. Peers verify old signature, adopt new public key
///   6. Old key is archived for historical signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationAnnouncement {
    pub agent_did: String,
    pub old_verifying_key_hex: String,
    pub new_verifying_key_hex: String,
    pub old_x25519_public_hex: String,
    pub new_x25519_public_hex: String,
    /// Old Kyber-1024 public key (hex) — None if pre-PQC agent
    #[serde(default)]
    pub old_kyber_public_hex: Option<String>,
    /// New Kyber-1024 public key (hex) — None if pre-PQC agent
    #[serde(default)]
    pub new_kyber_public_hex: Option<String>,
    pub timestamp: u64,
    /// Signature by OLD key over (did || new_verifying_key || new_x25519 || timestamp)
    pub old_key_signature: Vec<u8>,
    /// Signature by NEW key over (did || old_key_signature_hash)
    pub new_key_signature: Vec<u8>,
}

impl KeyRotationAnnouncement {
    /// Create a signed rotation announcement
    pub fn create(
        agent_did: &str,
        old_signing_key: &SigningKey,
        new_signing_key: &SigningKey,
        old_x25519_public: &[u8; 32],
        new_x25519_public: &[u8; 32],
    ) -> Self {
        Self::create_with_kyber(
            agent_did,
            old_signing_key,
            new_signing_key,
            old_x25519_public,
            new_x25519_public,
            None,
            None,
        )
    }

    /// Create a signed rotation announcement with optional Kyber-1024 keys
    pub fn create_with_kyber(
        agent_did: &str,
        old_signing_key: &SigningKey,
        new_signing_key: &SigningKey,
        old_x25519_public: &[u8; 32],
        new_x25519_public: &[u8; 32],
        old_kyber_public: Option<&[u8]>,
        new_kyber_public: Option<&[u8]>,
    ) -> Self {
        let old_vk = old_signing_key.verifying_key();
        let new_vk = new_signing_key.verifying_key();
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        let old_kyber_hex = old_kyber_public.map(hex::encode);
        let new_kyber_hex = new_kyber_public.map(hex::encode);

        // Data signed by old key
        let old_sign_data = Self::build_old_sign_data(
            agent_did,
            &hex::encode(new_vk.as_bytes()),
            &hex::encode(new_x25519_public),
            new_kyber_hex.as_deref(),
            timestamp,
        );
        let old_sig: Signature = old_signing_key.sign(&old_sign_data);

        // Data signed by new key (includes hash of old signature for binding)
        let old_sig_hash = Sha256::digest(&old_sig.to_bytes());
        let new_sign_data = Self::build_new_sign_data(agent_did, &old_sig_hash);
        let new_sig: Signature = new_signing_key.sign(&new_sign_data);

        Self {
            agent_did: agent_did.to_string(),
            old_verifying_key_hex: hex::encode(old_vk.as_bytes()),
            new_verifying_key_hex: hex::encode(new_vk.as_bytes()),
            old_x25519_public_hex: hex::encode(old_x25519_public),
            new_x25519_public_hex: hex::encode(new_x25519_public),
            old_kyber_public_hex: old_kyber_hex,
            new_kyber_public_hex: new_kyber_hex,
            timestamp,
            old_key_signature: old_sig.to_bytes().to_vec(),
            new_key_signature: new_sig.to_bytes().to_vec(),
        }
    }

    /// Verify the rotation announcement.
    ///
    /// Checks:
    /// 1. Old key signature is valid (proves current owner authorized rotation)
    /// 2. New key signature is valid (proves possession of new key)
    pub fn verify(&self) -> Result<bool> {
        // Parse old verifying key
        let old_vk_bytes: [u8; 32] = hex::decode(&self.old_verifying_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid old verifying key length"))?;
        let old_vk = VerifyingKey::from_bytes(&old_vk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid old verifying key: {}", e))?;

        // Parse new verifying key
        let new_vk_bytes: [u8; 32] = hex::decode(&self.new_verifying_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid new verifying key length"))?;
        let new_vk = VerifyingKey::from_bytes(&new_vk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid new verifying key: {}", e))?;

        // Verify old key signature
        let old_sign_data = Self::build_old_sign_data(
            &self.agent_did,
            &self.new_verifying_key_hex,
            &self.new_x25519_public_hex,
            self.new_kyber_public_hex.as_deref(),
            self.timestamp,
        );
        let old_sig_bytes: [u8; 64] = self
            .old_key_signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid old signature length"))?;
        let old_sig = Signature::from_bytes(&old_sig_bytes);
        if old_vk.verify(&old_sign_data, &old_sig).is_err() {
            return Ok(false);
        }

        // Verify new key signature
        let old_sig_hash = Sha256::digest(&old_sig.to_bytes());
        let new_sign_data = Self::build_new_sign_data(&self.agent_did, &old_sig_hash);
        let new_sig_bytes: [u8; 64] = self
            .new_key_signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid new signature length"))?;
        let new_sig = Signature::from_bytes(&new_sig_bytes);
        if new_vk.verify(&new_sign_data, &new_sig).is_err() {
            return Ok(false);
        }

        Ok(true)
    }

    fn build_old_sign_data(
        did: &str,
        new_vk_hex: &str,
        new_x25519_hex: &str,
        new_kyber_hex: Option<&str>,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"Qypha-KeyRotation-v1:");
        data.extend_from_slice(did.as_bytes());
        data.extend_from_slice(b":");
        data.extend_from_slice(new_vk_hex.as_bytes());
        data.extend_from_slice(b":");
        data.extend_from_slice(new_x25519_hex.as_bytes());
        // Include Kyber key in signed data when present
        if let Some(kyber_hex) = new_kyber_hex {
            data.extend_from_slice(b":");
            data.extend_from_slice(kyber_hex.as_bytes());
        }
        data.extend_from_slice(b":");
        data.extend_from_slice(&timestamp.to_le_bytes());
        data
    }

    fn build_new_sign_data(did: &str, old_sig_hash: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"Qypha-KeyRotation-NewKey-v1:");
        data.extend_from_slice(did.as_bytes());
        data.extend_from_slice(b":");
        data.extend_from_slice(old_sig_hash);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_create_and_verify_rotation() {
        let old_sk = SigningKey::generate(&mut OsRng);
        let new_sk = SigningKey::generate(&mut OsRng);

        let old_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let old_x25519_pub = PublicKey::from(&old_x25519_secret);

        let new_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let new_x25519_pub = PublicKey::from(&new_x25519_secret);

        let announcement = KeyRotationAnnouncement::create(
            "did:nxf:test123",
            &old_sk,
            &new_sk,
            old_x25519_pub.as_bytes(),
            new_x25519_pub.as_bytes(),
        );

        assert!(announcement.verify().unwrap());
    }

    #[test]
    fn test_forged_rotation_fails() {
        let old_sk = SigningKey::generate(&mut OsRng);
        let fake_sk = SigningKey::generate(&mut OsRng);
        let new_sk = SigningKey::generate(&mut OsRng);

        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_pub = PublicKey::from(&x_secret);

        // Try to forge: use fake key instead of old key
        let mut announcement = KeyRotationAnnouncement::create(
            "did:nxf:test",
            &fake_sk,
            &new_sk,
            x_pub.as_bytes(),
            x_pub.as_bytes(),
        );

        // Replace old key with the real old key (attacker trying to claim ownership)
        announcement.old_verifying_key_hex = hex::encode(old_sk.verifying_key().as_bytes());

        // Should fail — old signature doesn't match the claimed old key
        assert!(!announcement.verify().unwrap());
    }

    #[test]
    fn test_serialization() {
        let old_sk = SigningKey::generate(&mut OsRng);
        let new_sk = SigningKey::generate(&mut OsRng);

        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_pub = PublicKey::from(&x_secret);

        let announcement = KeyRotationAnnouncement::create(
            "did:nxf:test",
            &old_sk,
            &new_sk,
            x_pub.as_bytes(),
            x_pub.as_bytes(),
        );

        let json = serde_json::to_string(&announcement).unwrap();
        let deserialized: KeyRotationAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(deserialized.verify().unwrap());
    }
}

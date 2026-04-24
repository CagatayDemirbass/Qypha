use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::identity::{derive_did_from_verifying_key, AgentKeyPair};

const DID_PROFILE_PREFIX: &[u8] = b"QYPHA_DID_PROFILE_V1:";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DidContactService {
    IrohRelay {
        relay_urls: Vec<String>,
        mailbox_topic: String,
        #[serde(default)]
        endpoint_addr_json: Option<String>,
    },
    TorMailbox {
        onion_address: String,
        mailbox_namespace: String,
        port: u16,
    },
    TorDirect {
        onion_address: String,
        port: u16,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DidProfile {
    pub version: u8,
    pub did: String,
    pub verifying_key: [u8; 32],
    pub x25519_public_key: [u8; 32],
    #[serde(default)]
    pub kyber_public_key_hex: String,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub services: Vec<DidContactService>,
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl DidProfile {
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
                Self::write_canonical_str(buf, value);
            }
        }
    }

    fn write_canonical_services(buf: &mut Vec<u8>, services: &[DidContactService]) {
        buf.extend_from_slice(&(services.len() as u32).to_le_bytes());
        for service in services {
            match service {
                DidContactService::IrohRelay {
                    relay_urls,
                    mailbox_topic,
                    endpoint_addr_json,
                } => {
                    buf.push(0x01);
                    buf.extend_from_slice(&(relay_urls.len() as u32).to_le_bytes());
                    for url in relay_urls {
                        Self::write_canonical_str(buf, url);
                    }
                    Self::write_canonical_str(buf, mailbox_topic);
                    Self::write_canonical_opt_str(buf, endpoint_addr_json.as_deref());
                }
                DidContactService::TorMailbox {
                    onion_address,
                    mailbox_namespace,
                    port,
                } => {
                    buf.push(0x02);
                    Self::write_canonical_str(buf, onion_address);
                    Self::write_canonical_str(buf, mailbox_namespace);
                    buf.extend_from_slice(&port.to_le_bytes());
                }
                DidContactService::TorDirect {
                    onion_address,
                    port,
                } => {
                    buf.push(0x03);
                    Self::write_canonical_str(buf, onion_address);
                    buf.extend_from_slice(&port.to_le_bytes());
                }
            }
        }
    }

    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(512);
        data.extend_from_slice(DID_PROFILE_PREFIX);
        data.push(self.version);
        Self::write_canonical_str(&mut data, &self.did);
        Self::write_canonical_bytes(&mut data, &self.verifying_key);
        Self::write_canonical_bytes(&mut data, &self.x25519_public_key);
        Self::write_canonical_opt_str(
            &mut data,
            (!self.kyber_public_key_hex.is_empty()).then_some(self.kyber_public_key_hex.as_str()),
        );
        data.extend_from_slice(&self.created_at.to_le_bytes());
        match self.expires_at {
            None => data.push(0x00),
            Some(value) => {
                data.push(0x01);
                data.extend_from_slice(&value.to_le_bytes());
            }
        }
        Self::write_canonical_services(&mut data, &self.services);
        data
    }

    pub fn generate(
        keypair: &AgentKeyPair,
        services: Vec<DidContactService>,
        expires_at: Option<u64>,
    ) -> Self {
        let mut profile = Self {
            version: 1,
            did: keypair.did.clone(),
            verifying_key: keypair.verifying_key.to_bytes(),
            x25519_public_key: keypair.x25519_public_key_bytes(),
            kyber_public_key_hex: hex::encode(&keypair.kyber_public),
            created_at: chrono::Utc::now().timestamp() as u64,
            expires_at,
            services,
            signature: Vec::new(),
        };

        let signature = keypair.signing_key.sign(&profile.signing_data());
        profile.signature = signature.to_bytes().to_vec();
        profile
    }

    pub fn verify(&self) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.verifying_key)
            .context("Invalid DID profile verifying key")?;
        let expected_did = derive_did_from_verifying_key(&verifying_key);
        if self.did != expected_did {
            return Err(anyhow::anyhow!(
                "DID profile key mismatch: claimed DID '{}' does not match verifying key fingerprint '{}'",
                self.did,
                expected_did
            ));
        }
        if self.kyber_public_key_hex.is_empty() {
            return Err(anyhow::anyhow!(
                "DID profile is missing the required Kyber-1024 public key"
            ));
        }
        let kyber_public = hex::decode(&self.kyber_public_key_hex)
            .context("Invalid DID profile Kyber public key hex")?;
        if kyber_public.len() != pqc_kyber::KYBER_PUBLICKEYBYTES {
            return Err(anyhow::anyhow!(
                "DID profile Kyber public key has invalid length {} (expected {})",
                kyber_public.len(),
                pqc_kyber::KYBER_PUBLICKEYBYTES
            ));
        }

        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid DID profile signature format"))?;
        Ok(verifying_key
            .verify_strict(&self.signing_data(), &signature)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_profile_roundtrip_and_signature_verifies() {
        let keypair = AgentKeyPair::generate("ProfileOwner", "agent");
        let profile = DidProfile::generate(
            &keypair,
            vec![
                DidContactService::IrohRelay {
                    relay_urls: vec!["https://relay.example.com".to_string()],
                    mailbox_topic: "did-qypha-contact".to_string(),
                    endpoint_addr_json: Some(
                        "{\"node_id\":\"relay-contact\",\"addrs\":[{\"Relay\":\"https://relay.example.com/\"}]}"
                            .to_string(),
                    ),
                },
                DidContactService::TorMailbox {
                    onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                        .to_string(),
                    mailbox_namespace: "contact".to_string(),
                    port: 9444,
                },
                DidContactService::TorDirect {
                    onion_address: "zyxwvutsrqponmlkjihgfedcba234567zyxwvutsrqponmlkjihgfed".to_string(),
                    port: 9090,
                },
            ],
            None,
        );

        let encoded = serde_json::to_string(&profile).unwrap();
        let decoded: DidProfile = serde_json::from_str(&encoded).unwrap();

        assert!(decoded.verify().unwrap());
        assert_eq!(decoded.did, keypair.did);
        assert_eq!(decoded.verifying_key, keypair.verifying_key.to_bytes());
        assert_eq!(decoded.services.len(), 3);
    }

    #[test]
    fn did_profile_rejects_did_key_mismatch() {
        let keypair = AgentKeyPair::generate("ProfileOwner", "agent");
        let mut profile = DidProfile::generate(&keypair, Vec::new(), None);
        profile.did =
            "did:nxf:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        profile.signature = keypair
            .signing_key
            .sign(&profile.signing_data())
            .to_bytes()
            .to_vec();

        assert!(profile.verify().is_err());
    }

    #[test]
    fn did_profile_rejects_missing_kyber_public_key() {
        let keypair = AgentKeyPair::generate("ProfileOwner", "agent");
        let mut profile = DidProfile::generate(&keypair, Vec::new(), None);
        profile.kyber_public_key_hex.clear();
        profile.signature = keypair
            .signing_key
            .sign(&profile.signing_data())
            .to_bytes()
            .to_vec();

        assert!(profile.verify().is_err());
    }
}

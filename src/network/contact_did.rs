use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::crypto::identity::{derive_did_from_verifying_key, is_valid_did};

use super::did_profile::DidProfile;

pub const CONTACT_DID_PREFIX: &str = "did:qypha:";
const CONTACT_DID_FINGERPRINT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedContactDid {
    pub encoded: String,
    pub canonical_did: String,
}

fn decode_contact_did_fingerprint(value: &str) -> Result<[u8; CONTACT_DID_FINGERPRINT_LEN]> {
    let decoded = bs58::decode(value)
        .into_vec()
        .context("Qypha DID fingerprint must be base58")?;
    let bytes: [u8; CONTACT_DID_FINGERPRINT_LEN] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Qypha DID fingerprint must decode to 32 bytes"))?;
    Ok(bytes)
}

pub fn contact_did_from_verifying_key_bytes(verifying_key_bytes: [u8; 32]) -> String {
    let fingerprint = Sha256::digest(verifying_key_bytes);
    format!(
        "{CONTACT_DID_PREFIX}{}",
        bs58::encode(fingerprint).into_string()
    )
}

pub fn contact_did_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    contact_did_from_verifying_key_bytes(verifying_key.to_bytes())
}

pub fn contact_did_from_canonical_did(canonical_did: &str) -> Result<String> {
    if !is_valid_did(canonical_did) {
        anyhow::bail!("Unsupported canonical DID format");
    }
    let fingerprint_hex = canonical_did
        .strip_prefix("did:nxf:")
        .ok_or_else(|| anyhow::anyhow!("Unsupported canonical DID prefix"))?;
    let fingerprint =
        hex::decode(fingerprint_hex).context("Canonical DID fingerprint is not hex")?;
    let fingerprint: [u8; CONTACT_DID_FINGERPRINT_LEN] = fingerprint
        .try_into()
        .map_err(|_| anyhow::anyhow!("Canonical DID fingerprint must decode to 32 bytes"))?;
    Ok(format!(
        "{CONTACT_DID_PREFIX}{}",
        bs58::encode(fingerprint).into_string()
    ))
}

pub fn is_contact_did(value: &str) -> bool {
    decode_contact_did(value).is_ok()
}

pub fn encode_contact_did(profile: &DidProfile) -> Result<String> {
    if !is_valid_did(&profile.did) {
        anyhow::bail!(
            "Contact DID profile contains invalid canonical DID '{}'",
            profile.did
        );
    }
    if !profile.verify()? {
        anyhow::bail!("Contact DID profile signature is invalid");
    }
    let verifying_key = VerifyingKey::from_bytes(&profile.verifying_key)
        .context("Invalid DID profile verifying key")?;
    let expected_did = derive_did_from_verifying_key(&verifying_key);
    if expected_did != profile.did {
        anyhow::bail!(
            "Contact DID profile key mismatch: '{}' does not match '{}'",
            profile.did,
            expected_did
        );
    }
    Ok(contact_did_from_verifying_key(&verifying_key))
}

pub fn decode_contact_did(value: &str) -> Result<ResolvedContactDid> {
    let suffix = value
        .strip_prefix(CONTACT_DID_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("Unsupported Qypha DID prefix"))?;
    let fingerprint_bytes = decode_contact_did_fingerprint(suffix)?;
    let fingerprint_hex = hex::encode(fingerprint_bytes);
    Ok(ResolvedContactDid {
        encoded: format!("{CONTACT_DID_PREFIX}{suffix}"),
        canonical_did: format!("did:nxf:{fingerprint_hex}"),
    })
}

pub fn contact_did_matches_profile(contact_did: &str, profile: &DidProfile) -> Result<()> {
    let expected = encode_contact_did(profile)?;
    let resolved = decode_contact_did(contact_did)?;
    if resolved.encoded != expected {
        anyhow::bail!(
            "Qypha DID '{}' does not match the advertised contact profile '{}'",
            resolved.encoded,
            expected
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::discovery::build_local_did_profile_with_iroh_contact_endpoint;
    use serde_json::json;

    fn test_config() -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": "tester",
                "role": "agent",
                "did": "did:nxf:test"
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false,
                "transport_mode": "internet",
                "iroh": {
                    "relay_enabled": true,
                    "direct_enabled": false,
                    "relay_urls": ["https://relay.example.com"]
                },
                "mailbox": {
                    "endpoint": "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                    "pool_endpoints": []
                }
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

    #[test]
    fn contact_did_roundtrip_resolves_profile() {
        let keypair = AgentKeyPair::generate("ContactDidOwner", "agent");
        let config = test_config();
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &config.network.iroh,
                [7u8; 32],
            )
            .unwrap()
            .unwrap();
        let profile = build_local_did_profile_with_iroh_contact_endpoint(
            &keypair,
            &config,
            None,
            Some(&endpoint_addr_json),
        )
        .unwrap();

        let contact_did = encode_contact_did(&profile).unwrap();
        assert!(is_contact_did(&contact_did));

        let resolved = decode_contact_did(&contact_did).unwrap();
        assert_eq!(resolved.canonical_did, profile.did);
        assert_eq!(resolved.encoded, contact_did);
        contact_did_matches_profile(&contact_did, &profile).unwrap();
    }

    #[test]
    fn contact_did_rejects_tampered_payload() {
        let keypair = AgentKeyPair::generate("ContactDidOwner", "agent");
        let config = test_config();
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &config.network.iroh,
                [8u8; 32],
            )
            .unwrap()
            .unwrap();
        let profile = build_local_did_profile_with_iroh_contact_endpoint(
            &keypair,
            &config,
            None,
            Some(&endpoint_addr_json),
        )
        .unwrap();
        let contact_did = encode_contact_did(&profile).unwrap();
        let tampered = format!(
            "{}{}",
            CONTACT_DID_PREFIX,
            bs58::encode([0xFF; CONTACT_DID_FINGERPRINT_LEN]).into_string()
        );

        assert!(decode_contact_did(&tampered).is_ok());
        assert!(contact_did_matches_profile(&tampered, &profile).is_err());
        assert_ne!(tampered, contact_did);
    }

    #[test]
    fn contact_did_rejects_legacy_hex_format() {
        let legacy = "did:qypha:992b2ca90e5db4c7803b66a2978f35bcfdea4839ba6f66e491deb1d055714670";
        assert!(decode_contact_did(legacy).is_err());
        assert!(!is_contact_did(legacy));
    }
}

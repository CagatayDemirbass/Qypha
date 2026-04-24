use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::contact_did::{contact_did_matches_profile, is_contact_did};
use super::did_profile::DidProfile;

pub const CONTACT_BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBundleGetRequest {
    pub version: u8,
    pub contact_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBundlePutRequest {
    pub version: u8,
    pub contact_did: String,
    pub profile: DidProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactBundleGetResponse {
    pub version: u8,
    pub contact_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<DidProfile>,
}

impl ContactBundleGetRequest {
    pub fn new(contact_did: impl Into<String>) -> Self {
        Self {
            version: CONTACT_BUNDLE_VERSION,
            contact_did: contact_did.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CONTACT_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported contact bundle request version {}",
                self.version
            );
        }
        if !is_contact_did(&self.contact_did) {
            anyhow::bail!("Invalid Qypha DID format");
        }
        Ok(())
    }
}

impl ContactBundlePutRequest {
    pub fn new(contact_did: impl Into<String>, profile: DidProfile) -> Self {
        Self {
            version: CONTACT_BUNDLE_VERSION,
            contact_did: contact_did.into(),
            profile,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CONTACT_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported contact bundle publish version {}",
                self.version
            );
        }
        verify_contact_bundle(&self.contact_did, &self.profile)
    }
}

impl ContactBundleGetResponse {
    pub fn empty(contact_did: impl Into<String>) -> Self {
        Self {
            version: CONTACT_BUNDLE_VERSION,
            contact_did: contact_did.into(),
            profile: None,
        }
    }

    pub fn with_profile(contact_did: impl Into<String>, profile: DidProfile) -> Self {
        Self {
            version: CONTACT_BUNDLE_VERSION,
            contact_did: contact_did.into(),
            profile: Some(profile),
        }
    }

    pub fn into_verified_profile(self) -> Result<Option<DidProfile>> {
        if self.version != CONTACT_BUNDLE_VERSION {
            anyhow::bail!(
                "Unsupported contact bundle response version {}",
                self.version
            );
        }
        if !is_contact_did(&self.contact_did) {
            anyhow::bail!("Invalid Qypha DID format");
        }
        match self.profile {
            Some(profile) => {
                verify_contact_bundle(&self.contact_did, &profile)?;
                Ok(Some(profile))
            }
            None => Ok(None),
        }
    }
}

pub fn verify_contact_bundle(contact_did: &str, profile: &DidProfile) -> Result<()> {
    contact_did_matches_profile(contact_did, profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::encode_contact_did;
    use crate::network::discovery::build_local_did_profile_with_iroh_contact_endpoint;
    use serde_json::json;

    fn test_config() -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": "bundle-owner",
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
    fn verifies_profile_against_contact_did() {
        let keypair = AgentKeyPair::generate("bundle-owner", "agent");
        let config = test_config();
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &config.network.iroh,
                [4u8; 32],
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
        let response = ContactBundleGetResponse::with_profile(contact_did, profile.clone());
        assert_eq!(response.into_verified_profile().unwrap(), Some(profile));
    }
}

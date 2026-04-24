use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::config::AppConfig;
use crate::crypto::identity::AgentKeyPair;
use crate::network::did_profile::DidProfile;

pub mod iroh;
pub mod tor;

const IROH_CONTACT_TOPIC_SCOPE: &[u8] = b"QYPHA_IROH_CONTACT_TOPIC_V1:";
const TOR_CONTACT_NAMESPACE_SCOPE: &[u8] = b"QYPHA_TOR_CONTACT_NAMESPACE_V1:";

/// Peer discovery mechanisms
/// - mDNS: Local network (same office LAN)
/// - Kademlia DHT: Cross-network (different offices via WireGuard)
/// - Bootstrap nodes: Initial connection points for new agents
pub struct BootstrapConfig {
    pub nodes: Vec<String>, // Multiaddr of bootstrap nodes
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self { nodes: vec![] }
    }
}

pub fn contact_mailbox_topic_for_did(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IROH_CONTACT_TOPIC_SCOPE);
    hasher.update(did.as_bytes());
    format!("did-contact:{}", hex::encode(hasher.finalize()))
}

pub fn contact_mailbox_namespace_for_did(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TOR_CONTACT_NAMESPACE_SCOPE);
    hasher.update(did.as_bytes());
    format!("contact:{}", hex::encode(hasher.finalize()))
}

pub fn build_local_did_profile(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    tor_endpoint_override: Option<&str>,
) -> Result<DidProfile> {
    build_local_did_profile_with_runtime_contact_endpoints(
        keypair,
        config,
        tor_endpoint_override,
        None,
        None,
        None,
    )
}

pub fn build_local_did_profile_with_iroh_contact_endpoint(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    tor_endpoint_override: Option<&str>,
    iroh_contact_endpoint_addr_json: Option<&str>,
) -> Result<DidProfile> {
    build_local_did_profile_with_runtime_contact_endpoints(
        keypair,
        config,
        tor_endpoint_override,
        iroh_contact_endpoint_addr_json,
        None,
        None,
    )
}

pub fn build_local_did_profile_with_runtime_contact_endpoints(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    tor_endpoint_override: Option<&str>,
    iroh_contact_endpoint_addr_json: Option<&str>,
    tor_direct_onion_address: Option<&str>,
    tor_direct_port: Option<u16>,
) -> Result<DidProfile> {
    let mut services = Vec::new();

    if let Some(service) = iroh::build_iroh_relay_service(
        &config.network.iroh,
        &keypair.did,
        iroh_contact_endpoint_addr_json.map(str::to_string),
    )? {
        services.push(service);
    }

    if let Some(service) =
        tor::build_tor_mailbox_service_from_config(config, &keypair.did, tor_endpoint_override)?
    {
        services.push(service);
    }

    if let Some(onion_address) = tor_direct_onion_address {
        services.push(tor::build_tor_direct_service(
            onion_address,
            tor_direct_port.unwrap_or(config.network.listen_port),
        )?);
    }

    Ok(DidProfile::generate(keypair, services, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
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
    fn deterministic_contact_topics_and_namespaces() {
        let did = "did:nxf:abc123";
        assert_eq!(
            contact_mailbox_topic_for_did(did),
            contact_mailbox_topic_for_did(did)
        );
        assert_eq!(
            contact_mailbox_namespace_for_did(did),
            contact_mailbox_namespace_for_did(did)
        );
    }

    #[test]
    fn build_local_did_profile_uses_ipless_services() {
        let keypair = AgentKeyPair::generate("LocalProfile", "agent");
        let config = test_config();
        let profile = build_local_did_profile(&keypair, &config, None).unwrap();

        let encoded = serde_json::to_string(&profile).unwrap();
        assert!(encoded.contains("did-contact:"));
        assert!(encoded.contains("contact:"));
        assert!(!encoded.contains("/ip4/"));
        assert!(!encoded.contains("iroh_endpoint_addr"));
        assert!(!encoded.contains("tcp_address"));
    }

    #[test]
    fn build_local_did_profile_with_runtime_iroh_endpoint_keeps_it_relay_only() {
        let keypair = AgentKeyPair::generate("RuntimeProfile", "agent");
        let config = test_config();
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &config.network.iroh,
                [5u8; 32],
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
        let encoded = serde_json::to_string(&profile).unwrap();
        assert!(encoded.contains("\"endpoint_addr_json\""));
        assert!(!encoded.contains("127.0.0.1"));
        assert!(!encoded.contains("/ip4/"));
    }
}

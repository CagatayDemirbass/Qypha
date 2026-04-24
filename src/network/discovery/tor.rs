use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::config::AppConfig;
use crate::network::did_profile::DidContactService;
use crate::network::mailbox_transport::{parse_mailbox_service_endpoint, MailboxServiceEndpoint};

use super::contact_mailbox_namespace_for_did;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorMailboxContactDescriptor {
    pub onion_address: String,
    pub mailbox_namespace: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorDirectContactDescriptor {
    pub onion_address: String,
    pub port: u16,
}

fn normalize_tor_onion_address(value: &str) -> Result<String> {
    let normalized = value.trim().trim_end_matches(".onion").to_lowercase();
    if normalized.len() != 56 {
        anyhow::bail!("Tor onion addresses must be 56 characters");
    }
    if !normalized
        .chars()
        .all(|ch| matches!(ch, 'a'..='z' | '2'..='7'))
    {
        anyhow::bail!("Tor onion addresses must be base32 without separators");
    }
    Ok(normalized)
}

fn deterministic_pool_index(did: &str, len: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(b"QYPHA_TOR_DISCOVERY_POOL_PICK_V1:");
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(bytes) as usize) % len
}

fn configured_mailbox_endpoint_candidates(config: &AppConfig) -> Vec<String> {
    let mut endpoints = config
        .network
        .mailbox
        .pool_endpoints
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

pub fn resolve_public_bundle_endpoint_from_config(config: &AppConfig, did: &str) -> Option<String> {
    let pool = configured_mailbox_endpoint_candidates(config);
    if pool.is_empty() {
        return None;
    }
    let idx = deterministic_pool_index(did, pool.len());
    Some(pool[idx].clone())
}

pub fn build_tor_mailbox_service_from_endpoint(
    endpoint: &str,
    did: &str,
) -> Result<DidContactService> {
    match parse_mailbox_service_endpoint(endpoint)? {
        MailboxServiceEndpoint::Tor { onion, port } => Ok(DidContactService::TorMailbox {
            onion_address: onion,
            mailbox_namespace: contact_mailbox_namespace_for_did(did),
            port,
        }),
        MailboxServiceEndpoint::LoopbackHttp { .. } => {
            anyhow::bail!("Loopback mailbox endpoints must not be advertised in DID profiles")
        }
    }
}

pub fn build_tor_direct_service(onion_address: &str, port: u16) -> Result<DidContactService> {
    if port == 0 {
        anyhow::bail!("Tor direct contact service requires a non-zero port");
    }
    Ok(DidContactService::TorDirect {
        onion_address: normalize_tor_onion_address(onion_address)?,
        port,
    })
}

pub fn build_tor_mailbox_service_from_config(
    config: &AppConfig,
    did: &str,
    endpoint_override: Option<&str>,
) -> Result<Option<DidContactService>> {
    if let Some(endpoint) = endpoint_override {
        return Ok(Some(build_tor_mailbox_service_from_endpoint(
            endpoint, did,
        )?));
    }

    if let Some(endpoint) = config
        .network
        .mailbox
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(build_tor_mailbox_service_from_endpoint(
            endpoint, did,
        )?));
    }

    let pool = configured_mailbox_endpoint_candidates(config);
    if pool.is_empty() {
        return Ok(None);
    }

    let idx = deterministic_pool_index(did, pool.len());
    Ok(Some(build_tor_mailbox_service_from_endpoint(
        &pool[idx], did,
    )?))
}

pub fn resolve_tor_mailbox_service(
    service: &DidContactService,
) -> Result<TorMailboxContactDescriptor> {
    let DidContactService::TorMailbox {
        onion_address,
        mailbox_namespace,
        port,
    } = service
    else {
        anyhow::bail!("DID service is not a Tor mailbox contact");
    };

    Ok(TorMailboxContactDescriptor {
        onion_address: onion_address.clone(),
        mailbox_namespace: mailbox_namespace.clone(),
        port: *port,
    })
}

pub fn resolve_tor_direct_service(
    service: &DidContactService,
) -> Result<TorDirectContactDescriptor> {
    let DidContactService::TorDirect {
        onion_address,
        port,
    } = service
    else {
        anyhow::bail!("DID service is not a Tor direct contact");
    };

    Ok(TorDirectContactDescriptor {
        onion_address: onion_address.clone(),
        port: *port,
    })
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
                "mailbox": {
                    "endpoint": null,
                    "pool_endpoints": [
                        "tor://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:9444",
                        "tor://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:9444"
                    ]
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
    fn build_tor_mailbox_service_rejects_loopback_endpoints() {
        assert!(
            build_tor_mailbox_service_from_endpoint("http://127.0.0.1:9444", "did:nxf:alice")
                .is_err()
        );
    }

    #[test]
    fn build_tor_direct_service_normalizes_runtime_onion() {
        let service = build_tor_direct_service(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
            9090,
        )
        .unwrap();
        let resolved = resolve_tor_direct_service(&service).unwrap();
        assert_eq!(
            resolved.onion_address,
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
        );
        assert_eq!(resolved.port, 9090);
    }

    #[test]
    fn build_tor_mailbox_service_from_config_is_deterministic() {
        let config = test_config();
        let service_a =
            build_tor_mailbox_service_from_config(&config, "did:nxf:alice", None).unwrap();
        let service_b =
            build_tor_mailbox_service_from_config(&config, "did:nxf:alice", None).unwrap();

        assert_eq!(service_a, service_b);
        let resolved = resolve_tor_mailbox_service(service_a.as_ref().unwrap()).unwrap();
        assert!(resolved.onion_address.ends_with('a') || resolved.onion_address.ends_with('b'));
        assert_eq!(
            resolved.mailbox_namespace,
            contact_mailbox_namespace_for_did("did:nxf:alice")
        );
        assert!(!serde_json::to_string(service_a.as_ref().unwrap())
            .unwrap()
            .contains("127.0.0.1"));
    }
}

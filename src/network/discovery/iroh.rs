use anyhow::{Context, Result};
use sha2::Digest;

use crate::config::IrohConfig;
use crate::network::did_profile::DidContactService;

use super::contact_mailbox_topic_for_did;

const IROH_CONTACT_BUNDLE_ENDPOINT_SCOPE: &[u8] = b"QYPHA_IROH_CONTACT_BUNDLE_ENDPOINT_V1:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohRelayContactDescriptor {
    pub relay_urls: Vec<String>,
    pub mailbox_topic: String,
    pub endpoint_addr_json: Option<String>,
}

fn normalized_relay_urls(iroh_config: &IrohConfig) -> Vec<String> {
    let mut relay_urls = iroh_config
        .relay_urls
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if relay_urls.is_empty() {
        relay_urls = default_relay_urls();
    }
    relay_urls.sort();
    relay_urls.dedup();
    relay_urls
}

fn default_relay_urls() -> Vec<String> {
    let relay_map = if matches!(std::env::var("IROH_FORCE_STAGING_RELAYS"), Ok(value) if !value.is_empty())
    {
        iroh::defaults::staging::default_relay_map()
    } else {
        iroh::defaults::prod::default_relay_map()
    };
    relay_map
        .urls::<Vec<_>>()
        .into_iter()
        .map(|url| url.to_string())
        .collect()
}

pub fn relay_mode_from_config_for_discovery(iroh_config: &IrohConfig) -> Result<iroh::RelayMode> {
    if !iroh_config.relay_enabled {
        return Ok(iroh::RelayMode::Disabled);
    }

    let relay_urls = normalized_relay_urls(iroh_config);
    if relay_urls.is_empty() {
        return Ok(iroh::RelayMode::Default);
    }

    let urls = relay_urls
        .iter()
        .map(|value| value.parse::<iroh::RelayUrl>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::new)
        .context("Invalid configured iroh relay URL for discovery")?;

    Ok(iroh::RelayMode::custom(urls))
}

pub fn public_contact_bundle_secret_bytes(contact_did: &str) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(IROH_CONTACT_BUNDLE_ENDPOINT_SCOPE);
    hasher.update(contact_did.as_bytes());
    let digest = hasher.finalize();
    let mut derived = [0u8; 32];
    derived.copy_from_slice(&digest[..32]);
    derived
}

pub fn sanitize_relay_only_iroh_endpoint_addr(
    mut endpoint_addr: iroh::EndpointAddr,
) -> Result<iroh::EndpointAddr> {
    endpoint_addr
        .addrs
        .retain(|transport| matches!(transport, iroh::TransportAddr::Relay(_)));
    if endpoint_addr.addrs.is_empty() {
        anyhow::bail!("Iroh endpoint must advertise at least one relay address");
    }
    Ok(endpoint_addr)
}

pub fn sanitize_relay_only_iroh_endpoint_addr_json(endpoint_addr_json: &str) -> Result<String> {
    let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(endpoint_addr_json)
        .map_err(anyhow::Error::new)
        .context("Invalid iroh endpoint JSON")?;
    serde_json::to_string(&sanitize_relay_only_iroh_endpoint_addr(endpoint_addr)?)
        .map_err(anyhow::Error::new)
        .context("Failed to encode relay-only iroh endpoint")
}

#[cfg(test)]
pub(crate) fn sample_relay_only_iroh_endpoint_addr_json(seed: u8) -> String {
    let endpoint_id = iroh::SecretKey::from_bytes(&[seed; 32]).public();
    let endpoint_addr = iroh::EndpointAddr::from_parts(
        endpoint_id,
        [iroh::TransportAddr::Relay(
            "https://relay.example.test"
                .parse::<iroh::RelayUrl>()
                .expect("valid relay url"),
        )],
    );
    serde_json::to_string(&endpoint_addr).expect("encodable relay-only endpoint")
}

fn ensure_relay_only_endpoint_addr(
    endpoint_addr: iroh::EndpointAddr,
) -> Result<iroh::EndpointAddr> {
    if endpoint_addr
        .addrs
        .iter()
        .any(|transport| !matches!(transport, iroh::TransportAddr::Relay(_)))
    {
        anyhow::bail!("Iroh contact endpoint must not include direct or non-relay addresses");
    }
    sanitize_relay_only_iroh_endpoint_addr(endpoint_addr)
}

pub fn parse_public_iroh_contact_endpoint_addr(
    endpoint_addr_json: &str,
) -> Result<iroh::EndpointAddr> {
    let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(endpoint_addr_json)
        .map_err(anyhow::Error::new)
        .context("Invalid public iroh contact endpoint JSON")?;
    ensure_relay_only_endpoint_addr(endpoint_addr)
}

pub fn build_public_iroh_contact_endpoint_addr(
    iroh_config: &IrohConfig,
    endpoint_secret_bytes: [u8; 32],
) -> Result<Option<iroh::EndpointAddr>> {
    if !iroh_config.relay_enabled {
        return Ok(None);
    }

    let relay_urls = normalized_relay_urls(iroh_config);
    let endpoint_id = iroh::SecretKey::from_bytes(&endpoint_secret_bytes).public();
    let endpoint_addr = iroh::EndpointAddr::from_parts(
        endpoint_id,
        relay_urls
            .iter()
            .map(|value| {
                value
                    .parse::<iroh::RelayUrl>()
                    .map(iroh::TransportAddr::Relay)
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(anyhow::Error::new)
            .context("Invalid configured iroh relay URL for public contact endpoint")?,
    );
    Ok(Some(ensure_relay_only_endpoint_addr(endpoint_addr)?))
}

pub fn build_public_contact_bundle_endpoint_addr(
    iroh_config: &IrohConfig,
    contact_did: &str,
) -> Result<Option<iroh::EndpointAddr>> {
    if !iroh_config.relay_enabled {
        return Ok(None);
    }
    build_public_iroh_contact_endpoint_addr(
        iroh_config,
        public_contact_bundle_secret_bytes(contact_did),
    )
}

pub fn build_public_iroh_contact_endpoint_addr_json(
    iroh_config: &IrohConfig,
    endpoint_secret_bytes: [u8; 32],
) -> Result<Option<String>> {
    let Some(endpoint_addr) =
        build_public_iroh_contact_endpoint_addr(iroh_config, endpoint_secret_bytes)?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::to_string(&endpoint_addr).context(
        "Failed to encode public iroh contact endpoint address",
    )?))
}

pub fn build_iroh_relay_service(
    iroh_config: &IrohConfig,
    did: &str,
    endpoint_addr_json: Option<String>,
) -> Result<Option<DidContactService>> {
    if !iroh_config.relay_enabled {
        return Ok(None);
    }
    let endpoint_addr_json = endpoint_addr_json
        .map(|value| {
            parse_public_iroh_contact_endpoint_addr(&value).and_then(|addr| {
                serde_json::to_string(&addr)
                    .map_err(anyhow::Error::new)
                    .context("Failed to normalize public iroh contact endpoint")
            })
        })
        .transpose()?;
    Ok(Some(DidContactService::IrohRelay {
        relay_urls: normalized_relay_urls(iroh_config),
        mailbox_topic: contact_mailbox_topic_for_did(did),
        endpoint_addr_json,
    }))
}

pub fn resolve_iroh_relay_service(
    service: &DidContactService,
) -> Result<IrohRelayContactDescriptor> {
    let DidContactService::IrohRelay {
        relay_urls,
        mailbox_topic,
        endpoint_addr_json,
    } = service
    else {
        anyhow::bail!("DID service is not an iroh relay contact");
    };
    let endpoint_addr_json = endpoint_addr_json
        .as_deref()
        .map(|value| {
            parse_public_iroh_contact_endpoint_addr(value).and_then(|addr| {
                serde_json::to_string(&addr)
                    .map_err(anyhow::Error::new)
                    .context("Failed to normalize resolved public iroh contact endpoint")
            })
        })
        .transpose()?;

    Ok(IrohRelayContactDescriptor {
        relay_urls: relay_urls.clone(),
        mailbox_topic: mailbox_topic.clone(),
        endpoint_addr_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IrohConfig;

    #[test]
    fn build_iroh_relay_service_uses_deterministic_topic_and_no_ip() {
        let config = IrohConfig {
            relay_enabled: true,
            direct_enabled: true,
            relay_urls: vec![
                "https://relay-b.example.com".to_string(),
                "https://relay-a.example.com".to_string(),
            ],
        };

        let endpoint_addr_json =
            build_public_iroh_contact_endpoint_addr_json(&config, [7u8; 32]).unwrap();
        let service = build_iroh_relay_service(&config, "did:nxf:alice", endpoint_addr_json)
            .unwrap()
            .unwrap();
        let resolved = resolve_iroh_relay_service(&service).unwrap();

        assert_eq!(
            resolved.mailbox_topic,
            super::contact_mailbox_topic_for_did("did:nxf:alice")
        );
        assert_eq!(
            resolved.relay_urls,
            vec![
                "https://relay-a.example.com".to_string(),
                "https://relay-b.example.com".to_string()
            ]
        );
        let endpoint_addr = parse_public_iroh_contact_endpoint_addr(
            resolved.endpoint_addr_json.as_deref().unwrap(),
        )
        .unwrap();
        assert!(endpoint_addr
            .addrs
            .iter()
            .all(|transport| matches!(transport, iroh::TransportAddr::Relay(_))));
        assert!(!serde_json::to_string(&service).unwrap().contains("/ip4/"));
    }

    #[test]
    fn default_relay_urls_fill_empty_config() {
        let config = IrohConfig {
            relay_enabled: true,
            direct_enabled: false,
            relay_urls: Vec::new(),
        };
        let service = build_iroh_relay_service(&config, "did:nxf:alice", None)
            .unwrap()
            .unwrap();
        let resolved = resolve_iroh_relay_service(&service).unwrap();
        assert!(!resolved.relay_urls.is_empty());
    }

    #[test]
    fn parse_public_iroh_contact_endpoint_addr_rejects_direct_ip() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[9u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 7777))),
                iroh::TransportAddr::Relay(
                    "https://relay.example.com"
                        .parse::<iroh::RelayUrl>()
                        .unwrap(),
                ),
            ],
        );
        let encoded = serde_json::to_string(&endpoint_addr).unwrap();
        assert!(parse_public_iroh_contact_endpoint_addr(&encoded).is_err());
    }

    #[test]
    fn sanitize_relay_only_iroh_endpoint_addr_json_strips_direct_ip() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[12u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 7777))),
                iroh::TransportAddr::Relay(
                    "https://relay.example.com"
                        .parse::<iroh::RelayUrl>()
                        .unwrap(),
                ),
            ],
        );
        let encoded = serde_json::to_string(&endpoint_addr).unwrap();
        let sanitized = sanitize_relay_only_iroh_endpoint_addr_json(&encoded).unwrap();
        let parsed = serde_json::from_str::<iroh::EndpointAddr>(&sanitized).unwrap();

        assert_eq!(parsed.ip_addrs().count(), 0);
        assert_eq!(parsed.relay_urls().count(), 1);
    }

    #[test]
    fn sanitize_relay_only_iroh_endpoint_addr_json_rejects_direct_only() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[13u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [iroh::TransportAddr::Ip(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                7777,
            )))],
        );
        let encoded = serde_json::to_string(&endpoint_addr).unwrap();

        assert!(sanitize_relay_only_iroh_endpoint_addr_json(&encoded).is_err());
    }
}

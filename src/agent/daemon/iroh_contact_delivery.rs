use anyhow::{Context, Result};
use libp2p::PeerId;

use super::*;
use crate::network::did_profile::{DidContactService, DidProfile};
use crate::network::discovery;
use crate::network::discovery::iroh::{
    parse_public_iroh_contact_endpoint_addr, resolve_iroh_relay_service,
};
use crate::network::protocol::AgentResponse;

pub(crate) fn profile_iroh_relay_service(profile: &DidProfile) -> Option<&DidContactService> {
    profile.services.iter().find(|service| {
        matches!(
            service,
            DidContactService::IrohRelay {
                endpoint_addr_json: Some(_),
                ..
            }
        )
    })
}

pub(crate) fn local_runtime_iroh_contact_endpoint_addr_json(
    iroh_network: &IrohTransport,
) -> Result<String> {
    let mut endpoint_addr = iroh_network.endpoint_addr_for_invite(true);
    endpoint_addr
        .addrs
        .retain(|transport| matches!(transport, iroh::TransportAddr::Relay(_)));
    if endpoint_addr.addrs.is_empty() {
        anyhow::bail!("No relay-only iroh contact endpoint is available yet");
    }
    serde_json::to_string(&endpoint_addr).context("Failed to encode runtime iroh contact endpoint")
}

pub(crate) fn build_runtime_iroh_did_profile(
    keypair: &AgentKeyPair,
    config: &AppConfig,
    iroh_network: &IrohTransport,
) -> Result<DidProfile> {
    let endpoint_addr_json = local_runtime_iroh_contact_endpoint_addr_json(iroh_network)?;
    discovery::build_local_did_profile_with_iroh_contact_endpoint(
        keypair,
        config,
        None,
        Some(&endpoint_addr_json),
    )
}

pub(crate) async fn send_request_via_iroh_contact_service(
    iroh_network: &IrohTransport,
    service: &DidContactService,
    request: &AgentRequest,
) -> Result<(PeerId, AgentResponse)> {
    let resolved = resolve_iroh_relay_service(service)?;
    let endpoint_addr_json = resolved
        .endpoint_addr_json
        .ok_or_else(|| anyhow::anyhow!("Iroh relay contact service is missing endpoint data"))?;
    let endpoint_addr = parse_public_iroh_contact_endpoint_addr(&endpoint_addr_json)?;
    let peer_id = iroh_network.connect(endpoint_addr).await?.peer_id();
    let response = iroh_network.send_request(&peer_id, request).await?;
    Ok((peer_id, response))
}

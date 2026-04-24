use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::config::IrohConfig;

use super::contact_bundle::{ContactBundleGetRequest, ContactBundleGetResponse};
use super::contact_did::decode_contact_did;
use super::did_profile::DidProfile;
use super::discovery::iroh::{
    build_public_contact_bundle_endpoint_addr, public_contact_bundle_secret_bytes,
    relay_mode_from_config_for_discovery,
};

const IROH_CONTACT_BUNDLE_ALPN: &[u8] = b"qypha/contact-bundle/iroh/1.0.0";
const IROH_CONTACT_BUNDLE_REQUEST_MAX: usize = 16 * 1024;
const IROH_CONTACT_BUNDLE_RESPONSE_MAX: usize = 512 * 1024;

pub struct IrohContactBundleService {
    endpoint: iroh::Endpoint,
    bundle_state: Arc<RwLock<Option<(String, DidProfile)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl IrohContactBundleService {
    pub async fn start(iroh_config: &IrohConfig, contact_did: &str) -> Result<Self> {
        let relay_mode = relay_mode_from_config_for_discovery(iroh_config)?;
        let secret_bytes = public_contact_bundle_secret_bytes(contact_did);
        let endpoint = iroh::Endpoint::builder()
            .secret_key(iroh::SecretKey::from_bytes(&secret_bytes))
            .alpns(vec![IROH_CONTACT_BUNDLE_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .clear_ip_transports()
            .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .context("Failed to configure iroh public contact bundle endpoint")?
            .bind()
            .await
            .context("Failed to bind iroh public contact bundle endpoint")?;
        let bundle_state = Arc::new(RwLock::new(None::<(String, DidProfile)>));
        let endpoint_acc = endpoint.clone();
        let bundle_state_acc = Arc::clone(&bundle_state);
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint_acc.accept().await {
                let conn = match incoming.accept() {
                    Ok(accepting) => match accepting.await {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "iroh contact bundle handshake failed");
                            continue;
                        }
                    },
                    Err(error) => {
                        tracing::debug!(%error, "iroh contact bundle accept rejected");
                        continue;
                    }
                };
                let bundle_state_conn = Arc::clone(&bundle_state_acc);
                tokio::spawn(async move {
                    loop {
                        let (mut send, mut recv) = match conn.accept_bi().await {
                            Ok(streams) => streams,
                            Err(_) => break,
                        };
                        let req_bytes = match recv
                            .read_to_end(IROH_CONTACT_BUNDLE_REQUEST_MAX)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                tracing::debug!(%error, "iroh contact bundle request read failed");
                                continue;
                            }
                        };
                        let response = match bincode::deserialize::<ContactBundleGetRequest>(
                            &req_bytes,
                        ) {
                            Ok(request) => match request.validate() {
                                Ok(()) => {
                                    let state = bundle_state_conn.read().await;
                                    match &*state {
                                        Some((contact_did, profile))
                                            if request.contact_did == *contact_did =>
                                        {
                                            ContactBundleGetResponse::with_profile(
                                                contact_did.clone(),
                                                profile.clone(),
                                            )
                                        }
                                        _ => ContactBundleGetResponse::empty(
                                            request.contact_did.clone(),
                                        ),
                                    }
                                }
                                Err(error) => {
                                    tracing::debug!(%error, "iroh contact bundle request invalid");
                                    ContactBundleGetResponse::empty(request.contact_did)
                                }
                            },
                            Err(error) => {
                                tracing::debug!(%error, "iroh contact bundle request decode failed");
                                continue;
                            }
                        };
                        let response_bytes = match bincode::serialize(&response) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                tracing::warn!(%error, "iroh contact bundle response encode failed");
                                continue;
                            }
                        };
                        if send.write_all(&response_bytes).await.is_err() {
                            continue;
                        }
                        let _ = send.finish();
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            bundle_state,
            task,
        })
    }

    pub async fn publish(&self, contact_did: String, profile: DidProfile) {
        let mut state = self.bundle_state.write().await;
        *state = Some((contact_did, profile));
    }

    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        let mut addr = self.endpoint.addr();
        addr.addrs
            .retain(|transport| matches!(transport, iroh::TransportAddr::Relay(_)));
        addr
    }

    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
        if !self.endpoint.is_closed() {
            self.endpoint.close().await;
        }
    }
}

pub async fn lookup_contact_bundle_via_iroh(
    iroh_config: &IrohConfig,
    contact_did: &str,
) -> Result<Option<DidProfile>> {
    let endpoint_addr = build_public_contact_bundle_endpoint_addr(iroh_config, contact_did)?
        .ok_or_else(|| anyhow::anyhow!("Iroh relay discovery is disabled"))?;
    let relay_mode = relay_mode_from_config_for_discovery(iroh_config)?;
    let client_endpoint = iroh::Endpoint::builder()
        .secret_key(iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
        .alpns(vec![IROH_CONTACT_BUNDLE_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .clear_ip_transports()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .context("Failed to configure iroh contact bundle lookup client")?
        .bind()
        .await
        .context("Failed to bind iroh contact bundle lookup client")?;

    let conn = client_endpoint
        .connect(endpoint_addr, IROH_CONTACT_BUNDLE_ALPN)
        .await
        .context("iroh contact bundle lookup connect failed")?;
    let request = ContactBundleGetRequest::new(contact_did.to_string());
    let request_bytes =
        bincode::serialize(&request).context("Failed to encode iroh contact bundle request")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi failed")?;
    send.write_all(&request_bytes)
        .await
        .context("Failed to write iroh contact bundle request")?;
    send.finish()
        .context("Failed to finish iroh contact bundle request stream")?;
    let response_bytes = recv
        .read_to_end(IROH_CONTACT_BUNDLE_RESPONSE_MAX)
        .await
        .context("Failed to read iroh contact bundle response")?;
    let response: ContactBundleGetResponse =
        bincode::deserialize(&response_bytes).context("Invalid iroh contact bundle response")?;
    let profile = response.into_verified_profile()?;
    conn.close(0u32.into(), b"qypha-contact-bundle-lookup-done");
    client_endpoint.close().await;
    Ok(profile)
}

pub fn canonical_did_for_contact_did(contact_did: &str) -> Result<String> {
    Ok(decode_contact_did(contact_did)?.canonical_did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IrohConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::encode_contact_did;
    use crate::network::did_profile::DidContactService;
    use crate::network::did_profile::DidProfile;

    fn iroh_config() -> IrohConfig {
        IrohConfig {
            relay_enabled: true,
            direct_enabled: false,
            relay_urls: vec![],
        }
    }

    fn sample_profile(owner: &AgentKeyPair) -> DidProfile {
        DidProfile::generate(
            owner,
            vec![DidContactService::IrohRelay {
                relay_urls: vec!["https://relay.example.com".to_string()],
                mailbox_topic: "did-contact:test".to_string(),
                endpoint_addr_json: Some(
                    "{\"node_id\":\"relay-contact\",\"addrs\":[{\"Relay\":\"https://relay.example.com/\"}]}".to_string(),
                ),
            }],
            None,
        )
    }

    #[tokio::test]
    async fn lookup_roundtrip_works() {
        let owner = AgentKeyPair::generate("bundle-owner", "agent");
        let profile = sample_profile(&owner);
        let contact_did = encode_contact_did(&profile).unwrap();
        let service = IrohContactBundleService::start(&iroh_config(), &contact_did)
            .await
            .unwrap();
        service.publish(contact_did.clone(), profile.clone()).await;

        let resolved = lookup_contact_bundle_via_iroh(&iroh_config(), &contact_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved, profile);

        service.shutdown().await;
    }
}

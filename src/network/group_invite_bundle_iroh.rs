use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::config::IrohConfig;

use super::discovery::iroh::{
    build_public_iroh_contact_endpoint_addr, relay_mode_from_config_for_discovery,
};
use super::group_invite_bundle::{
    GroupInviteBundle, GroupInviteBundleGetRequest, GroupInviteBundleGetResponse,
};

const IROH_GROUP_INVITE_BUNDLE_ALPN: &[u8] = b"qypha/group-invite-bundle/iroh/1.0.0";
const IROH_GROUP_INVITE_BUNDLE_SCOPE: &[u8] = b"QYPHA_IROH_GROUP_INVITE_BUNDLE_ENDPOINT_V1:";
const IROH_GROUP_INVITE_BUNDLE_REQUEST_MAX: usize = 16 * 1024;
const IROH_GROUP_INVITE_BUNDLE_RESPONSE_MAX: usize = 1024 * 1024;

#[derive(Clone)]
pub struct IrohGroupInviteBundleService {
    endpoint: iroh::Endpoint,
    bundle_state: Arc<RwLock<HashMap<String, GroupInviteBundle>>>,
    #[allow(dead_code)]
    task: Arc<tokio::task::JoinHandle<()>>,
}

impl IrohGroupInviteBundleService {
    pub async fn start(iroh_config: &IrohConfig, issuer_contact_did: &str) -> Result<Self> {
        let relay_mode = relay_mode_from_config_for_discovery(iroh_config)?;
        let secret_bytes = public_group_invite_bundle_secret_bytes(issuer_contact_did);
        let endpoint = iroh::Endpoint::builder()
            .secret_key(iroh::SecretKey::from_bytes(&secret_bytes))
            .alpns(vec![IROH_GROUP_INVITE_BUNDLE_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .clear_ip_transports()
            .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .context("Failed to configure iroh public group invite bundle endpoint")?
            .bind()
            .await
            .context("Failed to bind iroh public group invite bundle endpoint")?;
        let bundle_state = Arc::new(RwLock::new(HashMap::<String, GroupInviteBundle>::new()));
        let endpoint_acc = endpoint.clone();
        let bundle_state_acc = Arc::clone(&bundle_state);
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint_acc.accept().await {
                let conn = match incoming.accept() {
                    Ok(accepting) => match accepting.await {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "iroh group invite bundle handshake failed");
                            continue;
                        }
                    },
                    Err(error) => {
                        tracing::debug!(%error, "iroh group invite bundle accept rejected");
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
                            .read_to_end(IROH_GROUP_INVITE_BUNDLE_REQUEST_MAX)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                tracing::debug!(%error, "iroh group invite bundle request read failed");
                                continue;
                            }
                        };
                        let response = match bincode::deserialize::<GroupInviteBundleGetRequest>(
                            &req_bytes,
                        ) {
                            Ok(request) => match request.validate() {
                                Ok(()) => {
                                    let state = bundle_state_conn.read().await;
                                    match state.get(&request.invite_id) {
                                        Some(bundle) => GroupInviteBundleGetResponse::with_bundle(
                                            request.issuer_contact_did.clone(),
                                            request.invite_id.clone(),
                                            bundle.clone(),
                                        ),
                                        None => GroupInviteBundleGetResponse::empty(
                                            request.issuer_contact_did.clone(),
                                            request.invite_id.clone(),
                                        ),
                                    }
                                }
                                Err(error) => {
                                    tracing::debug!(%error, "iroh group invite bundle request invalid");
                                    continue;
                                }
                            },
                            Err(error) => {
                                tracing::debug!(%error, "iroh group invite bundle request decode failed");
                                continue;
                            }
                        };
                        let response_bytes = match bincode::serialize(&response) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                tracing::warn!(%error, "iroh group invite bundle response encode failed");
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
            task: Arc::new(task),
        })
    }

    pub async fn publish(&self, bundle: GroupInviteBundle) {
        let mut state = self.bundle_state.write().await;
        state.insert(bundle.invite_id.clone(), bundle);
    }

    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        let mut addr = self.endpoint.addr();
        addr.addrs
            .retain(|transport| matches!(transport, iroh::TransportAddr::Relay(_)));
        addr
    }
}

pub fn public_group_invite_bundle_secret_bytes(issuer_contact_did: &str) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(IROH_GROUP_INVITE_BUNDLE_SCOPE);
    hasher.update(issuer_contact_did.as_bytes());
    let digest = hasher.finalize();
    let mut derived = [0u8; 32];
    derived.copy_from_slice(&digest[..32]);
    derived
}

pub async fn lookup_group_invite_bundle_via_iroh(
    iroh_config: &IrohConfig,
    issuer_contact_did: &str,
    invite_id: &str,
) -> Result<Option<GroupInviteBundle>> {
    let Some(endpoint_addr) = build_public_iroh_contact_endpoint_addr(
        iroh_config,
        public_group_invite_bundle_secret_bytes(issuer_contact_did),
    )?
    else {
        return Ok(None);
    };
    let relay_mode = relay_mode_from_config_for_discovery(iroh_config)?;
    let client_endpoint = iroh::Endpoint::builder()
        .secret_key(iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
        .alpns(vec![IROH_GROUP_INVITE_BUNDLE_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .clear_ip_transports()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .context("Failed to configure iroh group invite bundle lookup client")?
        .bind()
        .await
        .context("Failed to bind iroh group invite bundle lookup client")?;
    let conn = client_endpoint
        .connect(endpoint_addr, IROH_GROUP_INVITE_BUNDLE_ALPN)
        .await
        .context("iroh group invite bundle lookup connect failed")?;
    let request = GroupInviteBundleGetRequest::new(issuer_contact_did.to_string(), invite_id);
    let request_bytes = bincode::serialize(&request)
        .context("Failed to encode iroh group invite bundle request")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi failed")?;
    send.write_all(&request_bytes)
        .await
        .context("Failed to write iroh group invite bundle request")?;
    send.finish()
        .context("Failed to finish iroh group invite bundle request stream")?;
    let response_bytes = recv
        .read_to_end(IROH_GROUP_INVITE_BUNDLE_RESPONSE_MAX)
        .await
        .context("Failed to read iroh group invite bundle response")?;
    let response: GroupInviteBundleGetResponse = bincode::deserialize(&response_bytes)
        .context("Invalid iroh group invite bundle response")?;
    let bundle = response.into_verified_bundle()?;
    conn.close(0u32.into(), b"qypha-group-invite-bundle-lookup-done");
    client_endpoint.close().await;
    Ok(bundle)
}

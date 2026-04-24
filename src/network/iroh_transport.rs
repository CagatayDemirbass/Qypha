use anyhow::{Context, Result};
use libp2p::PeerId;
use sha2::Digest;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

use crate::config::IrohConfig;
use crate::network::protocol::{AgentRequest, AgentResponse};
use crate::network::IncomingRequestEnvelope;

const IROH_ALPN: &[u8] = b"qypha/agent/iroh/1.0.0";
const IROH_FAST_TRANSFER_ALPN: &[u8] = b"qypha/group-fast-transfer/iroh/1.0.0";
const IROH_REQUEST_SIZE_MAX: usize = 512 * 1024 * 1024;
const IROH_RESPONSE_SIZE_MAX: usize = 10 * 1024 * 1024;
const IROH_FAST_TRANSFER_ENDPOINT_SCOPE: &[u8] = b"qypha-iroh-fast-transfer-endpoint-v1";
const IROH_BIND_RETRY_ATTEMPTS: u32 = 25;
const IROH_BIND_RETRY_DELAY_MS: u64 = 100;
const IROH_SHUTDOWN_CLOSE_PROPAGATION_GRACE_MS: u64 = 750;

/// Build a QUIC transport config for persistent connections.
///
/// Only two things matter:
///   1. Long idle timeout — so the connection survives hours of silence.
///   2. Moderate keep-alive — just enough to prevent NAT/relay eviction
///      without flooding the relay during large file transfers.
///
/// The application-level heartbeat (10 s) handles liveness detection;
/// QUIC-level keep-alive only maintains the network path.
fn build_transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        // 25-second keep-alive: prevents NAT mapping expiry (typically
        // 30–120 s) without saturating the relay when multiple peers
        // are connected and one is doing a large transfer.
        .keep_alive_interval(Duration::from_secs(25))
        // 30-day idle timeout — effectively infinite.  The 25-second
        // keep-alive resets this continuously during normal operation.
        .max_idle_timeout(Some(
            Duration::from_secs(30 * 24 * 3600)
                .try_into()
                .expect("30 days fits in IdleTimeout"),
        ))
        .build()
}

fn filter_endpoint_addr_for_policy(
    mut endpoint_addr: iroh::EndpointAddr,
    allow_direct: bool,
    allow_relay: bool,
) -> Result<iroh::EndpointAddr> {
    endpoint_addr.addrs.retain(|transport| match transport {
        iroh::TransportAddr::Ip(_) => allow_direct,
        iroh::TransportAddr::Relay(_) => allow_relay,
        _ => false,
    });
    if endpoint_addr.addrs.is_empty() {
        if allow_relay && !allow_direct {
            anyhow::bail!("relay-only mode rejected direct-only iroh endpoint");
        }
        anyhow::bail!("iroh endpoint has no transport allowed by local policy");
    }
    Ok(endpoint_addr)
}

fn relay_mode_from_config(iroh_config: &IrohConfig) -> Result<iroh::RelayMode> {
    if !iroh_config.relay_enabled {
        return Ok(iroh::RelayMode::Disabled);
    }

    if iroh_config.relay_urls.is_empty() {
        return Ok(iroh::RelayMode::Default);
    }

    let mut urls = Vec::with_capacity(iroh_config.relay_urls.len());
    for raw in &iroh_config.relay_urls {
        let url = raw
            .parse::<iroh::RelayUrl>()
            .with_context(|| format!("Invalid iroh relay URL '{}'", raw))?;
        urls.push(url);
    }
    Ok(iroh::RelayMode::custom(urls))
}

fn is_addr_in_use_error(error: &iroh::endpoint::BindError) -> bool {
    matches!(
        error,
        iroh::endpoint::BindError::Sockets { source, .. }
            if source.kind() == std::io::ErrorKind::AddrInUse
    )
}

async fn bind_endpoint_with_retry<F>(mut build: F, label: &str) -> Result<iroh::Endpoint>
where
    F: FnMut() -> Result<iroh::endpoint::Builder>,
{
    let mut attempt = 0u32;
    loop {
        let builder = build()?;
        match builder.bind().await {
            Ok(endpoint) => return Ok(endpoint),
            Err(error) if attempt < IROH_BIND_RETRY_ATTEMPTS && is_addr_in_use_error(&error) => {
                attempt += 1;
                tracing::warn!(
                    attempt,
                    label,
                    delay_ms = IROH_BIND_RETRY_DELAY_MS,
                    "iroh bind hit an in-use socket; retrying after bounded backoff"
                );
                tokio::time::sleep(Duration::from_millis(IROH_BIND_RETRY_DELAY_MS)).await;
            }
            Err(error) => {
                return Err(anyhow::Error::new(error))
                    .with_context(|| format!("Failed to bind {label}"));
            }
        }
    }
}

fn derive_fast_transfer_secret_bytes(endpoint_secret_bytes: [u8; 32]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(IROH_FAST_TRANSFER_ENDPOINT_SCOPE);
    hasher.update(endpoint_secret_bytes);
    let digest = hasher.finalize();
    let mut derived = [0u8; 32];
    derived.copy_from_slice(&digest[..32]);
    derived
}

#[derive(Debug, Clone)]
pub enum IrohNetworkEvent {
    ConnectionEstablished {
        peer_id: PeerId,
        stable_id: usize,
    },
    ConnectionClosed {
        peer_id: PeerId,
        stable_id: usize,
        reason: Option<String>,
    },
}

fn reconnect_reset_close_event(
    peer_id: PeerId,
    stable_id: usize,
    close_reason: Option<String>,
) -> Option<IrohNetworkEvent> {
    close_reason.map(|reason| IrohNetworkEvent::ConnectionClosed {
        peer_id,
        stable_id,
        reason: Some(reason),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IrohConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IrohConnectOutcome {
    Established(PeerId),
    ReusedExisting(PeerId),
}

impl IrohConnectOutcome {
    pub fn peer_id(&self) -> PeerId {
        match self {
            Self::Established(peer_id) | Self::ReusedExisting(peer_id) => peer_id.clone(),
        }
    }
}

#[derive(Clone)]
struct TrackedConnection {
    stable_id: usize,
    conn: iroh::endpoint::Connection,
}

#[derive(Clone)]
struct TrackedTransferConnection {
    stable_id: usize,
    conn: iroh::endpoint::Connection,
}

#[derive(Debug, Clone)]
pub struct IrohTransferIncomingRequest {
    pub stable_id: usize,
    pub transfer_id: Option<String>,
    pub request: AgentRequest,
}

pub struct IrohTransport {
    endpoint: iroh::Endpoint,
    fast_transfer_endpoint: Option<iroh::Endpoint>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
    fast_transfer_accept_task: Option<tokio::task::JoinHandle<()>>,
    connections: Arc<Mutex<HashMap<PeerId, TrackedConnection>>>,
    incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    priority_incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    transfer_connections: Arc<Mutex<HashMap<String, TrackedTransferConnection>>>,
    pending_transfer_connections: Arc<Mutex<HashMap<usize, iroh::endpoint::Connection>>>,
    transfer_bindings: Arc<Mutex<HashMap<usize, String>>>,
    transfer_incoming_tx: mpsc::Sender<IrohTransferIncomingRequest>,
    transfer_incoming_rx: Option<mpsc::Receiver<IrohTransferIncomingRequest>>,
    events_tx: mpsc::Sender<IrohNetworkEvent>,
    events_rx: mpsc::Receiver<IrohNetworkEvent>,
    allow_direct: bool,
    allow_relay: bool,
    fast_transfer_allow_relay: bool,
}

fn preferred_iroh_connection_direction(
    local_peer_id: &PeerId,
    remote_peer_id: &PeerId,
) -> IrohConnectionDirection {
    if local_peer_id.to_bytes() < remote_peer_id.to_bytes() {
        IrohConnectionDirection::Outgoing
    } else {
        IrohConnectionDirection::Incoming
    }
}

fn should_replace_tracked_connection(
    local_peer_id: &PeerId,
    remote_peer_id: &PeerId,
    new_direction: IrohConnectionDirection,
    has_existing_connection: bool,
) -> bool {
    !has_existing_connection
        || preferred_iroh_connection_direction(local_peer_id, remote_peer_id) == new_direction
}

fn should_wait_for_shutdown_close_propagation(
    control_connections: usize,
    transfer_connections: usize,
    pending_transfer_connections: usize,
) -> bool {
    control_connections > 0 || transfer_connections > 0 || pending_transfer_connections > 0
}

async fn await_shutdown_close_propagation(close_wait_connections: Vec<iroh::endpoint::Connection>) {
    if close_wait_connections.is_empty() {
        return;
    }
    tokio::task::yield_now().await;
    futures::future::join_all(close_wait_connections.into_iter().map(|conn| async move {
        let _ = tokio::time::timeout(
            Duration::from_millis(IROH_SHUTDOWN_CLOSE_PROPAGATION_GRACE_MS),
            conn.closed(),
        )
        .await;
    }))
    .await;
}

async fn await_disconnect_close_propagation(conn: &iroh::endpoint::Connection) {
    tokio::task::yield_now().await;
    let _ = tokio::time::timeout(
        Duration::from_millis(IROH_SHUTDOWN_CLOSE_PROPAGATION_GRACE_MS),
        conn.closed(),
    )
    .await;
}

async fn propagated_connection_close_reason(conn: &iroh::endpoint::Connection) -> Option<String> {
    let close_reason = conn.close_reason().map(|reason| reason.to_string());
    if close_reason.is_some() {
        return close_reason;
    }
    await_disconnect_close_propagation(conn).await;
    conn.close_reason().map(|reason| reason.to_string())
}

impl IrohTransport {
    pub async fn new(
        listen_port: u16,
        iroh_config: &IrohConfig,
        endpoint_secret_bytes: [u8; 32],
        incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
        priority_incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    ) -> Result<Self> {
        if !iroh_config.direct_enabled && !iroh_config.relay_enabled {
            anyhow::bail!("Invalid iroh config: both direct_enabled and relay_enabled are false.");
        }

        let relay_mode = relay_mode_from_config(iroh_config)?;

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
        let endpoint = bind_endpoint_with_retry(
            || {
                let mut builder = iroh::Endpoint::builder()
                    // Endpoint identity is transport-scoped and does not need to reuse the
                    // agent's long-lived signing key. Safe mode now supplies a separate
                    // persisted secret.
                    .secret_key(iroh::SecretKey::from_bytes(&endpoint_secret_bytes))
                    .alpns(vec![IROH_ALPN.to_vec()])
                    .relay_mode(relay_mode.clone())
                    .transport_config(build_transport_config());
                if !iroh_config.direct_enabled {
                    // Enforce relay-only mode at the transport layer, not just in invite payloads.
                    builder = builder.clear_ip_transports();
                }
                builder
                    .bind_addr(bind_addr)
                    .context("Failed to configure iroh bind address")
            },
            "iroh endpoint",
        )
        .await?;

        let fast_transfer_endpoint = if iroh_config.relay_enabled {
            let fast_secret_bytes = derive_fast_transfer_secret_bytes(endpoint_secret_bytes);
            let fast_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let fast_endpoint = bind_endpoint_with_retry(
                || {
                    iroh::Endpoint::builder()
                        .secret_key(iroh::SecretKey::from_bytes(&fast_secret_bytes))
                        .alpns(vec![IROH_FAST_TRANSFER_ALPN.to_vec()])
                        .relay_mode(relay_mode.clone())
                        .transport_config(build_transport_config())
                        .clear_ip_transports()
                        .bind_addr(fast_bind_addr)
                        .context("Failed to configure iroh fast-transfer bind address")
                },
                "iroh fast-transfer endpoint",
            )
            .await?;
            Some(fast_endpoint)
        } else {
            None
        };

        let connections: Arc<Mutex<HashMap<PeerId, TrackedConnection>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let transfer_connections: Arc<Mutex<HashMap<String, TrackedTransferConnection>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_transfer_connections: Arc<Mutex<HashMap<usize, iroh::endpoint::Connection>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let transfer_bindings: Arc<Mutex<HashMap<usize, String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (transfer_incoming_tx, transfer_incoming_rx) =
            mpsc::channel::<IrohTransferIncomingRequest>(256);
        let (events_tx, events_rx) = mpsc::channel::<IrohNetworkEvent>(256);

        // Accept-side task: accepts incoming control-plane iroh connections and forwards requests.
        let accept_task = {
            let endpoint_acc = endpoint.clone();
            let connections_acc = Arc::clone(&connections);
            let events_tx_acc = events_tx.clone();
            let incoming_tx_acc = incoming_tx.clone();
            let priority_incoming_tx_acc = priority_incoming_tx.clone();
            let local_peer_id = peer_id_from_endpoint_id(&endpoint_acc.id());

            tokio::spawn(async move {
                while let Some(incoming) = endpoint_acc.accept().await {
                    let conn = match incoming.accept() {
                        Ok(accepting) => match accepting.await {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!(%e, "iroh incoming handshake failed");
                                continue;
                            }
                        },
                        Err(e) => {
                            tracing::debug!(%e, "iroh incoming accept() rejected");
                            continue;
                        }
                    };

                    let stable_id = conn.stable_id();
                    let peer_id = peer_id_from_endpoint_id(&conn.remote_id());
                    {
                        let mut map = connections_acc.lock().await;
                        if !should_replace_tracked_connection(
                            &local_peer_id,
                            &peer_id,
                            IrohConnectionDirection::Incoming,
                            map.contains_key(&peer_id),
                        ) {
                            tracing::debug!(
                                peer = %peer_id,
                                stable_id,
                                "rejecting duplicate incoming iroh connection in favor of existing preferred live session"
                            );
                            drop(map);
                            conn.close(0u32.into(), b"qypha-duplicate-connection-rejected");
                            continue;
                        }
                        let replaced = map.insert(
                            peer_id,
                            TrackedConnection {
                                stable_id,
                                conn: conn.clone(),
                            },
                        );
                        if let Some(old) = replaced {
                            old.conn.close(0u32.into(), b"qypha-connection-replaced");
                        }
                    }

                    let _ = events_tx_acc
                        .send(IrohNetworkEvent::ConnectionEstablished { peer_id, stable_id })
                        .await;

                    spawn_connection_reader(
                        peer_id,
                        stable_id,
                        conn,
                        Arc::clone(&connections_acc),
                        incoming_tx_acc.clone(),
                        priority_incoming_tx_acc.clone(),
                        events_tx_acc.clone(),
                    );
                }
            })
        };

        let fast_transfer_accept_task = if let Some(fast_endpoint_acc) =
            fast_transfer_endpoint.clone()
        {
            let transfer_connections_acc = Arc::clone(&transfer_connections);
            let pending_transfer_connections_acc = Arc::clone(&pending_transfer_connections);
            let transfer_bindings_acc = Arc::clone(&transfer_bindings);
            let transfer_incoming_tx_acc = transfer_incoming_tx.clone();

            Some(tokio::spawn(async move {
                while let Some(incoming) = fast_endpoint_acc.accept().await {
                    let conn = match incoming.accept() {
                        Ok(accepting) => match accepting.await {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!(%e, "iroh fast-transfer incoming handshake failed");
                                continue;
                            }
                        },
                        Err(e) => {
                            tracing::debug!(%e, "iroh fast-transfer incoming accept() rejected");
                            continue;
                        }
                    };

                    let stable_id = conn.stable_id();
                    pending_transfer_connections_acc
                        .lock()
                        .await
                        .insert(stable_id, conn.clone());
                    spawn_transfer_connection_reader(
                        stable_id,
                        conn,
                        Arc::clone(&transfer_connections_acc),
                        Arc::clone(&pending_transfer_connections_acc),
                        Arc::clone(&transfer_bindings_acc),
                        transfer_incoming_tx_acc.clone(),
                    );
                }
            }))
        } else {
            None
        };

        Ok(Self {
            endpoint,
            fast_transfer_endpoint,
            accept_task: Some(accept_task),
            fast_transfer_accept_task,
            connections,
            incoming_tx,
            priority_incoming_tx,
            transfer_connections,
            pending_transfer_connections,
            transfer_bindings,
            transfer_incoming_tx,
            transfer_incoming_rx: Some(transfer_incoming_rx),
            events_tx,
            events_rx,
            allow_direct: iroh_config.direct_enabled,
            allow_relay: iroh_config.relay_enabled,
            fast_transfer_allow_relay: iroh_config.relay_enabled,
        })
    }

    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    pub fn logical_peer_id(&self) -> PeerId {
        peer_id_from_endpoint_id(&self.endpoint.id())
    }

    pub fn endpoint_addr_for_invite(&self, hide_direct_ip: bool) -> iroh::EndpointAddr {
        let mut addr = self.endpoint.addr();
        addr.addrs.retain(|transport| match transport {
            iroh::TransportAddr::Ip(_) => self.allow_direct && !hide_direct_ip,
            iroh::TransportAddr::Relay(_) => self.allow_relay,
            _ => false,
        });
        addr
    }

    pub fn fast_transfer_endpoint_addr_for_grant(&self) -> Option<iroh::EndpointAddr> {
        if !self.fast_transfer_allow_relay {
            return None;
        }
        let endpoint = self.fast_transfer_endpoint.as_ref()?;
        let mut addr = endpoint.addr();
        addr.addrs
            .retain(|transport| matches!(transport, iroh::TransportAddr::Relay(_)));
        (!addr.addrs.is_empty()).then_some(addr)
    }

    pub async fn connect(&self, endpoint_addr: iroh::EndpointAddr) -> Result<IrohConnectOutcome> {
        let endpoint_addr = self
            .filter_endpoint_addr_for_connect(endpoint_addr)
            .context("iroh endpoint rejected by local transport policy")?;
        let conn = self
            .endpoint
            .connect(endpoint_addr, IROH_ALPN)
            .await
            .context("iroh connect failed")?;
        let peer_id = peer_id_from_endpoint_id(&conn.remote_id());
        let stable_id = conn.stable_id();
        let local_peer_id = self.logical_peer_id();

        {
            let mut map = self.connections.lock().await;
            if !should_replace_tracked_connection(
                &local_peer_id,
                &peer_id,
                IrohConnectionDirection::Outgoing,
                map.contains_key(&peer_id),
            ) {
                tracing::debug!(
                    peer = %peer_id,
                    stable_id,
                    "suppressing duplicate outgoing iroh connection in favor of existing preferred live session"
                );
                drop(map);
                conn.close(0u32.into(), b"qypha-duplicate-connection-reused");
                return Ok(IrohConnectOutcome::ReusedExisting(peer_id));
            }
            let replaced = map.insert(
                peer_id,
                TrackedConnection {
                    stable_id,
                    conn: conn.clone(),
                },
            );
            if let Some(old) = replaced {
                old.conn.close(0u32.into(), b"qypha-connection-replaced");
            }
        }

        spawn_connection_reader(
            peer_id,
            stable_id,
            conn,
            Arc::clone(&self.connections),
            self.incoming_tx.clone(),
            self.priority_incoming_tx.clone(),
            self.events_tx.clone(),
        );

        let _ = self
            .events_tx
            .send(IrohNetworkEvent::ConnectionEstablished { peer_id, stable_id })
            .await;
        Ok(IrohConnectOutcome::Established(peer_id))
    }

    pub async fn connect_transfer(
        &self,
        transfer_id: &str,
        endpoint_addr: iroh::EndpointAddr,
    ) -> Result<()> {
        let endpoint = self
            .fast_transfer_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("iroh fast-transfer endpoint is unavailable"))?;
        let endpoint_addr =
            filter_endpoint_addr_for_policy(endpoint_addr, false, self.fast_transfer_allow_relay)
                .context("iroh fast-transfer endpoint rejected by local transport policy")?;
        let conn = endpoint
            .connect(endpoint_addr, IROH_FAST_TRANSFER_ALPN)
            .await
            .context("iroh fast-transfer connect failed")?;
        let stable_id = conn.stable_id();
        {
            self.transfer_bindings
                .lock()
                .await
                .insert(stable_id, transfer_id.to_string());
            let mut map = self.transfer_connections.lock().await;
            let replaced = map.insert(
                transfer_id.to_string(),
                TrackedTransferConnection {
                    stable_id,
                    conn: conn.clone(),
                },
            );
            if let Some(old) = replaced {
                old.conn.close(0u32.into(), b"qypha-fast-transfer-replaced");
            }
        }
        spawn_transfer_connection_reader(
            stable_id,
            conn,
            Arc::clone(&self.transfer_connections),
            Arc::clone(&self.pending_transfer_connections),
            Arc::clone(&self.transfer_bindings),
            self.transfer_incoming_tx.clone(),
        );
        Ok(())
    }

    pub async fn bind_incoming_transfer_connection(
        &self,
        stable_id: usize,
        transfer_id: &str,
    ) -> Result<()> {
        let conn = self
            .pending_transfer_connections
            .lock()
            .await
            .remove(&stable_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No pending fast-transfer connection for stable_id {}",
                    stable_id
                )
            })?;
        self.transfer_bindings
            .lock()
            .await
            .insert(stable_id, transfer_id.to_string());
        let mut map = self.transfer_connections.lock().await;
        let replaced = map.insert(
            transfer_id.to_string(),
            TrackedTransferConnection {
                stable_id,
                conn: conn.clone(),
            },
        );
        if let Some(old) = replaced {
            old.conn.close(0u32.into(), b"qypha-fast-transfer-replaced");
        }
        Ok(())
    }

    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        request: &AgentRequest,
    ) -> Result<AgentResponse> {
        let conn = {
            let map = self.connections.lock().await;
            map.get(peer_id).map(|tracked| tracked.conn.clone())
        }
        .ok_or_else(|| anyhow::anyhow!("No active iroh connection for peer {}", peer_id))?;

        let payload = bincode::serialize(request).context("serialize request failed")?;
        if payload.len() > IROH_REQUEST_SIZE_MAX {
            anyhow::bail!(
                "request too large: {} bytes exceeds {}",
                payload.len(),
                IROH_REQUEST_SIZE_MAX
            );
        }

        let (mut send, mut recv) = conn.open_bi().await.context("open_bi failed")?;
        send.write_all(&payload)
            .await
            .context("write request failed")?;
        send.finish().context("finish request stream failed")?;

        let resp_bytes = recv
            .read_to_end(IROH_RESPONSE_SIZE_MAX)
            .await
            .context("read response failed")?;
        let response: AgentResponse =
            bincode::deserialize(&resp_bytes).context("deserialize response failed")?;
        Ok(response)
    }

    pub async fn send_request_without_response(
        &self,
        peer_id: &PeerId,
        request: &AgentRequest,
    ) -> Result<()> {
        let conn = {
            let map = self.connections.lock().await;
            map.get(peer_id).map(|tracked| tracked.conn.clone())
        }
        .ok_or_else(|| anyhow::anyhow!("No active iroh connection for peer {}", peer_id))?;

        let payload = bincode::serialize(request).context("serialize request failed")?;
        if payload.len() > IROH_REQUEST_SIZE_MAX {
            anyhow::bail!(
                "request too large: {} bytes exceeds {}",
                payload.len(),
                IROH_REQUEST_SIZE_MAX
            );
        }

        let (mut send, _recv) = conn.open_bi().await.context("open_bi failed")?;
        send.write_all(&payload)
            .await
            .context("write request failed")?;
        send.finish().context("finish request stream failed")?;
        Ok(())
    }

    pub async fn send_transfer_request(
        &self,
        transfer_id: &str,
        request: &AgentRequest,
    ) -> Result<AgentResponse> {
        let conn = {
            let map = self.transfer_connections.lock().await;
            map.get(transfer_id).map(|tracked| tracked.conn.clone())
        }
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No active iroh fast-transfer connection for {}",
                transfer_id
            )
        })?;

        let payload = bincode::serialize(request).context("serialize transfer request failed")?;
        if payload.len() > IROH_REQUEST_SIZE_MAX {
            anyhow::bail!(
                "transfer request too large: {} bytes exceeds {}",
                payload.len(),
                IROH_REQUEST_SIZE_MAX
            );
        }

        let (mut send, mut recv) = conn.open_bi().await.context("open_bi failed")?;
        send.write_all(&payload)
            .await
            .context("write transfer request failed")?;
        send.finish()
            .context("finish transfer request stream failed")?;

        let resp_bytes = recv
            .read_to_end(IROH_RESPONSE_SIZE_MAX)
            .await
            .context("read transfer response failed")?;
        let response: AgentResponse =
            bincode::deserialize(&resp_bytes).context("deserialize transfer response failed")?;
        Ok(response)
    }

    pub async fn disconnect_transfer(&self, transfer_id: &str) {
        let tracked = {
            let mut map = self.transfer_connections.lock().await;
            map.remove(transfer_id)
        };
        if let Some(tracked) = tracked {
            self.transfer_bindings
                .lock()
                .await
                .remove(&tracked.stable_id);
            tracked
                .conn
                .close(0u32.into(), b"qypha-fast-transfer-disconnect");
        }
    }

    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        let conn = {
            let map = self.connections.lock().await;
            map.get(peer_id).map(|tracked| tracked.conn.clone())
        };
        conn.is_some_and(|c| c.close_reason().is_none())
    }

    pub async fn current_stable_id(&self, peer_id: &PeerId) -> Option<usize> {
        let map = self.connections.lock().await;
        map.get(peer_id).map(|tracked| tracked.stable_id)
    }

    pub async fn disconnect(&self, peer_id: &PeerId) {
        let tracked = {
            let mut map = self.connections.lock().await;
            map.remove(peer_id)
        };
        if let Some(tracked) = tracked {
            tracked.conn.close(0u32.into(), b"qypha-policy-disconnect");
            let _ = self
                .events_tx
                .send(IrohNetworkEvent::ConnectionClosed {
                    peer_id: *peer_id,
                    stable_id: tracked.stable_id,
                    reason: Some("qypha-policy-disconnect".to_string()),
                })
                .await;
        }
    }

    pub async fn disconnect_with_propagation(&self, peer_id: &PeerId) {
        let tracked = {
            let mut map = self.connections.lock().await;
            map.remove(peer_id)
        };
        if let Some(tracked) = tracked {
            tracked.conn.close(0u32.into(), b"qypha-manual-disconnect");
            let _ = self
                .events_tx
                .send(IrohNetworkEvent::ConnectionClosed {
                    peer_id: *peer_id,
                    stable_id: tracked.stable_id,
                    reason: Some("qypha-manual-disconnect".to_string()),
                })
                .await;
            await_disconnect_close_propagation(&tracked.conn).await;
        }
    }

    pub async fn reset_for_reconnect(&self, peer_id: &PeerId) {
        let tracked = {
            let mut map = self.connections.lock().await;
            map.remove(peer_id)
        };
        if let Some(tracked) = tracked {
            let mut close_event = reconnect_reset_close_event(
                *peer_id,
                tracked.stable_id,
                tracked.conn.close_reason().map(|reason| reason.to_string()),
            );
            if close_event.is_none() {
                await_disconnect_close_propagation(&tracked.conn).await;
                close_event = reconnect_reset_close_event(
                    *peer_id,
                    tracked.stable_id,
                    tracked.conn.close_reason().map(|reason| reason.to_string()),
                );
            }
            if close_event.is_none() {
                tracked.conn.close(0u32.into(), b"qypha-reconnect-reset");
            }
            if let Some(event) = close_event {
                let _ = self.events_tx.send(event).await;
            }
        }
    }

    pub async fn shutdown(&mut self) {
        let connections = {
            let mut map = self.connections.lock().await;
            std::mem::take(&mut *map)
        };
        let transfer_connections = {
            let mut map = self.transfer_connections.lock().await;
            std::mem::take(&mut *map)
        };
        let pending_transfer_connections = {
            let mut map = self.pending_transfer_connections.lock().await;
            std::mem::take(&mut *map)
        };
        {
            let mut bindings = self.transfer_bindings.lock().await;
            bindings.clear();
        }
        let control_connection_count = connections.len();
        let transfer_connection_count = transfer_connections.len();
        let pending_transfer_connection_count = pending_transfer_connections.len();
        let mut close_wait_connections = Vec::with_capacity(
            control_connection_count
                + transfer_connection_count
                + pending_transfer_connection_count,
        );

        for tracked in transfer_connections.into_values() {
            close_wait_connections.push(tracked.conn.clone());
            tracked
                .conn
                .close(0u32.into(), b"qypha-fast-transfer-shutdown");
        }
        for conn in pending_transfer_connections.into_values() {
            close_wait_connections.push(conn.clone());
            conn.close(0u32.into(), b"qypha-fast-transfer-shutdown");
        }
        for (peer_id, tracked) in connections {
            close_wait_connections.push(tracked.conn.clone());
            tracked.conn.close(0u32.into(), b"qypha-agent-shutdown");
            let _ = self
                .events_tx
                .send(IrohNetworkEvent::ConnectionClosed {
                    peer_id,
                    stable_id: tracked.stable_id,
                    reason: Some("qypha-agent-shutdown".to_string()),
                })
                .await;
        }

        if should_wait_for_shutdown_close_propagation(
            control_connection_count,
            transfer_connection_count,
            pending_transfer_connection_count,
        ) {
            await_shutdown_close_propagation(close_wait_connections).await;
        }

        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.fast_transfer_accept_task.take() {
            task.abort();
            let _ = task.await;
        }

        if let Some(endpoint) = self.fast_transfer_endpoint.as_ref() {
            if !endpoint.is_closed() {
                endpoint.close().await;
            }
        }
        if !self.endpoint.is_closed() {
            self.endpoint.close().await;
        }
    }

    pub async fn next_event(&mut self) -> Option<IrohNetworkEvent> {
        self.events_rx.recv().await
    }

    pub fn take_transfer_request_rx(
        &mut self,
    ) -> Option<mpsc::Receiver<IrohTransferIncomingRequest>> {
        self.transfer_incoming_rx.take()
    }

    pub async fn next_transfer_request(&mut self) -> Option<IrohTransferIncomingRequest> {
        match self.transfer_incoming_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    fn filter_endpoint_addr_for_connect(
        &self,
        endpoint_addr: iroh::EndpointAddr,
    ) -> Result<iroh::EndpointAddr> {
        filter_endpoint_addr_for_policy(endpoint_addr, self.allow_direct, self.allow_relay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::sync::mpsc;

    fn sample_peer_id(seed: u8) -> PeerId {
        peer_id_from_endpoint_id(&iroh::SecretKey::from_bytes(&[seed; 32]).public())
    }

    fn sample_endpoint_addr() -> iroh::EndpointAddr {
        let endpoint_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777)),
                iroh::TransportAddr::Relay(
                    "https://relay.example.test"
                        .parse::<iroh::RelayUrl>()
                        .expect("valid relay url"),
                ),
            ],
        )
    }

    #[test]
    fn relay_only_policy_drops_ip_transports() {
        let filtered = filter_endpoint_addr_for_policy(sample_endpoint_addr(), false, true)
            .expect("relay-only endpoint should remain dialable");
        assert_eq!(filtered.ip_addrs().count(), 0);
        assert_eq!(filtered.relay_urls().count(), 1);
    }

    #[test]
    fn relay_only_policy_rejects_direct_only_endpoint() {
        let endpoint_id = iroh::SecretKey::from_bytes(&[11u8; 32]).public();
        let direct_only = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [iroh::TransportAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                7777,
            ))],
        );
        let err = filter_endpoint_addr_for_policy(direct_only, false, true)
            .expect_err("direct-only endpoint must fail closed in relay-only mode");
        assert!(err.to_string().contains("relay-only"));
    }

    #[test]
    fn preferred_connection_direction_is_deterministic_and_symmetric() {
        let peer_a = sample_peer_id(21);
        let peer_b = sample_peer_id(42);
        let (lower, higher) = if peer_a.to_bytes() < peer_b.to_bytes() {
            (peer_a, peer_b)
        } else {
            (peer_b, peer_a)
        };

        assert_eq!(
            preferred_iroh_connection_direction(&lower, &higher),
            IrohConnectionDirection::Outgoing
        );
        assert_eq!(
            preferred_iroh_connection_direction(&higher, &lower),
            IrohConnectionDirection::Incoming
        );
    }

    #[test]
    fn duplicate_connection_policy_prefers_single_shared_direction() {
        let peer_a = sample_peer_id(31);
        let peer_b = sample_peer_id(32);
        let (lower, higher) = if peer_a.to_bytes() < peer_b.to_bytes() {
            (peer_a, peer_b)
        } else {
            (peer_b, peer_a)
        };

        assert!(should_replace_tracked_connection(
            &lower,
            &higher,
            IrohConnectionDirection::Outgoing,
            false,
        ));
        assert!(!should_replace_tracked_connection(
            &lower,
            &higher,
            IrohConnectionDirection::Incoming,
            true,
        ));
        assert!(should_replace_tracked_connection(
            &higher,
            &lower,
            IrohConnectionDirection::Incoming,
            true,
        ));
        assert!(!should_replace_tracked_connection(
            &higher,
            &lower,
            IrohConnectionDirection::Outgoing,
            true,
        ));
    }

    #[test]
    fn reconnect_reset_forwards_existing_remote_close_reason() {
        let peer_id = sample_peer_id(33);
        let event = reconnect_reset_close_event(
            peer_id,
            7,
            Some("stream closed: qypha-agent-shutdown".to_string()),
        )
        .expect("existing close reason should become an event");

        match event {
            IrohNetworkEvent::ConnectionClosed {
                peer_id,
                stable_id: 7,
                reason: Some(reason),
            } if peer_id == sample_peer_id(33)
                && reason == "stream closed: qypha-agent-shutdown" => {}
            other => panic!("unexpected event: {other:?}"),
        }

        assert!(reconnect_reset_close_event(peer_id, 7, None).is_none());
    }

    #[test]
    fn shutdown_close_propagation_wait_depends_on_live_connections() {
        assert!(should_wait_for_shutdown_close_propagation(1, 0, 0));
        assert!(should_wait_for_shutdown_close_propagation(0, 1, 0));
        assert!(should_wait_for_shutdown_close_propagation(0, 0, 1));
        assert!(!should_wait_for_shutdown_close_propagation(0, 0, 0));
    }

    #[tokio::test]
    async fn shutdown_releases_bound_port() {
        let reserve = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve ephemeral udp port");
        let listen_port = reserve.local_addr().expect("reserved socket addr").port();
        drop(reserve);

        let (incoming_tx, _incoming_rx) = mpsc::channel(8);
        let (priority_incoming_tx, _priority_incoming_rx) = mpsc::channel(8);
        let iroh_config = IrohConfig {
            relay_enabled: false,
            direct_enabled: true,
            relay_urls: vec![],
        };
        let mut first = IrohTransport::new(
            listen_port,
            &iroh_config,
            [7u8; 32],
            incoming_tx,
            priority_incoming_tx,
        )
        .await
        .expect("first iroh transport should bind");
        first.shutdown().await;
        drop(first);

        let (incoming_tx_second, _incoming_rx_second) = mpsc::channel(8);
        let (priority_incoming_tx_second, _priority_incoming_rx_second) = mpsc::channel(8);
        let mut second = IrohTransport::new(
            listen_port,
            &iroh_config,
            [9u8; 32],
            incoming_tx_second,
            priority_incoming_tx_second,
        )
        .await
        .expect("shutdown must release iroh listen port");
        second.shutdown().await;
    }

    #[tokio::test]
    async fn send_request_without_response_delivers_envelope() {
        let (incoming_tx_a, _incoming_rx_a) = mpsc::channel(8);
        let (priority_incoming_tx_a, mut priority_incoming_rx_a) = mpsc::channel(8);
        let (incoming_tx_b, _incoming_rx_b) = mpsc::channel(8);
        let (priority_incoming_tx_b, _priority_incoming_rx_b) = mpsc::channel(8);
        let iroh_config = IrohConfig {
            relay_enabled: false,
            direct_enabled: true,
            relay_urls: vec![],
        };

        let mut receiver = IrohTransport::new(
            0,
            &iroh_config,
            [11u8; 32],
            incoming_tx_a,
            priority_incoming_tx_a,
        )
        .await
        .expect("receiver transport");
        let mut sender = IrohTransport::new(
            0,
            &iroh_config,
            [12u8; 32],
            incoming_tx_b,
            priority_incoming_tx_b,
        )
        .await
        .expect("sender transport");

        sender
            .connect(receiver.endpoint_addr_for_invite(false))
            .await
            .expect("connect sender -> receiver");

        let request = AgentRequest {
            message_id: "msg_shutdown_notice".to_string(),
            sender_did: "did:nxf:test_sender".to_string(),
            sender_name: "sender".to_string(),
            sender_role: "peer".to_string(),
            msg_type: crate::network::protocol::MessageKind::DisconnectNotice,
            payload: vec![1, 2, 3],
            signature: vec![],
            nonce: 7,
            timestamp: 11,
            ttl_ms: 30_000,
        };
        let peer_id = receiver.logical_peer_id();

        sender
            .send_request_without_response(&peer_id, &request)
            .await
            .expect("one-way request should be written");

        let envelope = tokio::time::timeout(Duration::from_secs(2), priority_incoming_rx_a.recv())
            .await
            .expect("receiver should get request in time")
            .expect("receiver envelope");
        assert_eq!(envelope.peer_id, sender.logical_peer_id());
        assert_eq!(envelope.request.message_id, request.message_id);
        assert_eq!(envelope.request.msg_type, request.msg_type);

        sender.shutdown().await;
        receiver.shutdown().await;
    }
}

fn spawn_connection_reader(
    peer_id: PeerId,
    stable_id: usize,
    conn: iroh::endpoint::Connection,
    connections: Arc<Mutex<HashMap<PeerId, TrackedConnection>>>,
    incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    priority_incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    events_tx: mpsc::Sender<IrohNetworkEvent>,
) {
    tokio::spawn(async move {
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    tracing::debug!(peer = %peer_id, %e, "iroh accept_bi ended");
                    break;
                }
            };

            let req_bytes = match recv.read_to_end(IROH_REQUEST_SIZE_MAX).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(peer = %peer_id, %e, "iroh request read failed");
                    continue;
                }
            };

            let request: AgentRequest = match bincode::deserialize(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(peer = %peer_id, %e, "iroh request decode failed");
                    continue;
                }
            };

            let active_session = {
                let map = connections.lock().await;
                map.get(&peer_id)
                    .is_some_and(|tracked| tracked.stable_id == stable_id)
            };

            let envelope = IncomingRequestEnvelope {
                peer_id,
                request,
                iroh_stable_id: Some(stable_id),
                iroh_active_session: Some(active_session),
            };
            let target_tx = if matches!(
                envelope.request.msg_type,
                crate::network::protocol::MessageKind::DisconnectNotice
            ) {
                &priority_incoming_tx
            } else {
                &incoming_tx
            };
            let _ = target_tx.send(envelope).await;

            let response = AgentResponse {
                success: true,
                message: "OK".to_string(),
            };
            let response_bytes = match bincode::serialize(&response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(peer = %peer_id, %e, "iroh response encode failed");
                    continue;
                }
            };

            if send.write_all(&response_bytes).await.is_err() {
                continue;
            }
            let _ = send.finish();
        }

        let close_reason = propagated_connection_close_reason(&conn).await;
        let mut emit_closed_event = false;
        {
            let mut map = connections.lock().await;
            let remove_active = map
                .get(&peer_id)
                .is_some_and(|tracked| tracked.stable_id == stable_id);
            if remove_active {
                map.remove(&peer_id);
                emit_closed_event = true;
            } else {
                tracing::debug!(
                    peer = %peer_id,
                    stable_id,
                    "stale iroh connection closed; active connection remains"
                );
            }
        }
        if emit_closed_event {
            let _ = events_tx
                .send(IrohNetworkEvent::ConnectionClosed {
                    peer_id,
                    stable_id,
                    reason: close_reason,
                })
                .await;
        }
    });
}

fn spawn_transfer_connection_reader(
    stable_id: usize,
    conn: iroh::endpoint::Connection,
    transfer_connections: Arc<Mutex<HashMap<String, TrackedTransferConnection>>>,
    pending_transfer_connections: Arc<Mutex<HashMap<usize, iroh::endpoint::Connection>>>,
    transfer_bindings: Arc<Mutex<HashMap<usize, String>>>,
    transfer_incoming_tx: mpsc::Sender<IrohTransferIncomingRequest>,
) {
    tokio::spawn(async move {
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    tracing::debug!(stable_id, %e, "iroh fast-transfer accept_bi ended");
                    break;
                }
            };

            let req_bytes = match recv.read_to_end(IROH_REQUEST_SIZE_MAX).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(stable_id, %e, "iroh fast-transfer request read failed");
                    continue;
                }
            };

            let request: AgentRequest = match bincode::deserialize(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(stable_id, %e, "iroh fast-transfer request decode failed");
                    continue;
                }
            };

            let transfer_id = {
                let bindings = transfer_bindings.lock().await;
                bindings.get(&stable_id).cloned()
            };

            let _ = transfer_incoming_tx
                .send(IrohTransferIncomingRequest {
                    stable_id,
                    transfer_id,
                    request,
                })
                .await;

            let response = AgentResponse {
                success: true,
                message: "OK".to_string(),
            };
            let response_bytes = match bincode::serialize(&response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(stable_id, %e, "iroh fast-transfer response encode failed");
                    continue;
                }
            };

            if send.write_all(&response_bytes).await.is_err() {
                continue;
            }
            let _ = send.finish();
        }

        let bound_transfer_id = transfer_bindings.lock().await.remove(&stable_id);
        pending_transfer_connections.lock().await.remove(&stable_id);
        if let Some(transfer_id) = bound_transfer_id {
            let mut map = transfer_connections.lock().await;
            let remove_active = map
                .get(&transfer_id)
                .is_some_and(|tracked| tracked.stable_id == stable_id);
            if remove_active {
                map.remove(&transfer_id);
            }
        }
    });
}

pub fn peer_id_from_endpoint_id(endpoint_id: &iroh::EndpointId) -> PeerId {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"NXF_IROH_PEERID_V1");
    hasher.update(endpoint_id.as_bytes());
    let digest = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    if let Ok(keypair) = libp2p::identity::Keypair::ed25519_from_bytes(seed) {
        return PeerId::from_public_key(&keypair.public());
    }

    if let Ok(multihash) = libp2p::multihash::Multihash::<64>::wrap(0x12, &digest[..32]) {
        if let Ok(peer_id) = PeerId::from_multihash(multihash) {
            return peer_id;
        }
    }

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    PeerId::from_public_key(&keypair.public())
}

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    identity, kad, mdns, noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use super::codec::LargeCborCodec;
use super::protocol::{AgentRequest, AgentResponse, MessageKind};
use super::tor_transport::{TorManager, TorServiceRole};
use super::IncomingRequestEnvelope;
use crate::config::{TorConfig, TransportMode};
use crate::crypto::keystore::KeyStore;

/// Combined network behaviour for Qypha agents.
///
/// mDNS is wrapped in Toggle so it can be disabled in Tor mode
/// (mDNS broadcasts would leak the agent's local IP address).
#[derive(NetworkBehaviour)]
pub struct AgentBehaviour {
    /// Ping: keeps connections alive and measures latency
    pub ping: ping::Behaviour,

    /// mDNS for local peer discovery (same LAN) — disabled in Tor mode
    pub mdns: Toggle<mdns::tokio::Behaviour>,

    /// Kademlia DHT for cross-network peer discovery — disabled in Tor mode
    /// (DHT queries leak peer association graphs and enable traffic correlation attacks)
    pub kademlia: Toggle<kad::Behaviour<kad::store::MemoryStore>>,

    /// Request-Response for agent-to-agent encrypted messages (custom codec with 100 MB limit)
    pub messaging: request_response::Behaviour<LargeCborCodec<AgentRequest, AgentResponse>>,
}

/// The P2P network node for an agent
pub struct NetworkNode {
    pub peer_id: PeerId,
    pub swarm: Swarm<AgentBehaviour>,
    pub known_peers: HashMap<String, PeerId>, // DID -> PeerId mapping
    /// Transport mode this node is running in
    pub transport_mode: TransportMode,
    /// Our .onion v3 address (if Tor mode)
    pub onion_address: Option<String>,
    /// Embedded Tor client manager (if Tor mode)
    pub tor_manager: Option<Arc<TorManager>>,
    /// DID -> .onion address mapping (populated from invites/handshakes)
    pub onion_peers: HashMap<String, String>,
}

impl NetworkNode {
    /// Create and start a new network node.
    ///
    /// Supports three transport modes:
    /// - **Tcp**: Standard TCP on all interfaces, mDNS enabled (LAN only)
    /// - **Tor**: TCP on localhost only, mDNS disabled, Arti onion service running
    /// - **Internet**: TCP on all interfaces, mDNS enabled, invite system for WAN peers
    pub async fn new(
        listen_port: u16,
        transport_mode: TransportMode,
        tor_config: Option<&TorConfig>,
        agent_name: &str,
    ) -> Result<Self> {
        // Generate libp2p identity (separate from agent Ed25519 — this is transport-level)
        let local_key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        tracing::info!(%peer_id, ?transport_mode, "Creating P2P network node");

        // Bootstrap Tor if needed
        let tor_manager = if matches!(transport_mode, TransportMode::Tor) {
            let tc =
                tor_config.ok_or_else(|| anyhow::anyhow!("Tor config required for Tor mode"))?;

            let tor_data_dir = tc
                .data_dir
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    KeyStore::agent_tor_dir(agent_name)
                        .unwrap_or_else(|_| std::path::PathBuf::from("./tor"))
                });

            std::fs::create_dir_all(&tor_data_dir)?;

            let mgr = TorManager::bootstrap(
                &tor_data_dir,
                listen_port,
                tc.circuit_timeout_secs,
                TorServiceRole::DirectPeer,
            )
            .await?;

            Some(Arc::new(mgr))
        } else {
            None
        };

        // Determine whether mDNS should be enabled.
        // Tor mode: DISABLED (IP leak prevention)
        // Tcp/Internet: ENABLED
        let enable_mdns = !matches!(transport_mode, TransportMode::Tor);

        if matches!(transport_mode, TransportMode::Tor) {
            tracing::info!(?transport_mode, "mDNS force-disabled (IP leak prevention)");
        }

        // Helper: build common behaviour components
        let build_common = |key: &identity::Keypair,
                            transport_mode: &TransportMode,
                            enable_mdns: bool|
         -> Result<
            (
                ping::Behaviour,
                Toggle<mdns::tokio::Behaviour>,
                Toggle<kad::Behaviour<kad::store::MemoryStore>>,
                request_response::Behaviour<LargeCborCodec<AgentRequest, AgentResponse>>,
            ),
            Box<dyn std::error::Error + Send + Sync>,
        > {
            let peer_id = PeerId::from(key.public());

            // Ping acts as the primary keep-alive for TCP connections.
            // Sending every 15 s ensures the idle-connection timer (6 h) is
            // continuously reset, so connections survive hours of inactivity
            // just like WhatsApp.  The 30 s timeout is generous enough to
            // tolerate Tor-routed latency spikes.
            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(30)),
            );

            let mdns = if enable_mdns {
                Toggle::from(Some(mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    peer_id,
                )?))
            } else {
                Toggle::from(None)
            };

            let kademlia = if enable_mdns {
                let store = kad::store::MemoryStore::new(peer_id);
                Toggle::from(Some(kad::Behaviour::new(peer_id, store)))
            } else {
                tracing::info!(
                    ?transport_mode,
                    "Kademlia DHT force-disabled (metadata leak prevention)"
                );
                Toggle::from(None)
            };

            let messaging = request_response::Behaviour::with_codec(
                LargeCborCodec::<AgentRequest, AgentResponse>::default(),
                [(
                    StreamProtocol::new("/qypha/agent/1.0.0"),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default().with_request_timeout(Duration::from_secs(300)),
            );

            Ok((ping, mdns, kademlia, messaging))
        };

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let (ping, mdns, kademlia, messaging) =
                    build_common(key, &transport_mode, enable_mdns)?;
                Ok(AgentBehaviour {
                    ping,
                    mdns,
                    kademlia,
                    messaging,
                })
            })?
            .with_swarm_config(|cfg| {
                // Effectively infinite idle timeout (30 days). Ping keep-alive
                // (every 15 s) resets the timer continuously. Connections only
                // end on explicit /disconnect — never on inactivity.
                cfg.with_idle_connection_timeout(Duration::from_secs(30 * 24 * 3600))
            })
            .build();

        let onion_address = tor_manager.as_ref().map(|m| m.onion_address().to_string());

        let mut node = Self {
            peer_id,
            swarm,
            known_peers: HashMap::new(),
            transport_mode,
            onion_address,
            tor_manager,
            onion_peers: HashMap::new(),
        };

        // Listen address depends on transport mode:
        // - Tcp/Internet: 0.0.0.0 (all interfaces)
        // - Tor: 127.0.0.1 only (onion service forwards traffic)
        let listen_addr: Multiaddr = match node.transport_mode {
            TransportMode::Tor => format!("/ip4/127.0.0.1/tcp/{}", listen_port).parse()?,
            _ => format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse()?,
        };
        node.swarm.listen_on(listen_addr)?;

        tracing::info!(port = listen_port, "Listening for peer connections");

        Ok(node)
    }

    /// Run the event loop — handles peer discovery, incoming messages, etc.
    pub async fn run(
        &mut self,
        mut incoming_tx: mpsc::Sender<IncomingRequestEnvelope>,
    ) -> Result<()> {
        loop {
            match self.swarm.select_next_some().await {
                // ─── mDNS: New peer discovered on LAN ───
                SwarmEvent::Behaviour(AgentBehaviourEvent::Mdns(mdns::Event::Discovered(
                    peers,
                ))) => {
                    for (peer_id, addr) in peers {
                        tracing::info!(%peer_id, %addr, "Discovered peer via mDNS");
                        self.swarm.dial(addr)?;
                    }
                }

                // ─── mDNS: Peer expired ───
                SwarmEvent::Behaviour(AgentBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                    for (peer_id, _addr) in peers {
                        tracing::warn!(%peer_id, "Peer expired from mDNS");
                    }
                }

                // ─── Ping: connection keep-alive ───
                SwarmEvent::Behaviour(AgentBehaviourEvent::Ping(event)) => match event.result {
                    Ok(rtt) => {
                        tracing::debug!(peer = %event.peer, ?rtt, "Ping OK");
                    }
                    Err(e) => {
                        tracing::warn!(peer = %event.peer, "Ping failed: {}", e);
                    }
                },

                // ─── Messaging: Incoming request from another agent ───
                SwarmEvent::Behaviour(AgentBehaviourEvent::Messaging(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) => {
                    tracing::info!(%peer, "Received agent message");

                    // Forward to the agent processing pipeline
                    let _ = incoming_tx
                        .send(IncomingRequestEnvelope {
                            peer_id: peer,
                            request,
                            iroh_stable_id: None,
                            iroh_active_session: None,
                        })
                        .await;

                    // Send ACK response
                    let response = AgentResponse {
                        success: true,
                        message: "Received".to_string(),
                    };
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_response(channel, response);
                }

                // ─── Connection established ───
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    tracing::info!(%peer_id, "Connection established");
                }

                // ─── Connection closed ───
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    tracing::warn!(%peer_id, "Connection closed");
                }

                // ─── Listening ───
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(%address, "Listening on");
                }

                _ => {}
            }
        }
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(&mut self, peer_id: &PeerId, request: AgentRequest) {
        self.swarm
            .behaviour_mut()
            .messaging
            .send_request(peer_id, request);
    }

    /// Register a DID -> PeerId mapping
    pub fn register_peer(&mut self, did: String, peer_id: PeerId) {
        self.known_peers.insert(did, peer_id);
    }

    /// Look up PeerId from DID
    pub fn resolve_did(&self, did: &str) -> Option<&PeerId> {
        self.known_peers.get(did)
    }

    /// Register a DID -> .onion address mapping
    pub fn register_onion_peer(&mut self, did: String, onion_address: String) {
        self.onion_peers.insert(did, onion_address);
    }

    /// Look up .onion address from DID
    pub fn resolve_onion(&self, did: &str) -> Option<&String> {
        self.onion_peers.get(did)
    }

    /// Validate that a listen address is safe for Tor mode.
    /// In Tor mode, only loopback addresses (127.0.0.1, ::1) are allowed.
    pub fn validate_tor_listen_addr(addr: &Multiaddr) -> Result<()> {
        for protocol in addr.iter() {
            match protocol {
                libp2p::multiaddr::Protocol::Ip4(ip) => {
                    if !ip.is_loopback() {
                        return Err(anyhow::anyhow!(
                            "SECURITY: Tor mode cannot listen on public IP {}. Use 127.0.0.1 only.",
                            ip
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Detect the local IP address of the outbound network interface.
///
/// Uses a UDP socket trick: connect to a remote address (without sending data)
/// and check which local interface was selected by the OS.
pub fn detect_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response;

    /// Diagnostic test: verifies two nodes can complete TCP + Noise + Yamux
    /// handshake and exchange a request-response message.
    #[tokio::test]
    async fn two_nodes_connect_and_handshake() {
        // Create two nodes on different ports (TCP mode, no Tor)
        let mut node_a = NetworkNode::new(19090, TransportMode::Tcp, None, "test_a")
            .await
            .expect("Node A failed to start");

        let mut node_b = NetworkNode::new(19091, TransportMode::Tcp, None, "test_b")
            .await
            .expect("Node B failed to start");

        let peer_a = node_a.peer_id;
        let peer_b = node_b.peer_id;

        // Node A dials Node B directly (no mDNS)
        let addr_b: Multiaddr = "/ip4/127.0.0.1/tcp/19091".parse().unwrap();
        node_a.swarm.dial(addr_b).expect("Dial failed");

        // Poll both swarms until connection is established (max 5 seconds)
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut a_connected = false;
        let mut b_connected = false;
        let mut a_got_response = false;
        let mut handshake_sent = false;

        loop {
            if (a_connected && b_connected && a_got_response)
                || tokio::time::Instant::now() > deadline
            {
                break;
            }

            tokio::select! {
                event = node_a.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            assert_eq!(peer_id, peer_b);
                            a_connected = true;

                            // Send a test request
                            if !handshake_sent {
                                let req = super::super::protocol::AgentRequest {
                                    message_id: "test-1".to_string(),
                                    sender_did: "did:test:a".to_string(),
                                    sender_name: "TestA".to_string(),
                                    sender_role: "tester".to_string(),
                                    msg_type: super::super::protocol::MessageKind::Heartbeat,
                                    payload: vec![],
                                    signature: vec![],
                                    nonce: 1,
                                    timestamp: 1,
                                    ttl_ms: 0,
                                };
                                node_a.swarm.behaviour_mut().messaging.send_request(&peer_b, req);
                                handshake_sent = true;
                            }
                        }
                        SwarmEvent::Behaviour(AgentBehaviourEvent::Messaging(
                            request_response::Event::Message {
                                message: request_response::Message::Response { .. },
                                ..
                            }
                        )) => {
                            a_got_response = true;
                        }
                        SwarmEvent::OutgoingConnectionError { error, .. } => {
                            panic!("Node A outgoing connection failed: {}", error);
                        }
                        _ => {}
                    }
                }
                event = node_b.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            assert_eq!(peer_id, peer_a);
                            b_connected = true;
                        }
                        SwarmEvent::Behaviour(AgentBehaviourEvent::Messaging(
                            request_response::Event::Message {
                                message: request_response::Message::Request { channel, .. },
                                ..
                            }
                        )) => {
                            let resp = super::super::protocol::AgentResponse {
                                success: true,
                                message: "OK".to_string(),
                            };
                            let _ = node_b.swarm.behaviour_mut().messaging.send_response(channel, resp);
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            panic!("Node B incoming connection failed: {}", error);
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(a_connected, "Node A never connected to Node B");
        assert!(b_connected, "Node B never saw connection from Node A");
        assert!(a_got_response, "Node A never got response from Node B");
    }
}

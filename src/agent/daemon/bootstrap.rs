use super::handshake_request_gate::{self, HandshakeRequestGate};
use super::incoming_connect_gate::{self, IncomingConnectGate};
use super::*;

pub(crate) struct TransportBackend {
    pub(crate) internet_mode: bool,
    pub(crate) network: Option<NetworkNode>,
    pub(crate) iroh_network: Option<IrohTransport>,
    pub(crate) iroh_invite_addr: Option<iroh::EndpointAddr>,
    pub(crate) iroh_endpoint_id: Option<String>,
    pub(crate) our_peer_id: libp2p::PeerId,
}

pub(crate) struct PeerBootstrapState {
    pub(crate) peer_store: Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) used_invites_path: Option<std::path::PathBuf>,
    pub(crate) used_invites_persist_key: Option<[u8; 32]>,
    pub(crate) used_invites: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) group_mailboxes: Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) handshake_request_gate: Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    pub(crate) incoming_connect_gate: Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) direct_peer_dids: Arc<DashMap<String, bool>>,
    pub(crate) invite_proof_by_peer: Arc<DashMap<String, String>>,
    pub(crate) manual_disconnect_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) remote_offline_dids: Arc<tokio::sync::Mutex<HashSet<String>>>,
    pub(crate) ip_hidden: Arc<AtomicBool>,
}

pub(crate) async fn start_transport_backend(
    config: &AppConfig,
    iroh_endpoint_secret_bytes: [u8; 32],
    msg_tx: mpsc::Sender<crate::network::IncomingRequestEnvelope>,
    priority_msg_tx: mpsc::Sender<crate::network::IncomingRequestEnvelope>,
) -> Result<TransportBackend> {
    let internet_mode = matches!(config.network.transport_mode, TransportMode::Internet);
    let mut network: Option<NetworkNode> = None;
    let mut iroh_network: Option<IrohTransport> = None;
    let mut iroh_invite_addr: Option<iroh::EndpointAddr> = None;
    let mut iroh_endpoint_id: Option<String> = None;
    let our_peer_id: libp2p::PeerId;

    if internet_mode {
        let iroh = IrohTransport::new(
            config.network.listen_port,
            &config.network.iroh,
            iroh_endpoint_secret_bytes,
            msg_tx,
            priority_msg_tx,
        )
        .await?;
        our_peer_id = iroh.logical_peer_id();
        iroh_endpoint_id = Some(iroh.endpoint_id().to_string());
        iroh_invite_addr = Some(iroh.endpoint_addr_for_invite(true));
        iroh_network = Some(iroh);
    } else {
        let tor_config = if matches!(config.network.transport_mode, TransportMode::Tor) {
            Some(&config.network.tor)
        } else {
            None
        };

        let node = NetworkNode::new(
            config.network.listen_port,
            config.network.transport_mode.clone(),
            tor_config,
            &config.agent.name,
        )
        .await?;
        our_peer_id = node.peer_id;
        network = Some(node);
    }

    Ok(TransportBackend {
        internet_mode,
        network,
        iroh_network,
        iroh_invite_addr,
        iroh_endpoint_id,
        our_peer_id,
    })
}

pub(crate) fn initialize_peer_bootstrap_state(
    agent_data_dir: &std::path::Path,
    log_mode: &LogMode,
    log_mode_str: &str,
    peer_store_persist_key: Option<[u8; 32]>,
    used_invites_persist_key: Option<[u8; 32]>,
    handshake_request_gate_persist_key: Option<[u8; 32]>,
    incoming_connect_gate_persist_key: Option<[u8; 32]>,
) -> PeerBootstrapState {
    let peer_store_path = peer_store::store_path_for_mode(agent_data_dir, log_mode_str);
    let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::load_with_persist_key(
        peer_store_path.as_deref(),
        peer_store_persist_key,
    )));
    let used_invites_path = used_invites_store_path(agent_data_dir, log_mode);
    let used_invites = Arc::new(tokio::sync::Mutex::new(
        used_invites_path
            .as_ref()
            .map_or_else(std::collections::HashSet::new, |p| {
                load_used_invites(p, used_invites_persist_key.as_ref())
            }),
    ));
    let handshake_request_gate_path =
        handshake_request_gate::store_path_for_mode(agent_data_dir, log_mode);
    let handshake_request_gate = Arc::new(tokio::sync::Mutex::new(
        HandshakeRequestGate::load_with_persist_key(
            handshake_request_gate_path.as_deref(),
            handshake_request_gate_persist_key,
        ),
    ));
    let incoming_connect_gate_path =
        incoming_connect_gate::store_path_for_mode(agent_data_dir, log_mode);
    let incoming_connect_gate = Arc::new(tokio::sync::Mutex::new(
        IncomingConnectGate::load_with_persist_key(
            incoming_connect_gate_path.as_deref(),
            incoming_connect_gate_persist_key,
        ),
    ));

    PeerBootstrapState {
        peer_store,
        used_invites_path,
        used_invites_persist_key,
        used_invites,
        group_mailboxes: Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default())),
        handshake_request_gate,
        incoming_connect_gate,
        direct_peer_dids: Arc::new(DashMap::new()),
        invite_proof_by_peer: Arc::new(DashMap::new()),
        manual_disconnect_dids: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        remote_offline_dids: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        ip_hidden: Arc::new(AtomicBool::new(true)),
    }
}

pub(crate) async fn bootstrap_connections(
    backend: &mut TransportBackend,
    config: &AppConfig,
    bootstrap_peer: Option<&String>,
    direct_peer_dids: &Arc<DashMap<String, bool>>,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    initial_iroh_reconnects: &mut Vec<KnownPeer>,
) {
    {
        let mut store = peer_store.lock().await;
        if backend.internet_mode || matches!(config.network.transport_mode, TransportMode::Tor) {
            let scrubbed = store.scrub_for_private_transport_mode();
            if scrubbed > 0 {
                tracing::warn!(
                    scrubbed,
                    "Scrubbed legacy TCP reconnect metadata from peer store for private transport mode"
                );
            }
        }
        let known = store.auto_reconnect_peers();
        if !known.is_empty() {
            let startup_status = if backend.internet_mode
                || matches!(config.network.transport_mode, TransportMode::Tor)
            {
                "queued for background reconnect"
            } else {
                "reconnecting..."
            };
            println!(
                "   {} {} known peer(s) found, {}",
                "Auto-reconnect:".yellow().bold(),
                known.len(),
                startup_status
            );

            let tor_only_mode = matches!(config.network.transport_mode, TransportMode::Tor);
            for kp in known {
                direct_peer_dids.insert(kp.did.clone(), true);
                if backend.internet_mode {
                    let Some(iroh_json) = kp.iroh_endpoint_addr.as_ref() else {
                        continue;
                    };

                    let sanitized_iroh_json = match crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json(iroh_json) {
                        Ok(sanitized) => sanitized,
                        Err(e) => {
                            println!(
                                "   {} {} — invalid relay-only iroh address in peer store ({})",
                                "Failed:".red(),
                                kp.name.cyan(),
                                e
                            );
                            continue;
                        }
                    };
                    let endpoint_addr =
                        match serde_json::from_str::<iroh::EndpointAddr>(&sanitized_iroh_json) {
                            Ok(addr) => addr,
                            Err(e) => {
                                println!(
                                    "   {} {} — sanitized iroh address could not be parsed ({})",
                                    "Failed:".red(),
                                    kp.name.cyan(),
                                    e
                                );
                                continue;
                            }
                        };
                    if endpoint_addr.addrs.is_empty() {
                        println!(
                            "   {} {} — no usable relay-only iroh transport address",
                            "Skipped:".yellow(),
                            kp.name.cyan()
                        );
                        continue;
                    }
                    if backend.iroh_network.is_some() {
                        initial_iroh_reconnects.push(kp.clone());
                    }
                    continue;
                }

                if matches!(config.network.transport_mode, TransportMode::Tor) {
                    continue;
                }

                if let Some(ref onion) = kp.onion_address {
                    if let Some(ref tor_mgr) = backend
                        .network
                        .as_ref()
                        .and_then(|n| n.tor_manager.as_ref())
                    {
                        println!(
                            "   {} {}.onion ({})",
                            "Reconnecting:".yellow(),
                            &onion[..16.min(onion.len())],
                            kp.name.cyan()
                        );
                        match tor_bridge::create_tor_bridge_isolated(
                            tor_mgr,
                            onion,
                            kp.onion_port,
                            Some(&kp.did),
                        )
                        .await
                        {
                            Ok(bridge_port) => {
                                let addr: libp2p::Multiaddr =
                                    format!("/ip4/127.0.0.1/tcp/{}", bridge_port)
                                        .parse()
                                        .expect("valid multiaddr");
                                match backend
                                    .network
                                    .as_mut()
                                    .expect("network exists")
                                    .swarm
                                    .dial(addr)
                                {
                                    Ok(()) => {
                                        println!("   {} {} via Tor", "OK".green(), kp.name.cyan());
                                    }
                                    Err(e) => {
                                        println!("   {} {} ({})", "Failed:".red(), kp.name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "   {} {} — Tor bridge failed: {}",
                                    "Failed:".red(),
                                    kp.name,
                                    e
                                );
                            }
                        }
                    }
                } else if let Some(ref tcp) = kp.tcp_address {
                    if tor_only_mode {
                        println!(
                            "   {} {} has only TCP address in peer store — skipped (Tor-only mode)",
                            "Security:".yellow().bold(),
                            kp.name.cyan()
                        );
                        continue;
                    }
                    if let Ok(addr) = tcp.parse::<libp2p::Multiaddr>() {
                        println!("   {} {} via TCP", "Reconnecting:".yellow(), kp.name.cyan());
                        if let Err(e) = backend
                            .network
                            .as_mut()
                            .expect("network exists")
                            .swarm
                            .dial(addr)
                        {
                            println!("   {} {} ({})", "Failed:".red(), kp.name, e);
                        }
                    }
                }
            }
        }
    }

    if let Some(peer_addr) = bootstrap_peer {
        if backend.internet_mode {
            if let Some(iroh) = backend.iroh_network.as_ref() {
                match crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json(peer_addr) {
                    Ok(sanitized) => {
                        let endpoint_addr =
                            match serde_json::from_str::<iroh::EndpointAddr>(&sanitized) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    println!(
                                        "   {} sanitized iroh --peer payload is invalid: {}",
                                        "Error:".red().bold(),
                                        e
                                    );
                                    return;
                                }
                            };
                        println!(
                            "   {} {}",
                            "Dialing relay-only iroh peer:".yellow(),
                            sanitized.dimmed()
                        );
                        if let Err(e) = iroh.connect(endpoint_addr).await {
                            tracing::warn!("Failed to dial bootstrap iroh peer: {}", e);
                            println!("   {} {}", "Dial failed:".red(), e);
                        }
                    }
                    Err(e) => println!(
                        "   {} invalid relay-only iroh --peer (expected EndpointAddr JSON with a relay route): {}",
                        "Error:".red().bold(),
                        e
                    ),
                }
            }
        } else if matches!(config.network.transport_mode, TransportMode::Tor)
            && !peer_addr.contains("onion3")
        {
            println!(
                "   {} refusing non-onion --peer in Tor mode (no clear-net fallback)",
                "SECURITY:".red().bold()
            );
            println!(
                "   {} use /onion3/... or /connect <invite>",
                "Hint:".dimmed()
            );
        } else {
            match peer_addr.parse::<libp2p::Multiaddr>() {
                Ok(addr) => {
                    println!("   {} {}", "Dialing peer:".yellow(), peer_addr.dimmed());
                    if let Err(e) = backend
                        .network
                        .as_mut()
                        .expect("network exists")
                        .swarm
                        .dial(addr)
                    {
                        tracing::warn!("Failed to dial bootstrap peer: {}", e);
                        println!("   {} {}", "Dial failed:".red(), e);
                    }
                }
                Err(e) => tracing::warn!("Invalid peer multiaddr '{}': {}", peer_addr, e),
            }
        }
    }
}

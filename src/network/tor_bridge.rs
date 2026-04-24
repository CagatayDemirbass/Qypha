//! TCP bridge for routing libp2p connections through Tor.
//!
//! When dialing a .onion peer, we:
//! 1. Connect to the remote .onion address through Arti (getting a DataStream)
//! 2. Create a local TCP listener on a random port
//! 3. Tell libp2p to dial `127.0.0.1:<bridge_port>`
//! 4. Bridge bidirectional traffic between libp2p and the Tor stream
//!
//! This avoids implementing a custom libp2p Transport trait and works
//! with the existing TCP+Noise+Yamux stack transparently.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tor_transport::TorManager;

/// Create a TCP bridge to a remote .onion address through Tor.
///
/// Returns the local port that libp2p should dial to reach the remote peer.
///
/// Data flow:
/// ```text
/// libp2p → TCP 127.0.0.1:bridge_port → bridge → Tor DataStream → Tor Network → .onion
/// ```
pub async fn create_tor_bridge(
    tor_manager: &Arc<TorManager>,
    onion_addr: &str,
    onion_port: u16,
) -> Result<u16> {
    create_tor_bridge_isolated(tor_manager, onion_addr, onion_port, None).await
}

/// Create a circuit-isolated TCP bridge to a remote .onion address.
///
/// When `peer_did` is Some, each peer gets its own Tor circuit to prevent
/// cross-peer correlation attacks at the Tor relay level.
pub async fn create_tor_bridge_isolated(
    tor_manager: &Arc<TorManager>,
    onion_addr: &str,
    onion_port: u16,
    peer_did: Option<&str>,
) -> Result<u16> {
    // 1. Connect to remote .onion address through Tor FIRST
    //    This ensures the Tor circuit is ready before libp2p tries to connect.
    //    Use isolated circuits when peer DID is known.
    let tor_stream = if let Some(did) = peer_did {
        tor_manager
            .connect_to_onion_isolated(onion_addr, onion_port, did)
            .await
            .context("Failed to connect to .onion address through Tor (isolated)")?
    } else {
        tor_manager
            .connect_to_onion(onion_addr, onion_port)
            .await
            .context("Failed to connect to .onion address through Tor")?
    };

    // 2. Create local TCP listener on a random ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind bridge listener")?;

    let bridge_port = listener.local_addr()?.port();
    tracing::info!(
        bridge_port = bridge_port,
        onion = %onion_addr,
        "Tor bridge ready — dial 127.0.0.1:{}",
        bridge_port
    );

    // 3. Spawn bridge task: accept one libp2p connection and pipe to Tor
    //    Yield to let the accept task start before we return the port.
    //    Without this, swarm.dial() can race and fail if the accept isn't ready.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // Signal that we're about to accept — caller can now dial safely.
        let _ = ready_tx.send(());
        match listener.accept().await {
            Ok((local_stream, _)) => {
                tracing::debug!("Bridge: libp2p connected to bridge port");

                // Split both streams for bidirectional copy
                let (mut tor_read, mut tor_write) = tokio::io::split(tor_stream);
                let (mut local_read, mut local_write) = tokio::io::split(local_stream);

                // Bidirectional proxy: pipe data in both directions
                let client_to_tor = async {
                    let result = tokio::io::copy(&mut local_read, &mut tor_write).await;
                    let _ = tor_write.shutdown().await;
                    result
                };

                let tor_to_client = async {
                    let result = tokio::io::copy(&mut tor_read, &mut local_write).await;
                    let _ = local_write.shutdown().await;
                    result
                };

                let (c2t, t2c) = tokio::join!(client_to_tor, tor_to_client);

                match (c2t, t2c) {
                    (Ok(sent), Ok(recv)) => {
                        tracing::debug!(
                            sent_bytes = sent,
                            recv_bytes = recv,
                            "Tor bridge closed normally"
                        );
                    }
                    (Err(e1), Err(e2)) => {
                        tracing::warn!("Tor bridge errors: send={}, recv={}", e1, e2);
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::debug!("Tor bridge closed with one-side error: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Bridge accept failed: {}", e);
            }
        }
    });

    // Wait for accept task to signal readiness before returning port.
    // This ensures listener.accept() is queued before swarm.dial() connects.
    let _ = ready_rx.await;

    Ok(bridge_port)
}

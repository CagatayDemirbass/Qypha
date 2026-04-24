//! Embedded Tor client manager using Arti.
//!
//! Manages the lifecycle of the Tor client:
//! - Bootstrap (download consensus, establish circuits)
//! - Create/restore persistent v3 onion service
//! - Connect to remote .onion addresses
//! - Provide onion address for peer sharing

use anyhow::{Context, Result};
use arti_client::{DataStream, TorClient, TorClientConfig};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tor_rtcompat::PreferredRuntime;

#[derive(Clone, Copy, Debug)]
pub enum TorServiceRole {
    DirectPeer,
    Mailbox,
}

impl TorServiceRole {
    fn log_label(self) -> &'static str {
        match self {
            Self::DirectPeer => "direct_peer_onion",
            Self::Mailbox => "mailbox_onion",
        }
    }

    fn rate_window_secs(self) -> u64 {
        10
    }

    fn rate_max_connections(self) -> usize {
        match self {
            Self::DirectPeer => 20,
            // Mailbox traffic uses short-lived HTTP-over-Tor streams for poll/post/ack.
            // A higher ceiling avoids false positives during legitimate join/poll bursts.
            Self::Mailbox => 128,
        }
    }
}

/// Manages the embedded Arti Tor client and onion service.
///
/// Each Qypha agent gets its own TorManager, which:
/// - Bootstraps a Tor client on startup
/// - Creates a persistent v3 onion service (same .onion address across restarts)
/// - Provides outgoing connections through Tor circuits
/// - Bridges incoming onion service connections to the local libp2p TCP port
pub struct TorManager {
    /// The embedded Arti Tor client
    client: Arc<TorClient<PreferredRuntime>>,
    /// The onion service role served by this manager.
    service_role: TorServiceRole,
    /// Our .onion v3 address (56 chars, no ".onion" suffix)
    onion_address: String,
    /// Path where Tor state is persisted
    data_dir: PathBuf,
    /// Local port the onion service forwards to
    local_port: u16,
    /// Per-peer isolation tokens: same DID → same token → same circuit
    /// Different DIDs get different tokens → different circuits (isolation)
    isolation_tokens: Mutex<HashMap<String, arti_client::IsolationToken>>,
    /// Background onion-service task. Aborted on drop so Ghost cleanup does not
    /// race a detached Arti service against already-wiped temp state.
    onion_service_task: Option<tokio::task::JoinHandle<()>>,
}

impl TorManager {
    /// Bootstrap Tor and create/restore the onion service.
    ///
    /// First run: downloads Tor consensus (~5-10 MB), takes 30-120 seconds.
    /// Subsequent runs: fast startup from cached consensus.
    ///
    /// The onion service forwards incoming connections to `127.0.0.1:local_port`,
    /// where libp2p's TCP transport is listening.
    pub async fn bootstrap(
        tor_data_dir: &Path,
        local_port: u16,
        circuit_timeout_secs: u64,
        service_role: TorServiceRole,
    ) -> Result<Self> {
        let cache_dir = tor_data_dir.join("cache");
        let state_dir = tor_data_dir.join("state");
        std::fs::create_dir_all(&cache_dir)?;
        std::fs::create_dir_all(&state_dir)?;

        // Arti requires restrictive permissions on its directories
        // to prevent other users from reading Tor state/keys
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(tor_data_dir, perms.clone())?;
            std::fs::set_permissions(&cache_dir, perms.clone())?;
            std::fs::set_permissions(&state_dir, perms)?;
        }
        #[cfg(windows)]
        {
            // Windows: make directories read-only for current user via readonly flag.
            // Full NTFS ACL restriction would require the `windows-acl` crate.
            // For now, Arti's fs-mistrust handles permission checks on Windows.
            tracing::debug!("Windows: Tor directory permissions managed by fs-mistrust");
        }

        // Configure Arti with our custom data directories
        let mut builder = TorClientConfig::builder();
        {
            use arti_client::config::CfgPath;
            let storage = builder.storage();
            storage.cache_dir(CfgPath::new_literal(cache_dir));
            storage.state_dir(CfgPath::new_literal(state_dir));
        }
        let config = builder
            .build()
            .context("Failed to build Tor client config")?;

        // Bootstrap the Tor client (connects to Tor network, downloads consensus)
        // Apply circuit timeout to prevent hanging on adversarial/slow Tor relays.
        let timeout_duration = std::time::Duration::from_secs(if circuit_timeout_secs > 0 {
            circuit_timeout_secs
        } else {
            120
        });
        tracing::info!(
            timeout_secs = timeout_duration.as_secs(),
            "Bootstrapping embedded Tor client (this may take a moment)..."
        );
        let client = tokio::time::timeout(timeout_duration, TorClient::create_bootstrapped(config))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Tor bootstrap timed out after {} seconds. \
             Check network connectivity or try increasing circuit_timeout_secs.",
                    timeout_duration.as_secs()
                )
            })?
            .context("Failed to bootstrap Tor client")?;
        tracing::info!("Tor client bootstrapped successfully");

        let client = Arc::new(client);

        // Create or restore the onion service
        let (onion_address, onion_service_task) =
            Self::setup_onion_service(&client, tor_data_dir, local_port, service_role)
                .await
                .context("Failed to setup onion service")?;

        tracing::info!(
            service_role = service_role.log_label(),
            onion_address = %onion_address,
            local_port = local_port,
            "Onion service ready — forwarding to 127.0.0.1:{}",
            local_port
        );

        Ok(Self {
            client,
            service_role,
            onion_address,
            data_dir: tor_data_dir.to_path_buf(),
            local_port,
            isolation_tokens: Mutex::new(HashMap::new()),
            onion_service_task: Some(onion_service_task),
        })
    }

    /// Create or restore a persistent v3 onion service.
    ///
    /// The onion service key is managed by Arti's key manager in the state directory.
    /// Same key = same .onion address across restarts.
    async fn setup_onion_service(
        client: &Arc<TorClient<PreferredRuntime>>,
        tor_data_dir: &Path,
        local_port: u16,
        service_role: TorServiceRole,
    ) -> Result<(String, tokio::task::JoinHandle<()>)> {
        use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsNickname};

        let nickname = HsNickname::new("qypha".to_string())
            .map_err(|e| anyhow::anyhow!("Invalid onion service nickname: {}", e))?;

        // Configure the onion service
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .context("Failed to build onion service config")?;

        // Launch the onion service through the Tor client.
        // This is synchronous — returns immediately with a handle and a stream of requests.
        // Arti handles key persistence in its state directory.
        let (onion_svc, rend_requests) = client
            .launch_onion_service(svc_config)
            .context("Failed to launch onion service")?;

        // Get the .onion address from the service.
        // HsId.to_string() returns "xxxx...xxxx.onion" — we strip the suffix for storage.
        let onion_address = onion_svc
            .onion_name()
            .map(|hsid| {
                let full = hsid.to_string();
                full.trim_end_matches(".onion").to_string()
            })
            .unwrap_or_else(|| {
                tracing::warn!("Onion service started but address not yet available");
                "pending".to_string()
            });

        // Spawn background task to handle incoming Tor connections.
        // Flow: RendRequest → accept → StreamRequest → accept → DataStream → bridge to local TCP
        //
        // MILITARY: Rate limiting prevents rendezvous flooding attacks.
        // Max 20 connections per 10 seconds — excess are silently dropped.
        let port = local_port;
        let service_label = service_role.log_label();
        let service_onion = onion_address.clone();
        let local_forward = format!("127.0.0.1:{local_port}");
        let onion_service_task = tokio::spawn(async move {
            // CRITICAL: Keep the onion service handle alive for the lifetime of this task.
            // Dropping `onion_svc` signals Arti to shut down the onion service.
            let _onion_svc_guard = onion_svc;

            use futures::StreamExt;
            use tor_cell::relaycell::msg::Connected;

            // Rate limiter: track recent connection timestamps.
            // Direct peer onion traffic is sparse; mailbox onion traffic is intentionally burstier
            // because poll/post/ack currently use short-lived HTTP-over-Tor requests.
            let rate_window_secs = service_role.rate_window_secs();
            let rate_max_connections = service_role.rate_max_connections();
            let mut recent_connections: std::collections::VecDeque<std::time::Instant> =
                std::collections::VecDeque::new();

            // handle_rend_requests auto-accepts all rendezvous requests,
            // converting the RendRequest stream into a StreamRequest stream
            let mut stream_requests = std::pin::pin!(handle_rend_requests(rend_requests));

            while let Some(stream_req) = stream_requests.next().await {
                let now = std::time::Instant::now();
                let request = format!("{:?}", stream_req.request());

                // Evict expired entries from the rate limiter window
                let window = std::time::Duration::from_secs(rate_window_secs);
                while recent_connections
                    .front()
                    .map_or(false, |t| now.duration_since(*t) > window)
                {
                    recent_connections.pop_front();
                }

                // Check rate limit
                if recent_connections.len() >= rate_max_connections {
                    tracing::warn!(
                        service_role = service_label,
                        onion_address = %service_onion,
                        local_forward = %local_forward,
                        request = %request,
                        count = recent_connections.len(),
                        limit = rate_max_connections,
                        window_secs = rate_window_secs,
                        "Tor onion rendezvous rate limit exceeded — dropping incoming stream request"
                    );
                    // Silently drop the connection request (don't accept)
                    continue;
                }

                recent_connections.push_back(now);
                let accepted_request = request.clone();
                let accepted_service_onion = service_onion.clone();
                let accepted_local_forward = local_forward.clone();

                tokio::spawn(async move {
                    tracing::debug!(
                        service_role = service_label,
                        onion_address = %accepted_service_onion,
                        local_forward = %accepted_local_forward,
                        request = %accepted_request,
                        "Accepted incoming Tor rendezvous stream"
                    );
                    // Accept the stream request with an empty Connected message
                    match stream_req.accept(Connected::new_empty()).await {
                        Ok(tor_stream) => {
                            if let Err(e) = bridge_to_local(tor_stream, port).await {
                                tracing::debug!("Incoming Tor bridge ended: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to accept incoming Tor stream: {}", e);
                        }
                    }
                });
            }
            tracing::info!("Onion service handler stopped");
        });

        // Write the onion address to a file for convenience
        let hostname_path = tor_data_dir.join("hostname");
        std::fs::write(&hostname_path, format!("{}.onion\n", onion_address))?;

        Ok((onion_address, onion_service_task))
    }

    /// Connect to a remote .onion address through Tor.
    ///
    /// Returns an async TCP-like stream that transparently routes through the Tor network.
    pub async fn connect_to_onion(&self, onion_addr: &str, port: u16) -> Result<DataStream> {
        let target = format!("{}.onion", onion_addr);
        tracing::info!(target = %target, port = port, "Connecting through Tor...");

        let stream: DataStream = self
            .client
            .connect((&*target, port))
            .await
            .context(format!(
                "Failed to connect to {}.onion:{}",
                onion_addr, port
            ))?;

        tracing::info!(target = %target, "Tor connection established");
        Ok(stream)
    }

    /// Connect to a remote .onion address with per-peer circuit isolation.
    ///
    /// MILITARY REQUIREMENT: Each peer gets its own Tor circuit to prevent
    /// cross-peer correlation attacks at the Tor relay level. Without isolation,
    /// a compromised Tor relay can observe that traffic to Peer A and Peer B
    /// comes from the same circuit, linking them to the same agent.
    ///
    /// Uses Arti's `StreamPrefs` with a per-DID `IsolationToken` to force
    /// separate circuit construction for each remote peer.
    pub async fn connect_to_onion_isolated(
        &self,
        onion_addr: &str,
        port: u16,
        peer_did: &str,
    ) -> Result<DataStream> {
        use arti_client::StreamPrefs;

        let target = format!("{}.onion", onion_addr);
        tracing::info!(
            target = %target,
            port = port,
            peer_did = %peer_did,
            "Connecting through Tor with circuit isolation..."
        );

        // Per-peer isolation: same DID → same token → same circuit (connection reuse).
        // Different DID → different token → different circuit (isolation).
        // Tokens are cached in isolation_tokens map so the same DID always reuses
        // the same IsolationToken, preventing unnecessary circuit churn.
        let mut prefs = StreamPrefs::new();
        let token = {
            let mut tokens = self.isolation_tokens.lock().await;
            tokens
                .entry(peer_did.to_string())
                .or_insert_with(arti_client::IsolationToken::new)
                .clone()
        };
        prefs.set_isolation(token);

        let stream: DataStream = self
            .client
            .connect_with_prefs((&*target, port), &prefs)
            .await
            .context(format!(
                "Failed to connect to {}.onion:{} (isolated for {})",
                onion_addr, port, peer_did
            ))?;

        tracing::info!(
            target = %target,
            peer = %peer_did,
            "Tor connection established (circuit-isolated, per-DID token)"
        );
        Ok(stream)
    }

    /// Get our .onion address (56 chars, no ".onion" suffix)
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    pub fn service_role(&self) -> TorServiceRole {
        self.service_role
    }

    /// Get our full .onion address with suffix
    pub fn onion_address_full(&self) -> String {
        format!("{}.onion", self.onion_address)
    }

    /// Get the local port that the onion service forwards to
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Get a reference to the Tor client
    pub fn client(&self) -> &Arc<TorClient<PreferredRuntime>> {
        &self.client
    }

    /// Get the data directory path
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        if let Some(task) = self.onion_service_task.take() {
            task.abort();
        }
    }
}

/// Bridge an incoming Tor DataStream to the local libp2p TCP port.
///
/// Creates a local TCP connection to 127.0.0.1:port and pipes data bidirectionally.
async fn bridge_to_local(tor_stream: DataStream, local_port: u16) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let local_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port))
        .await
        .context("Failed to connect to local libp2p port")?;

    tracing::debug!(local_port, "Bridging incoming Tor connection to local port");

    let (mut tor_read, mut tor_write) = tokio::io::split(tor_stream);
    let (mut local_read, mut local_write) = tokio::io::split(local_stream);

    let tor_to_local = async {
        let r = tokio::io::copy(&mut tor_read, &mut local_write).await;
        let _ = local_write.shutdown().await;
        r
    };

    let local_to_tor = async {
        let r = tokio::io::copy(&mut local_read, &mut tor_write).await;
        let _ = tor_write.shutdown().await;
        r
    };

    let _ = tokio::join!(tor_to_local, local_to_tor);
    Ok(())
}

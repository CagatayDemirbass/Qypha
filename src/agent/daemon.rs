use anyhow::Result;
use colored::Colorize;
use dashmap::DashMap;
use futures::StreamExt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::artifact::chunked_transfer::{self, ChunkedReceiveSession};
use crate::artifact::transfer;
use crate::config::{AppConfig, TransportMode};
use crate::control_plane::audit::{AuditLog, LogMode};
use crate::control_plane::policy::PolicyEngine;
use crate::control_plane::rbac::RbacEngine;
use crate::crypto::at_rest::derive_agent_scoped_persist_key;
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::keystore::KeyStore;
use crate::crypto::rate_limiter::RateLimiter;
use crate::crypto::replay_guard::ReplayGuard;
use crate::crypto::signing;
use crate::network::contact_mailbox_transport::ContactMailboxTransport;
use crate::network::invite::{DecodedInvite, PeerInvite};
use crate::network::iroh_transport::{IrohNetworkEvent, IrohTransport};
use crate::network::peer_store::{self, KnownPeer, PeerStore};
use crate::network::protocol::{AgentRequest, FileTransferPayload, HandshakePayload, MessageKind};
use crate::network::tor_bridge;
use crate::network::tor_mailbox::TorMailboxTransport;
use crate::network::NetworkNode;
use crate::os_adapter::secure_wipe::{secure_wipe_dir, secure_wipe_file};

#[path = "daemon/bootstrap.rs"]
mod bootstrap;
#[path = "daemon/chat_shared.rs"]
mod chat_shared;
#[path = "daemon/cleanup.rs"]
mod cleanup;
#[path = "daemon/command_helpers.rs"]
mod command_helpers;
#[path = "daemon/commands.rs"]
mod commands;
#[path = "daemon/contact_mailbox_runtime.rs"]
mod contact_mailbox_runtime;
#[path = "daemon/contact_promotion.rs"]
mod contact_promotion;
#[path = "daemon/contact_request_commands.rs"]
mod contact_request_commands;
#[path = "daemon/contact_requests.rs"]
mod contact_requests;
#[path = "daemon/did_connect_commands.rs"]
mod did_connect_commands;
#[path = "daemon/did_profile_cache.rs"]
mod did_profile_cache;
#[path = "daemon/group_mailbox/mod.rs"]
mod group_mailbox;
#[path = "daemon/handshake.rs"]
mod handshake;
#[path = "daemon/handshake_request_gate.rs"]
mod handshake_request_gate;
#[path = "daemon/headless.rs"]
mod headless;
#[path = "daemon/incoming.rs"]
mod incoming;
#[path = "daemon/incoming_connect_gate.rs"]
mod incoming_connect_gate;
#[path = "daemon/invite_shared.rs"]
mod invite_shared;
#[path = "daemon/iroh_command_chat.rs"]
mod iroh_command_chat;
#[path = "daemon/iroh_command_domains.rs"]
mod iroh_command_domains;
#[path = "daemon/iroh_command_handlers.rs"]
mod iroh_command_handlers;
#[path = "daemon/iroh_command_invite.rs"]
mod iroh_command_invite;
#[path = "daemon/iroh_command_peer.rs"]
mod iroh_command_peer;
#[path = "daemon/iroh_command_transfer.rs"]
mod iroh_command_transfer;
#[path = "daemon/iroh_contact_delivery.rs"]
mod iroh_contact_delivery;
#[path = "daemon/iroh_event_connection.rs"]
mod iroh_event_connection;
#[path = "daemon/iroh_event_domains.rs"]
mod iroh_event_domains;
#[path = "daemon/iroh_event_handlers.rs"]
mod iroh_event_handlers;
#[path = "daemon/iroh_identity.rs"]
pub(crate) mod iroh_identity;
#[path = "daemon/iroh_runtime.rs"]
mod iroh_runtime;
#[path = "daemon/libp2p_command_chat.rs"]
mod libp2p_command_chat;
#[path = "daemon/libp2p_command_domains.rs"]
mod libp2p_command_domains;
#[path = "daemon/libp2p_command_handlers.rs"]
mod libp2p_command_handlers;
#[path = "daemon/libp2p_command_invite.rs"]
mod libp2p_command_invite;
#[path = "daemon/libp2p_command_peer.rs"]
mod libp2p_command_peer;
#[path = "daemon/libp2p_command_transfer.rs"]
mod libp2p_command_transfer;
#[path = "daemon/libp2p_event_connectivity.rs"]
mod libp2p_event_connectivity;
#[path = "daemon/libp2p_event_domains.rs"]
mod libp2p_event_domains;
#[path = "daemon/libp2p_event_handlers.rs"]
mod libp2p_event_handlers;
#[path = "daemon/libp2p_event_messaging.rs"]
mod libp2p_event_messaging;
#[path = "daemon/libp2p_runtime.rs"]
mod libp2p_runtime;
#[path = "daemon/paths.rs"]
pub(crate) mod paths;
#[path = "daemon/peer.rs"]
mod peer;
#[path = "daemon/receive_dir.rs"]
mod receive_dir;
#[path = "daemon/repl.rs"]
mod repl;
#[path = "daemon/selectors.rs"]
mod selectors;
#[path = "daemon/startup.rs"]
mod startup;
#[path = "daemon/tor_direct_delivery.rs"]
mod tor_direct_delivery;
#[path = "daemon/transfer_gate.rs"]
mod transfer_gate;
#[path = "daemon/transfer_shared.rs"]
mod transfer_shared;

use self::bootstrap::*;
use self::chat_shared::*;
use self::cleanup::*;
use self::command_helpers::*;
use self::commands::*;
use self::contact_mailbox_runtime::*;
use self::contact_promotion::*;
use self::contact_request_commands::*;
use self::contact_requests::*;
use self::group_mailbox::*;
use self::handshake::*;
use self::headless::*;
use self::incoming::*;
use self::invite_shared::*;
use self::iroh_identity::*;
use self::iroh_runtime::*;
use self::libp2p_runtime::*;
use self::paths::*;
use self::peer::*;
use self::receive_dir::*;
use self::repl::*;
use self::selectors::*;
use self::startup::*;
use self::tor_direct_delivery::*;
use self::transfer_gate::*;

// ─────────────────────────────────────────────────────────────────────────────
// Ghost Mode: global flag for emergency cleanup on panic/signal
// ─────────────────────────────────────────────────────────────────────────────
static GHOST_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);
static GRACEFUL_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
const TOR_CHUNK_SIZE_BYTES: usize = 4 * 1024 * 1024;
const IROH_CHUNK_SIZE_BYTES: usize = 8 * 1024 * 1024;
const IROH_DIRECT_CHUNK_SIZE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_AGENT_ROLE: &str = "agent";
const SAFE_PEER_STORE_PERSIST_KEY_SCOPE: &[u8] = b"safe-peer-store-v1";
const USED_INVITES_PERSIST_KEY_SCOPE: &[u8] = b"used-invites-v1";
const HANDSHAKE_REQUEST_GATE_PERSIST_KEY_SCOPE: &[u8] = b"handshake-request-gate-v1";
const INCOMING_CONNECT_GATE_PERSIST_KEY_SCOPE: &[u8] = b"incoming-connect-gate-v1";

/// Internal ratchet bootstrap marker.
/// Initiator sends this immediately after handshake so responder gets a sending chain.
const RATCHET_BOOTSTRAP_MARKER: &[u8] = b"__NXF_RATCHET_BOOTSTRAP_V1__";

pub(crate) fn clear_graceful_shutdown_requested() {
    GRACEFUL_SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

pub(crate) fn mark_graceful_shutdown_requested() {
    GRACEFUL_SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

pub(crate) fn graceful_shutdown_requested() -> bool {
    GRACEFUL_SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Commands from the REPL to the network task
enum NetworkCommand {
    SendChat {
        message: String,
    },
    SendChatToPeer {
        peer_id: libp2p::PeerId,
        peer_did: String,
        peer_name: String,
        message: String,
    },
    SendChatToGroup {
        group_id: String,
        message: String,
    },
    SendRatchetBootstrap {
        peer_id: libp2p::PeerId,
        peer_did: String,
    },
    EnsurePeerHandshake {
        peer_id: libp2p::PeerId,
        ack_handshake_message_id: Option<String>,
        trusted_known_peer_bootstrap: bool,
    },
    SendFile {
        path: String,
        peer_selector: String,
    },
    SendGroupFile {
        group_id: String,
        path: String,
    },
    SendGroupFastFileAccept {
        group_id: String,
        transfer_id: String,
    },
    ListPeers,
    ListAllPeers,
    ListPeersVerbose,
    ListGroups,
    WhoAmI,
    GenerateInvite,
    CreateNormalGroup {
        group_name: String,
    },
    CreateAnonymousGroup {
        group_name: Option<String>,
    },
    GenerateGroupInvite {
        group_id: String,
    },
    GenerateAnonymousGroupInvite {
        group_special_id: String,
    },
    SendHandshakeInvite {
        member_id: String,
    },
    SendHandshakeInviteScoped {
        group_id: String,
        member_id: String,
    },
    ConnectInvite {
        code: String,
    },
    ConnectDid {
        did: String,
        intro_message: Option<String>,
    },
    SendContactAccept {
        pending: PendingContactRequest,
    },
    SendContactReject {
        pending: PendingContactRequest,
        reason: Option<String>,
    },
    DisconnectPeerIntent {
        peer_id: libp2p::PeerId,
        peer_did: String,
        peer_name: String,
    },
    DisconnectKnownPeer {
        peer_did: String,
        peer_name: String,
    },
    KickGroupMember {
        member_selector: String,
    },
    LockGroup {
        group_id: String,
    },
    UnlockGroup {
        group_id: String,
    },
    LeaveGroup {
        group_id: String,
    },
    DisbandGroup {
        group_id: String,
    },
    ShowOnion,
    /// Background Tor re-dial succeeded — dial this bridge port
    TorRedial {
        peer_id: libp2p::PeerId,
        peer_did: String,
        bridge_port: u16,
    },
    /// Background Tor re-dial failed after all retries
    TorRedialFailed {
        peer_id: libp2p::PeerId,
        peer_did: String,
    },
    /// Rebind an in-flight Tor chunked transfer to a reconnected peer that
    /// came back with a fresh libp2p transport identity for the same DID.
    RebindTorTransferPeer {
        peer_id: libp2p::PeerId,
        peer_did: String,
        peer_name: String,
    },
    /// Background Tor reconnect bridge is ready for a known peer DID.
    TorBackgroundDial {
        did: String,
        bridge_port: u16,
    },
    /// Background Tor reconnect bridge failed for a known peer DID.
    TorBackgroundDialFailed {
        did: String,
    },
    /// Force-close a peer connection after a security rejection.
    DisconnectPeer {
        peer_id: libp2p::PeerId,
    },
    /// Force-close a peer connection after sending a signed peer notice.
    DisconnectPeerWithNotice {
        peer_id: libp2p::PeerId,
        notice_kind: DisconnectNoticeKind,
    },
    /// Remote peer announced an intentional agent shutdown/offline state.
    RemotePeerOffline {
        peer_id: libp2p::PeerId,
        peer_did: String,
        peer_name: String,
    },
    /// Remote peer ended the relationship via /disconnect.
    RemotePeerManualDisconnect {
        peer_id: libp2p::PeerId,
        peer_did: String,
        peer_name: String,
    },
    /// Receiver accepted a pending chunked transfer; notify sender to start streaming.
    SendTransferAccept {
        peer_id: libp2p::PeerId,
        session_id: String,
        received_chunks: Vec<usize>,
    },
    /// Receiver explicitly rejected a transfer; notify sender.
    SendTransferReject {
        peer_id: libp2p::PeerId,
        session_id: Option<String>,
        request_message_id: Option<String>,
        reason: String,
    },
    /// Receiver acknowledged inline transfer state back to sender.
    SendTransferStatus {
        peer_id: libp2p::PeerId,
        session_id: Option<String>,
        request_message_id: Option<String>,
        filename: Option<String>,
        status: String,
        detail: Option<String>,
    },
    /// Sender-side notification that peer rejected transfer.
    TransferRejectedByPeer {
        peer_id: libp2p::PeerId,
        session_id: Option<String>,
        reason: String,
    },
    /// Synchronization: signal that the previous command's output is done.
    /// Sent after every REPL command; the FIFO ordering of the channel
    /// guarantees this is processed AFTER the command's output is printed.
    OutputDone(tokio::sync::oneshot::Sender<()>),
    /// Gracefully stop the network runtime and release bound sockets.
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

/// State for an in-progress outbound chunked transfer.
/// Instead of sending all chunks in a tight loop (which overwhelms yamux),
/// we send one chunk per select! iteration, interleaving with swarm events.
struct PendingChunkTransfer {
    peer_id: libp2p::PeerId,
    peer_name: String,
    peer_did: String,
    session: chunked_transfer::TransferSession,
    chunk_source: ChunkSource,
    next_chunk: usize,
    chunk_size: usize,
    x25519_pk: [u8; 32],
    kyber_pk: Option<Vec<u8>>,
    ttl: u64,
    path: String,
    packed_mb: f64,
    packed_size: u64,
    /// RequestId of the in-flight chunk (None = ready to send next)
    inflight_request: Option<libp2p::request_response::OutboundRequestId>,
    /// How many times the current chunk has been retried
    retry_count: usize,
    /// When to attempt next send (for exponential backoff after failure)
    backoff_until: Option<tokio::time::Instant>,
    /// Total seconds spent waiting for peer to reconnect (resets on success)
    reconnect_wait_secs: u64,
    /// True while a Tor re-dial is in progress (prevents OutboundFailure from aborting)
    reconnecting: bool,
    /// When the last Tor bridge was created — used for proactive circuit rotation
    last_bridge_at: tokio::time::Instant,
    /// Whether a warm standby bridge is currently being created in background
    bridge_warming: bool,
    /// Peer's .onion address (cached for bridge rotation)
    peer_onion: Option<String>,
    /// Peer's onion port (cached)
    peer_onion_port: u16,
    /// Random delay before sending next chunk (traffic timing analysis resistance)
    chunk_jitter_until: Option<tokio::time::Instant>,
    /// Do not send any chunk until receiver explicitly accepts the transfer init.
    awaiting_receiver_accept: bool,
    awaiting_started_at: tokio::time::Instant,
    /// True when the sender must re-send ChunkTransferInit before streaming can continue.
    needs_reinit: bool,
}

struct PendingDisconnectNotice {
    peer_id: libp2p::PeerId,
    deadline: tokio::time::Instant,
}

/// iroh-mode outbound chunk transfer state.
struct PendingIrohChunkTransfer {
    peer_id: libp2p::PeerId,
    peer_name: String,
    peer_did: String,
    session: chunked_transfer::TransferSession,
    merkle_proof_cache: Vec<Vec<u8>>,
    chunk_source: ChunkSource,
    next_chunk: usize,
    chunk_size: usize,
    x25519_pk: [u8; 32],
    kyber_pk: Vec<u8>,
    ttl: u64,
    path: String,
    packed_mb: f64,
    packed_size: u64,
    awaiting_receiver_accept: bool,
    awaiting_started_at: tokio::time::Instant,
    approval_poll_after: Option<tokio::time::Instant>,
    retry_after: Option<tokio::time::Instant>,
    reconnect_wait_secs: u64,
    needs_reinit: bool,
}

#[derive(Debug, Clone)]
struct TransferStartApproval {
    peer_did: String,
    received_chunks: Vec<usize>,
}

async fn request_network_shutdown(cmd_tx: &mpsc::Sender<NetworkCommand>) {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    if cmd_tx
        .send(NetworkCommand::Shutdown(done_tx))
        .await
        .is_err()
    {
        return;
    }

    if tokio::time::timeout(tokio::time::Duration::from_secs(5), done_rx)
        .await
        .is_err()
    {
        tracing::warn!("network runtime shutdown acknowledgement timed out");
    }
}

const SIGNAL_SHUTDOWN_SEND_TIMEOUT_SECS: u64 = 1;
const SIGNAL_SHUTDOWN_FORCE_EXIT_TIMEOUT_SECS: u64 = 8;

fn spawn_shutdown_signal_bridge(line_tx: mpsc::Sender<String>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sighup = signal(SignalKind::hangup()).ok();

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async {
                    if let Some(sig) = sigterm.as_mut() {
                        let _ = sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
                _ = async {
                    if let Some(sig) = sighup.as_mut() {
                        let _ = sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }

        mark_graceful_shutdown_requested();
        let graceful_shutdown_enqueued = tokio::time::timeout(
            tokio::time::Duration::from_secs(SIGNAL_SHUTDOWN_SEND_TIMEOUT_SECS),
            line_tx.send("/quit".to_string()),
        )
        .await
        .ok()
        .and_then(|result| result.ok())
        .is_some();
        if !graceful_shutdown_enqueued {
            tracing::error!(
                timeout_secs = SIGNAL_SHUTDOWN_SEND_TIMEOUT_SECS,
                "signal-triggered shutdown could not be queued; forcing process exit"
            );
            std::process::exit(1);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(
            SIGNAL_SHUTDOWN_FORCE_EXIT_TIMEOUT_SECS,
        ))
        .await;
        tracing::error!(
            timeout_secs = SIGNAL_SHUTDOWN_FORCE_EXIT_TIMEOUT_SECS,
            "signal-triggered shutdown did not complete in time; forcing process exit"
        );
        std::process::exit(1);
    });
}

/// Backing storage for outbound chunked transfer payload.
/// Ghost paths use in-memory chunks to avoid plaintext temp files.
enum ChunkSource {
    TempFile(std::path::PathBuf),
    SharedTempFile(std::path::PathBuf),
    InMemory(Vec<Vec<u8>>),
}

impl ChunkSource {
    fn read_chunk(
        &self,
        session: &chunked_transfer::TransferSession,
        index: usize,
    ) -> Result<Vec<u8>> {
        match self {
            Self::TempFile(path) => chunked_transfer::read_chunk_from_file(path, session, index),
            Self::SharedTempFile(path) => {
                chunked_transfer::read_chunk_from_file(path, session, index)
            }
            Self::InMemory(chunks) => chunks
                .get(index)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Chunk index {} out of bounds", index)),
        }
    }

    fn secure_cleanup(&mut self) {
        match self {
            Self::TempFile(path) => {
                secure_wipe_file(path);
            }
            Self::SharedTempFile(_) => {}
            Self::InMemory(chunks) => {
                for chunk in chunks.iter_mut() {
                    chunk.fill(0);
                }
                chunks.clear();
            }
        }
    }

    async fn secure_cleanup_async(&mut self) {
        match std::mem::replace(self, Self::InMemory(Vec::new())) {
            Self::TempFile(path) => {
                secure_wipe_file_async(path).await;
            }
            Self::SharedTempFile(_) => {}
            Self::InMemory(mut chunks) => {
                for chunk in &mut chunks {
                    chunk.fill(0);
                }
                chunks.clear();
            }
        }
    }
}

async fn secure_wipe_file_async(path: std::path::PathBuf) {
    let path_str = path.display().to_string();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        secure_wipe_file(&path);
    })
    .await
    {
        tracing::warn!(path = %path_str, %e, "secure file wipe task failed");
    }
}

async fn secure_wipe_dir_async(path: std::path::PathBuf) {
    let path_str = path.display().to_string();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        secure_wipe_dir(&path);
    })
    .await
    {
        tracing::warn!(path = %path_str, %e, "secure directory wipe task failed");
    }
}

struct ScopedEnvVarRestore {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnvVarRestore {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVarRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Start the agent daemon: P2P network + message handler + interactive REPL
///
/// `log_mode_override` — if Some, overrides the value in config (from --log-mode flag)
pub async fn start_daemon(
    mut config: AppConfig,
    bootstrap_peer: Option<String>,
    log_mode_override: Option<String>,
) -> Result<()> {
    clear_graceful_shutdown_requested();
    config.agent.role = "agent".to_string();
    tracing::info!(
        agent = %config.agent.name,
        "Starting Qypha agent daemon"
    );

    // ── Per-agent data directory ────────────────────────────────────────────
    let agent_data_dir = KeyStore::agent_data_dir(&config.agent.name)?;
    let keys_dir = KeyStore::agent_keys_dir(&config.agent.name)?;
    let effective_log_mode = log_mode_override
        .clone()
        .unwrap_or_else(|| config.logging.mode.clone());

    // SECURITY: Ghost is launch-only. Reject before touching on-disk identity.
    if effective_log_mode == "ghost" {
        anyhow::bail!(
            "Ghost mode must be started via `Qypha launch` (not `start`). \
             This enforces ephemeral in-memory keys and full forensic hardening."
        );
    }

    // ── Load agent identity ────────────────────────────────────────────────
    let id_path = keys_dir.join("agent_identity.json");
    if !id_path.exists() {
        return Err(anyhow::anyhow!(
            "Agent identity not found at {}. Run `Qypha init --name {}` first.",
            id_path.display(),
            config.agent.name,
        ));
    }
    let passphrase = if let Ok(p) = std::env::var("QYPHA_PASSPHRASE") {
        p
    } else {
        use dialoguer::Password;
        Password::new()
            .with_prompt("  Enter passphrase to unlock agent identity")
            .interact()
            .map_err(|e| anyhow::anyhow!("Failed to read passphrase: {}", e))?
    };
    let keypair = AgentKeyPair::load_from_file(&id_path, &passphrase)?;
    std::env::remove_var("QYPHA_PASSPHRASE");
    if crate::agent::init::sync_config_identity_fields(&mut config, &keypair) {
        tracing::warn!(
            did = %config.agent.did,
            name = %config.agent.name,
            role = %config.agent.role,
            "Recovered stale config identity fields from encrypted agent identity"
        );
        if let Ok(config_path) = std::env::var("QYPHA_ACTIVE_CONFIG_PATH") {
            let config_passphrase = crate::config::config_passphrase_from_env();
            if let Err(error) = crate::agent::init::write_config_to_path(
                std::path::Path::new(&config_path),
                &config,
                config_passphrase.as_deref(),
            ) {
                tracing::warn!(
                    path = %config_path,
                    %error,
                    "Failed to persist recovered config identity fields"
                );
            }
        }
    }

    // ── OPSEC: Ghost mode transport enforcement ──
    // LAN/Internet expose IP — force upgrade to Tor for Ghost mode
    if effective_log_mode == "ghost"
        && matches!(
            config.network.transport_mode,
            TransportMode::Tcp | TransportMode::Internet
        )
    {
        println!(
            "   {} LAN/Internet transport exposes IP — forcing Tor for Ghost OPSEC",
            "GHOST WARNING:".red().bold()
        );
        config.network.transport_mode = TransportMode::Tor;
    }

    let _ghost_tor_guard = if effective_log_mode == "ghost"
        && matches!(config.network.transport_mode, TransportMode::Tor)
    {
        let tmp =
            tempfile::tempdir().map_err(|e| anyhow::anyhow!("Ghost Tor tmpdir failed: {}", e))?;
        println!(
            "   {} Tor state redirected to volatile tmpdir (zero disk trace)",
            "GHOST:".red().bold()
        );
        config.network.tor.data_dir = Some(tmp.path().to_string_lossy().to_string());
        Some(tmp)
    } else {
        None
    };

    let is_ghost = effective_log_mode == "ghost";

    // ── Ghost pre-flight: prevent forensic traces (same as launch path) ──
    if is_ghost {
        println!(
            "   {} Activating Ghost forensic prevention (start --log-mode ghost path)",
            "GHOST:".red().bold()
        );
        GHOST_MODE_ACTIVE.store(true, Ordering::SeqCst);
        // Set env var for child process awareness
        std::env::set_var("QYPHA_LOG_MODE", "ghost");
    }

    let result = start_daemon_inner(
        config,
        keypair,
        agent_data_dir,
        bootstrap_peer,
        log_mode_override,
    )
    .await;

    // ── Ghost post-flight: forensic cleanup on exit ──
    if is_ghost {
        println!(
            "\n   {} Running post-daemon forensic cleanup...",
            "GHOST:".red().bold()
        );
        // Wipe Ghost received files
        let ghost_recv_dir = runtime_temp_path("qypha-ghost-recv");
        if ghost_recv_dir.exists() {
            secure_wipe_dir(&ghost_recv_dir);
        }
        let ghost_handoff_dir = runtime_temp_path("qypha-ghost-handoff");
        if ghost_handoff_dir.exists() {
            secure_wipe_dir(&ghost_handoff_dir);
        }
        // Wipe chunked transfer temps
        let transfer_dir = runtime_temp_path("qypha-transfer");
        if transfer_dir.exists() {
            secure_wipe_dir(&transfer_dir);
        }
        let session_dir = runtime_temp_path("qypha-sessions");
        if session_dir.exists() {
            secure_wipe_dir(&session_dir);
        }
        println!(
            "   {} Ghost temp files securely wiped",
            "GHOST:".red().bold()
        );
    }

    result
}

/// Inner daemon logic shared by Safe startup path and ghost launch path.
pub(crate) async fn start_daemon_inner(
    mut config: AppConfig,
    keypair: AgentKeyPair,
    agent_data_dir: std::path::PathBuf,
    bootstrap_peer: Option<String>,
    log_mode_override: Option<String>,
) -> Result<()> {
    let runtime_mode = configure_runtime_mode(&mut config, log_mode_override)?;
    let log_mode = runtime_mode.log_mode.clone();
    let log_mode_str = runtime_mode.log_mode_str.clone();
    let is_zero_trace = runtime_mode.is_zero_trace;
    let privacy_hardened_mode = runtime_mode.privacy_hardened_mode;

    let safe_runtime_temp_root = if matches!(log_mode, LogMode::Safe) {
        let root = configure_safe_runtime_temp_root(&agent_data_dir).map_err(|e| {
            anyhow::anyhow!(
                "Failed to initialize Safe runtime temp root under {}: {}",
                agent_data_dir.display(),
                e
            )
        })?;
        let wiped = wipe_stale_safe_temp_artifacts(&root);
        if wiped > 0 {
            println!(
                "   {} startup janitor wiped {} stale Safe temp artifact dir(s)",
                "SAFE:".yellow().bold(),
                wiped
            );
        }
        Some(root)
    } else {
        None
    };
    let _safe_runtime_tmp_env = safe_runtime_temp_root
        .as_ref()
        .map(|root| ScopedEnvVarRestore::set("QYPHA_RUNTIME_TMPDIR", root));

    let (local_contact_profile, local_contact_did) =
        crate::agent::init::build_contact_identity_artifacts(
            &agent_data_dir,
            &keypair,
            &config,
            &log_mode,
        )?;

    if !is_zero_trace {
        match KeyStore::agent_keys_dir(&config.agent.name).and_then(|keys_dir| {
            crate::agent::init::export_contact_artifacts(
                &keys_dir,
                &agent_data_dir,
                &keypair,
                &config,
                &log_mode,
            )
        }) {
            Ok(exported) => {
                tracing::info!(
                    contact_did = %exported.contact_did,
                    contact_did_path = %exported.contact_did_path.display(),
                    "Exported shareable contact DID artifacts"
                );
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    agent = %config.agent.name,
                    "Failed to refresh shareable contact DID artifacts"
                );
            }
        }
    }

    install_runtime_guards(&keypair, &log_mode);

    let log_dir = agent_data_dir.join("audit");
    let x25519_secret = keypair.x25519_secret_key_bytes();
    let kyber_secret = if keypair.kyber_secret.is_empty() {
        None
    } else {
        Some(keypair.kyber_secret.as_slice())
    };
    let audit_root_key = AuditLog::derive_root_key_from_secrets(&x25519_secret, kyber_secret);
    let audit = Arc::new(tokio::sync::Mutex::new(AuditLog::new(
        &log_dir,
        &config.agent.did,
        &audit_root_key,
        log_mode.clone(),
    )?));

    // ── Initialize RBAC engine ──────────────────────────────────────────────
    let rbac_path = agent_data_dir.join("rbac.json");
    let rbac = if rbac_path.exists() {
        RbacEngine::load(&rbac_path).unwrap_or_else(|_| {
            RbacEngine::from_config(
                &config.roles.definitions,
                &config.roles.assignments,
                &rbac_path,
            )
        })
    } else {
        let engine = RbacEngine::from_config(
            &config.roles.definitions,
            &config.roles.assignments,
            &rbac_path,
        );
        engine
    };

    let rbac = Arc::new(tokio::sync::RwLock::new(rbac));

    // Role system disabled: all agents use a single unrestricted role.
    // Register our own agent in RBAC
    {
        let mut rbac_w = rbac.write().await;
        rbac_w.register_agent_by_role(&config.agent.did, DEFAULT_AGENT_ROLE);
    }

    let _policy = Arc::new(PolicyEngine::new(rbac.clone()));

    // ── Initialize security guards ──────────────────────────────────────────
    let replay_window_ms = config.security.replay_window_seconds * 1000;
    let replay_guard = Arc::new(tokio::sync::Mutex::new(ReplayGuard::new(
        config.security.nonce_window_size as usize,
        replay_window_ms,
    )));

    let rate_limiter = Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        config.security.rate_limit_per_minute as usize,
        60, // 1 minute window
    )));
    // Chunked file transfers legitimately emit many signed requests per minute.
    // Keep strict limits for chat/control traffic, but use a separate high-water
    // limiter for ChunkData to avoid breaking large transfers.
    let chunk_rate_limit_per_minute = std::cmp::max(
        (config.security.rate_limit_per_minute as usize).saturating_mul(64),
        6000,
    );
    let chunk_rate_limiter = Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        chunk_rate_limit_per_minute,
        60, // 1 minute window
    )));

    // ── Double Ratchet: per-peer forward secrecy ────────────────────────────
    // Ghost: default no disk staging (RAM-only transfer buffers),
    // unless explicitly enabled for content-only temporary disk staging.
    let zero_trace_disk_staging =
        is_zero_trace && config.transfer.allow_disk_chunk_staging_in_zero_trace;
    let ram_only_chunk_staging = is_zero_trace && !zero_trace_disk_staging;
    // Do not persist resumable session metadata when:
    // - zero-trace mode, or
    // - Tor transport, or
    // - operator disabled resume persistence.
    let no_resume_session_persistence = privacy_hardened_mode
        || matches!(config.network.transport_mode, TransportMode::Tor)
        || !config.transfer.enable_resume;
    // Tor/Safe/Ghost: never write persistent local artifact-store copies.
    let no_persistent_artifact_store =
        privacy_hardened_mode || matches!(config.network.transport_mode, TransportMode::Tor);
    let strict_pqc_runtime =
        matches!(config.network.transport_mode, TransportMode::Tor) || privacy_hardened_mode;
    if strict_pqc_runtime && (keypair.kyber_public.is_empty() || keypair.kyber_secret.is_empty()) {
        return Err(anyhow::anyhow!(
            "Strict Tor/Safe/Ghost security requires Kyber keys. Re-initialize agent identity with PQC support."
        ));
    }
    if zero_trace_disk_staging {
        println!(
            "   {} zero-trace disk staging enabled: large transfers use temp files (metadata remains in-memory)",
            "WARNING:".yellow().bold()
        );
    }
    let ratchet_persist_dir = if privacy_hardened_mode {
        None
    } else {
        Some(agent_data_dir.join("ratchet"))
    };
    let ratchet_persist_key = if privacy_hardened_mode {
        None
    } else {
        // Derive ratchet persistence key from agent's X25519 secret
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"Qypha-Ratchet-Persist-Key");
        hasher.update(&keypair.x25519_secret_key_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Some(key)
    };
    let ratchet_mgr = Arc::new(tokio::sync::Mutex::new(
        crate::crypto::double_ratchet::RatchetManager::new(
            ratchet_persist_dir,
            ratchet_persist_key,
        ),
    ));
    let pending_hybrid_ratchet_inits: Arc<DashMap<String, PendingHybridRatchetInit>> =
        Arc::new(DashMap::new());
    // Load persisted ratchet sessions only in persistent modes.
    if !privacy_hardened_mode {
        let _ = ratchet_mgr.lock().await.load_all();
    }

    // Generate initial ratchet DH keypair (akin to Signal's signed prekey).
    // Public key is shared in handshakes; secret is used for responder sessions.
    let ratchet_init_dh = crate::crypto::double_ratchet::RatchetKeyPair::generate();
    let ratchet_init_secret_bytes: [u8; 32] = ratchet_init_dh.secret.to_bytes();
    let ratchet_init_pub_hex = hex::encode(ratchet_init_dh.public.as_bytes());
    drop(ratchet_init_dh);

    // ── Shared peer state: PeerId string → PeerInfo ────────────────────────
    let peers: Arc<DashMap<String, PeerInfo>> = Arc::new(DashMap::new());
    let active_chat_target_did: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let active_chat_target_group_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let active_chat_target_group_label: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let iroh_peer_liveness: Arc<DashMap<String, IrohPeerLiveness>> = Arc::new(DashMap::new());
    let iroh_handshake_sync: Arc<DashMap<String, IrohHandshakeSyncState>> =
        Arc::new(DashMap::new());
    let iroh_authenticated_sessions: Arc<IrohAuthenticatedSessionMap> = Arc::new(DashMap::new());
    let active_incoming_iroh_transfers: Arc<DashMap<String, ActiveIncomingIrohTransfer>> =
        Arc::new(DashMap::new());
    let receive_dir_path = receive_dir_store_path(&agent_data_dir);
    let loaded_receive_dir_config = load_receive_dir_config(&receive_dir_path);
    if matches!(log_mode, LogMode::Safe) {
        if let Err(error) = harden_configured_receive_dirs(&loaded_receive_dir_config) {
            tracing::warn!(%error, "Failed to harden configured receive directories for Safe mode");
            println!(
                "   {} could not fully harden configured receive directories: {}",
                "Warning:".yellow().bold(),
                error
            );
        }
    }
    let receive_dir_config = Arc::new(tokio::sync::Mutex::new(loaded_receive_dir_config));

    // ── Channels ──────────────────────────────────────────────────────────
    let (msg_tx, msg_rx) = mpsc::channel::<crate::network::IncomingRequestEnvelope>(256);
    let (priority_msg_tx, priority_msg_rx) =
        mpsc::channel::<crate::network::IncomingRequestEnvelope>(32);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(256);
    let msg_tx_repl = msg_tx.clone();
    let transfer_decisions = Arc::new(tokio::sync::Mutex::new(TransferDecisionState::default()));
    let transfer_start_approvals = Arc::new(tokio::sync::Mutex::new(HashMap::<
        String,
        TransferStartApproval,
    >::new()));
    let pending_contact_requests =
        Arc::new(tokio::sync::Mutex::new(ContactRequestRegistry::default()));

    // ── Start transport backend ─────────────────────────────────────────────
    let iroh_endpoint_secret_bytes = resolve_iroh_endpoint_secret_bytes(
        &agent_data_dir,
        &log_mode,
        &config.network.transport_mode,
        &keypair,
    )?;
    let mut transport = start_transport_backend(
        &config,
        iroh_endpoint_secret_bytes,
        msg_tx.clone(),
        priority_msg_tx.clone(),
    )
    .await?;
    let internet_mode = transport.internet_mode;

    print_startup_banner(
        &config,
        transport.network.as_ref(),
        internet_mode,
        transport.iroh_endpoint_id.as_deref(),
        transport.iroh_invite_addr.as_ref(),
        &transport.our_peer_id,
        &log_mode,
        Some(local_contact_did.as_str()),
    );

    let published_contact_profile = if matches!(config.network.transport_mode, TransportMode::Tor) {
        match transport.network.as_ref() {
            Some(network) => build_runtime_tor_did_profile(&keypair, &config, network)?,
            None => local_contact_profile.clone(),
        }
    } else {
        local_contact_profile.clone()
    };

    let group_mailbox_store_path = group_mailboxes_store_path(&agent_data_dir, &log_mode);
    let group_mailbox_persist_key = group_mailbox_store_path
        .as_ref()
        .map(|_| derive_group_mailbox_persist_key(&keypair));
    let peer_store_persist_key = matches!(log_mode, LogMode::Safe)
        .then(|| derive_agent_scoped_persist_key(&keypair, SAFE_PEER_STORE_PERSIST_KEY_SCOPE));
    let used_invites_persist_key = (!matches!(log_mode, LogMode::Ghost))
        .then(|| derive_agent_scoped_persist_key(&keypair, USED_INVITES_PERSIST_KEY_SCOPE));
    let handshake_request_gate_persist_key = (!matches!(log_mode, LogMode::Ghost)).then(|| {
        derive_agent_scoped_persist_key(&keypair, HANDSHAKE_REQUEST_GATE_PERSIST_KEY_SCOPE)
    });
    let incoming_connect_gate_persist_key = (!matches!(log_mode, LogMode::Ghost)).then(|| {
        derive_agent_scoped_persist_key(&keypair, INCOMING_CONNECT_GATE_PERSIST_KEY_SCOPE)
    });
    let peer_bootstrap = initialize_peer_bootstrap_state(
        &agent_data_dir,
        &log_mode,
        &log_mode_str,
        peer_store_persist_key,
        used_invites_persist_key,
        handshake_request_gate_persist_key,
        incoming_connect_gate_persist_key,
    );
    let peer_store = peer_bootstrap.peer_store.clone();
    let used_invites_path = peer_bootstrap.used_invites_path.clone();
    let used_invites_persist_key = peer_bootstrap.used_invites_persist_key;
    let used_invites = peer_bootstrap.used_invites.clone();
    let group_mailboxes = peer_bootstrap.group_mailboxes.clone();
    let mailbox_transport = Arc::new(TorMailboxTransport::new(
        config
            .network
            .mailbox
            .client_tor_data_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| agent_data_dir.join("mailbox_tor_client")),
    ));
    let contact_mailbox_transport = Arc::new(ContactMailboxTransport::new(
        config
            .network
            .mailbox
            .client_tor_data_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| agent_data_dir.join("contact_mailbox_tor_client")),
    ));
    let contact_bundle_transport = Arc::new(
        crate::network::contact_bundle_transport::ContactBundleTransport::new(
            config
                .network
                .mailbox
                .client_tor_data_dir
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| agent_data_dir.join("contact_bundle_tor_client")),
        ),
    );
    let group_invite_bundle_transport = Arc::new(
        crate::network::group_invite_bundle_transport::GroupInviteBundleTransport::new(
            config
                .network
                .mailbox
                .client_tor_data_dir
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| agent_data_dir.join("group_invite_bundle_tor_client")),
        ),
    );
    let mut public_contact_bundle_service = if config.network.iroh.relay_enabled {
        match crate::network::contact_bundle_iroh::IrohContactBundleService::start(
            &config.network.iroh,
            &local_contact_did,
        )
        .await
        {
            Ok(service) => {
                service
                    .publish(local_contact_did.clone(), published_contact_profile.clone())
                    .await;
                Some(service)
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    did = %local_contact_did,
                    "Failed to start public iroh contact bundle service"
                );
                None
            }
        }
    } else {
        None
    };
    let public_group_invite_bundle_service = if config.network.iroh.relay_enabled {
        match crate::network::group_invite_bundle_iroh::IrohGroupInviteBundleService::start(
            &config.network.iroh,
            &local_contact_did,
        )
        .await
        {
            Ok(service) => Some(Arc::new(service)),
            Err(error) => {
                tracing::warn!(
                    %error,
                    did = %local_contact_did,
                    "Failed to start public iroh group invite bundle service"
                );
                None
            }
        }
    } else {
        None
    };
    if let Some(endpoint) =
        crate::network::discovery::tor::resolve_public_bundle_endpoint_from_config(
            &config,
            &keypair.did,
        )
    {
        let request = crate::network::contact_bundle::ContactBundlePutRequest::new(
            local_contact_did.clone(),
            published_contact_profile.clone(),
        );
        if let Err(error) = contact_bundle_transport
            .put_to_endpoint(&endpoint, &request)
            .await
        {
            tracing::warn!(
                %error,
                endpoint = %endpoint,
                did = %local_contact_did,
                "Failed to publish contact bundle to public Tor discovery cache"
            );
        }
    }
    let direct_peer_dids = peer_bootstrap.direct_peer_dids.clone();
    let invite_proof_by_peer = peer_bootstrap.invite_proof_by_peer.clone();
    let manual_disconnect_dids = peer_bootstrap.manual_disconnect_dids.clone();
    let remote_offline_dids = peer_bootstrap.remote_offline_dids.clone();
    let ip_hidden = peer_bootstrap.ip_hidden.clone();
    let handshake_request_gate = peer_bootstrap.handshake_request_gate.clone();
    let incoming_connect_gate = peer_bootstrap.incoming_connect_gate.clone();
    {
        let mut registry = group_mailboxes.lock().await;
        registry.configure_persistence(group_mailbox_store_path.clone(), group_mailbox_persist_key);
        if let Err(error) = registry.load_persisted() {
            tracing::warn!(%error, "Failed to load persisted mailbox groups");
            println!(
                "   {} encrypted mailbox group restore failed: {}",
                "Warning:".yellow().bold(),
                error
            );
        }
    }
    {
        let gate = handshake_request_gate.lock().await;
        handshake_request_gate::emit_headless_policy_snapshot(&gate.snapshot());
    }
    {
        let gate = incoming_connect_gate.lock().await;
        incoming_connect_gate::emit_headless_policy_snapshot(&gate.snapshot());
    }
    let restorable_local_mailbox_group_ids = {
        let registry = group_mailboxes.lock().await;
        local_embedded_mailbox_group_ids_to_restore(&agent_data_dir, &registry.cloned_sessions())
    };
    for group_id in restorable_local_mailbox_group_ids {
        let endpoint =
            match restore_local_embedded_mailbox_service(&config, &agent_data_dir, &group_id).await
            {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let failure = {
                        let mut registry = group_mailboxes.lock().await;
                        registry.note_mailbox_transport_failure(
                            &group_id,
                            config.network.mailbox.poll_interval_ms,
                            chrono::Utc::now().timestamp_millis().max(0) as u64,
                        )
                    };
                    if failure.should_log {
                        let group_log_id = redacted_log_marker("group", &group_id);
                        tracing::warn!(
                            group_id = %group_log_id,
                            retry_in_ms = failure.next_retry_after_ms,
                            consecutive_failures = failure.failures,
                            %error,
                            "Failed to restore embedded mailbox relay; group remains degraded"
                        );
                        println!(
                            "   {} {}",
                            "Mailbox warning:".yellow().bold(),
                            format!("{} restore is degraded; retrying in background", group_id)
                                .dimmed()
                        );
                    } else {
                        println!(
                            "   {} {}",
                            "Mailbox status:".yellow().bold(),
                            format!(
                                "{} restore is retrying in {} ms",
                                group_id, failure.next_retry_after_ms
                            )
                            .dimmed()
                        );
                    }
                    continue;
                }
            };
        {
            let mut registry = group_mailboxes.lock().await;
            let endpoint_changed = registry.update_mailbox_endpoint(&group_id, &endpoint)?;
            if endpoint_changed {
                tracing::warn!(
                    group_id = %group_id,
                    endpoint = %endpoint,
                    "Persisted mailbox group endpoint drifted; synced restored local relay endpoint"
                );
            }
        }
        match probe_group_mailbox_health(&group_mailboxes, &mailbox_transport, &group_id, 3).await {
            Ok(()) => {
                println!(
                    "   {} {}",
                    "Mailbox:".yellow().bold(),
                    format!(
                        "restored dedicated Tor relay for {} at {}",
                        group_id, endpoint
                    )
                    .dimmed()
                );
            }
            Err((error, failure)) => {
                if failure.should_log {
                    let group_log_id = redacted_log_marker("group", &group_id);
                    tracing::warn!(
                        group_id = %group_log_id,
                        retry_in_ms = failure.next_retry_after_ms,
                        consecutive_failures = failure.failures,
                        %error,
                        "Mailbox restore probe failed; group remains degraded"
                    );
                    println!(
                        "   {} {}",
                        "Mailbox warning:".yellow().bold(),
                        format!(
                            "{} relay restored but health probe failed; retrying in {} ms",
                            group_id, failure.next_retry_after_ms
                        )
                        .dimmed()
                    );
                } else {
                    println!(
                        "   {} {}",
                        "Mailbox status:".yellow().bold(),
                        format!(
                            "{} relay probe is retrying in {} ms",
                            group_id, failure.next_retry_after_ms
                        )
                        .dimmed()
                    );
                }
            }
        }
    }

    // ── Initial audit event ────────────────────────────────────────────────
    record_agent_start(
        &audit,
        &config.agent.did,
        config.network.listen_port,
        &log_mode_str,
    )
    .await;

    let mut initial_iroh_reconnects = Vec::new();
    bootstrap_connections(
        &mut transport,
        &config,
        bootstrap_peer.as_ref(),
        &direct_peer_dids,
        &peer_store,
        &mut initial_iroh_reconnects,
    )
    .await;
    let our_peer_id = transport.our_peer_id;
    let mut network = transport.network;
    let mut iroh_network = transport.iroh_network;

    let incoming_runtime = spawn_incoming_message_handler(
        IncomingMessageContext {
            peers: peers.clone(),
            invite_proof_by_peer: invite_proof_by_peer.clone(),
            agent_name: config.agent.name.clone(),
            keypair: keypair.clone(),
            audit: audit.clone(),
            replay_guard: replay_guard.clone(),
            rate_limiter: rate_limiter.clone(),
            chunk_rate_limiter: chunk_rate_limiter.clone(),
            log_mode: log_mode.clone(),
            peer_store: peer_store.clone(),
            used_invites: used_invites.clone(),
            used_invites_path: used_invites_path.clone(),
            used_invites_persist_key,
            default_ttl: config.security.message_ttl_ms,
            transport_mode: config.network.transport_mode.clone(),
            our_did: config.agent.did.clone(),
            local_onion_address: network
                .as_ref()
                .and_then(|transport| transport.onion_address.clone()),
            rbac: rbac.clone(),
            ratchet_mgr: ratchet_mgr.clone(),
            pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits.clone(),
            ratchet_init_secret: ratchet_init_secret_bytes,
            cmd_tx: cmd_tx.clone(),
            transfer_decisions: transfer_decisions.clone(),
            transfer_start_approvals: transfer_start_approvals.clone(),
            pending_contact_requests: pending_contact_requests.clone(),
            incoming_connect_gate: incoming_connect_gate.clone(),
            direct_peer_dids: direct_peer_dids.clone(),
            active_chat_target_did: active_chat_target_did.clone(),
            active_chat_target_group_label: active_chat_target_group_label.clone(),
            manual_disconnect_dids: manual_disconnect_dids.clone(),
            remote_offline_dids: remote_offline_dids.clone(),
            iroh_peer_liveness: iroh_peer_liveness.clone(),
            iroh_handshake_sync: iroh_handshake_sync.clone(),
            iroh_authenticated_sessions: iroh_authenticated_sessions.clone(),
            active_incoming_iroh_transfers: active_incoming_iroh_transfers.clone(),
            receive_dir_config: receive_dir_config.clone(),
        },
        msg_rx,
        priority_msg_rx,
    );
    let active_recv_for_swarm = Arc::clone(&incoming_runtime.active_receive_count);

    // ─────────────────────────────────────────────────────────────────────
    // Spawn: network event loop
    // ─────────────────────────────────────────────────────────────────────
    let peers_net = peers.clone();
    let config_net = config.clone();
    let sign_key = keypair.signing_key.clone();
    let keypair_net = keypair.clone();
    let audit_net = audit.clone();
    let rbac_net = rbac.clone();
    let peer_store_net = peer_store.clone();
    let used_invites_net = used_invites.clone();
    let used_invites_path_net = used_invites_path.clone();
    let used_invites_persist_key_net = used_invites_persist_key;
    let group_mailboxes_net = group_mailboxes.clone();
    let handshake_request_gate_net = handshake_request_gate.clone();
    let incoming_connect_gate_net = incoming_connect_gate.clone();
    let mailbox_transport_net = mailbox_transport.clone();
    let contact_mailbox_transport_net = contact_mailbox_transport.clone();
    let contact_bundle_transport_net = contact_bundle_transport.clone();
    let group_invite_bundle_transport_net = group_invite_bundle_transport.clone();
    let public_group_invite_bundle_service_net = public_group_invite_bundle_service.clone();
    let invite_proof_net = invite_proof_by_peer.clone();
    let manual_disconnect_dids_net = manual_disconnect_dids.clone();
    let remote_offline_dids_net = remote_offline_dids.clone();
    let ip_hidden_net = ip_hidden.clone();
    let cmd_tx_net = cmd_tx.clone(); // for Tor re-dial commands from within network task
    let ratchet_mgr_net = ratchet_mgr.clone();
    let ratchet_init_pub_hex_net = ratchet_init_pub_hex.clone();
    let transfer_start_approvals_net = transfer_start_approvals.clone();
    let log_mode_net = log_mode.clone();
    let receive_dir_config_net = receive_dir_config.clone();
    let direct_peer_dids_net = direct_peer_dids.clone();
    let iroh_peer_liveness_net = iroh_peer_liveness.clone();
    let iroh_handshake_sync_net = iroh_handshake_sync.clone();
    let iroh_authenticated_sessions_net = iroh_authenticated_sessions.clone();
    let active_incoming_iroh_transfers_net = active_incoming_iroh_transfers.clone();
    let active_chat_target_did_net = active_chat_target_did.clone();

    if !internet_mode {
        let network = network.expect("network backend must exist for non-Internet modes");
        spawn_libp2p_runtime(
            Libp2pRuntimeContext {
                agent_data_dir: agent_data_dir.clone(),
                peers: peers_net,
                config: config_net,
                sign_key,
                keypair: keypair_net,
                audit: audit_net,
                rbac: rbac_net,
                peer_store: peer_store_net,
                used_invites: used_invites_net,
                used_invites_path: used_invites_path_net,
                used_invites_persist_key: used_invites_persist_key_net,
                group_mailboxes: group_mailboxes_net,
                handshake_request_gate: handshake_request_gate_net,
                mailbox_transport: mailbox_transport_net,
                contact_mailbox_transport: contact_mailbox_transport_net,
                contact_bundle_transport: contact_bundle_transport_net,
                group_invite_bundle_transport: group_invite_bundle_transport_net,
                public_group_invite_bundle_service: public_group_invite_bundle_service_net,
                invite_proof_by_peer: invite_proof_net,
                manual_disconnect_dids: manual_disconnect_dids_net,
                remote_offline_dids: remote_offline_dids_net,
                ip_hidden: ip_hidden_net,
                cmd_tx: cmd_tx_net,
                ratchet_mgr: ratchet_mgr_net,
                pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits.clone(),
                ratchet_init_pub_hex: ratchet_init_pub_hex_net,
                transfer_start_approvals: transfer_start_approvals_net,
                pending_contact_requests: pending_contact_requests.clone(),
                incoming_connect_gate: incoming_connect_gate_net.clone(),
                log_mode: log_mode_net,
                receive_dir_config: receive_dir_config_net.clone(),
                direct_peer_dids: direct_peer_dids_net,
                msg_tx: msg_tx.clone(),
                active_receive_count: active_recv_for_swarm,
                active_incoming_iroh_transfers: active_incoming_iroh_transfers_net,
                active_chat_target_did: active_chat_target_did_net,
                our_peer_id,
                no_resume_session_persistence,
                no_persistent_artifact_store,
                ram_only_chunk_staging,
            },
            network,
            cmd_rx,
        );
    } else {
        let iroh_network = iroh_network.expect("iroh backend must exist for Internet mode");
        spawn_iroh_runtime(
            IrohRuntimeContext {
                agent_data_dir: agent_data_dir.clone(),
                peers: peers_net,
                config: config_net,
                sign_key,
                keypair: keypair_net,
                audit: audit_net,
                rbac: rbac_net,
                peer_store: peer_store_net,
                used_invites: used_invites_net,
                used_invites_path: used_invites_path_net,
                used_invites_persist_key: used_invites_persist_key_net,
                group_mailboxes: group_mailboxes_net,
                handshake_request_gate: handshake_request_gate_net,
                mailbox_transport: mailbox_transport_net,
                contact_mailbox_transport: contact_mailbox_transport_net,
                contact_bundle_transport: contact_bundle_transport_net,
                group_invite_bundle_transport: group_invite_bundle_transport_net,
                public_group_invite_bundle_service: public_group_invite_bundle_service_net,
                invite_proof_by_peer: invite_proof_net,
                manual_disconnect_dids: manual_disconnect_dids_net,
                remote_offline_dids: remote_offline_dids_net,
                ratchet_mgr: ratchet_mgr_net,
                pending_hybrid_ratchet_inits: pending_hybrid_ratchet_inits.clone(),
                ratchet_init_pub_hex: ratchet_init_pub_hex_net,
                transfer_start_approvals: transfer_start_approvals_net,
                pending_contact_requests: pending_contact_requests.clone(),
                incoming_connect_gate: incoming_connect_gate_net,
                direct_peer_dids: direct_peer_dids_net,
                iroh_peer_liveness: iroh_peer_liveness_net,
                iroh_handshake_sync: iroh_handshake_sync_net,
                iroh_authenticated_sessions: iroh_authenticated_sessions_net,
                active_incoming_iroh_transfers: active_incoming_iroh_transfers_net,
                active_chat_target_did: active_chat_target_did_net,
                receive_dir_config: receive_dir_config_net,
                log_mode: log_mode.clone(),
                no_persistent_artifact_store,
                initial_iroh_reconnects,
            },
            iroh_network,
            cmd_rx,
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Interactive REPL (rustyline — raw mode, no terminal buffer limit)
    // ─────────────────────────────────────────────────────────────────────
    // Rustyline puts the terminal in raw mode, reading input character by
    // character. This bypasses the OS canonical-mode line buffer limit
    // (macOS MAX_CANON = 1024, Linux = 4096) that causes keyboard lockup
    // when pasting long invite codes (~4000+ chars with Kyber-1024 keys).

    let (line_tx, line_rx) = mpsc::channel::<String>(16);
    let repl_agent_name = config.agent.name.clone();
    let repl_disable_history = matches!(log_mode, LogMode::Safe | LogMode::Ghost);
    let repl_peers = peers.clone();
    let repl_direct_peer_dids = direct_peer_dids.clone();
    let repl_active_target_did = active_chat_target_did.clone();
    let repl_active_target_group_label = active_chat_target_group_label.clone();

    // Ack channel: main loop signals rustyline after command output is complete.
    // This prevents rustyline from re-prompting before output is printed.
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();

    spawn_repl_input_task(
        line_tx.clone(),
        repl_peers,
        repl_direct_peer_dids,
        repl_active_target_did,
        repl_active_target_group_label,
        repl_agent_name,
        repl_disable_history,
        ack_rx,
    );
    spawn_shutdown_signal_bridge(line_tx.clone());
    run_repl_command_loop(
        line_rx,
        ReplCommandContext {
            cmd_tx: cmd_tx.clone(),
            msg_tx_repl,
            peers,
            direct_peer_dids,
            active_chat_target_did,
            active_chat_target_group_id,
            active_chat_target_group_label,
            audit,
            agent_did: config.agent.did.clone(),
            receive_dir_config,
            receive_dir_path,
            peer_store,
            transfer_decisions,
            pending_contact_requests,
            group_mailboxes: group_mailboxes.clone(),
            handshake_request_gate: handshake_request_gate.clone(),
            incoming_connect_gate: incoming_connect_gate.clone(),
            ratchet_mgr: ratchet_mgr.clone(),
            agent_data_dir,
            log_mode: log_mode.clone(),
            ack_tx,
        },
    )
    .await?;
    request_network_shutdown(&cmd_tx).await;

    // In Ghost+Tor mode, explicitly drop the mailbox Tor client and give Arti a
    // brief moment to flush volatile state before the launcher wipes its tempdir.
    if matches!(log_mode, LogMode::Ghost)
        && matches!(config.network.transport_mode, TransportMode::Tor)
    {
        drop(mailbox_transport);
        tokio::task::yield_now().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }

    if let Some(service) = public_contact_bundle_service.take() {
        service.shutdown().await;
    }

    {
        let registry = group_mailboxes.lock().await;
        if let Err(error) = registry.persist_now() {
            tracing::warn!(%error, "Failed to persist mailbox groups during shutdown");
        }
    }

    // ── Cleanup: persist ratchet state (persistent) or wipe (zero-trace) ──
    {
        let mut rmgr = ratchet_mgr.lock().await;
        if privacy_hardened_mode {
            rmgr.secure_wipe();
        } else {
            let _ = rmgr.persist_all();
        }
    }

    if let Some(root) = safe_runtime_temp_root.as_ref() {
        let wiped = wipe_stale_safe_temp_artifacts(root);
        if wiped > 0 {
            println!(
                "   {} shutdown janitor wiped {} Safe temp artifact dir(s)",
                "SAFE:".yellow().bold(),
                wiped
            );
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Ghost Mode: Emergency Cleanup (Signal-Safe)
// ─────────────────────────────────────────────────────────────────────────────

/// Signal-safe emergency cleanup — uses ONLY async-signal-safe operations.
///
/// Called from panic hooks and signal handlers where malloc/fork are unsafe.
/// Uses raw libc::write() to stdout (fd 1) instead of Rust's stdio (which
/// uses locks and buffers). Does NOT call Command::new() (fork+exec) since
/// that can deadlock if a mutex is held when the signal arrives.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer_store::KnownPeer;

    fn sample_peer_info(did: &str) -> PeerInfo {
        PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: did.to_string(),
            name: "Peer".to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: None,
            verifying_key: None,
            aegis_supported: false,
            ratchet_dh_public: None,
        }
    }

    #[test]
    fn test_used_invites_store_path_is_disabled_only_for_ghost() {
        let root = std::path::PathBuf::from("/tmp/qypha-test");
        assert!(used_invites_store_path(&root, &LogMode::Safe).is_some());
        assert!(used_invites_store_path(&root, &LogMode::Ghost).is_none());
    }

    #[test]
    fn test_trusted_peer_identity_accepts_live_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        peers.insert("peer-1".to_string(), sample_peer_info("did:nxf:alice"));
        let store = PeerStore::new(None);

        assert!(is_trusted_peer_identity("did:nxf:alice", &peers, &store));
    }

    #[test]
    fn test_trusted_peer_identity_accepts_persisted_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        let mut store = PeerStore::new(None);
        store.upsert(KnownPeer {
            did: "did:nxf:bob".to_string(),
            name: "Bob".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWBob".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: true,
        });

        assert!(is_trusted_peer_identity("did:nxf:bob", &peers, &store));
    }

    #[test]
    fn test_trusted_peer_identity_rejects_unknown_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        let store = PeerStore::new(None);

        assert!(!is_trusted_peer_identity("did:nxf:mallory", &peers, &store));
    }

    #[test]
    fn test_desired_auto_reconnect_defaults_by_mode() {
        assert!(desired_auto_reconnect(&LogMode::Safe, None));
        assert!(!desired_auto_reconnect(&LogMode::Ghost, None));
    }

    #[test]
    fn test_safe_only_persists_trusted_new_peers() {
        assert!(!should_persist_known_peer(&LogMode::Safe, None, false));
        assert!(should_persist_known_peer(&LogMode::Safe, None, true));
        let existing = KnownPeer {
            did: "did:nxf:alice".to_string(),
            name: "Alice".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWAlice".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: false,
        };
        assert!(should_persist_known_peer(
            &LogMode::Safe,
            Some(&existing),
            false
        ));
    }

    #[test]
    fn test_build_known_peer_prefers_relay_only_iroh_reconnect_route() {
        let mut peer = sample_peer_info("did:nxf:alice");
        peer.onion_address = Some("freshonion".to_string());
        let endpoint_json =
            crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(41);
        let existing = KnownPeer {
            did: "did:nxf:alice".to_string(),
            name: "Alice".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWAlice".to_string(),
            onion_address: Some("oldonion".to_string()),
            tcp_address: Some("/ip4/127.0.0.1/tcp/9000".to_string()),
            iroh_endpoint_addr: Some(endpoint_json.clone()),
            onion_port: 1111,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 0,
            auto_reconnect: false,
        };

        let built = build_known_peer(&peer, Some(&existing), true);
        assert!(built.onion_address.is_none());
        assert!(built.tcp_address.is_none());
        assert_eq!(
            built.iroh_endpoint_addr.as_deref(),
            Some(endpoint_json.as_str())
        );
        assert_eq!(built.onion_port, 9090);
        assert!(built.auto_reconnect);
    }

    #[test]
    fn test_should_auto_send_iroh_handshake_for_invite_bound_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        let invites: DashMap<String, String> = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        invites.insert(peer_id.to_string(), "invite-code".to_string());

        assert!(should_auto_send_iroh_handshake(&peer_id, &peers, &invites));
    }

    #[test]
    fn test_should_auto_send_iroh_handshake_for_known_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        let invites: DashMap<String, String> = DashMap::new();
        let peer = sample_peer_info("did:nxf:alice");
        let peer_id = peer.peer_id;
        peers.insert(peer_id.to_string(), peer);

        assert!(should_auto_send_iroh_handshake(&peer_id, &peers, &invites));
    }

    #[test]
    fn test_should_not_auto_send_iroh_handshake_for_unknown_incoming_peer() {
        let peers: DashMap<String, PeerInfo> = DashMap::new();
        let invites: DashMap<String, String> = DashMap::new();
        let peer_id = libp2p::PeerId::random();
        peers.insert(peer_id.to_string(), sample_peer_info(""));

        assert!(!should_auto_send_iroh_handshake(&peer_id, &peers, &invites));
    }

    #[test]
    fn test_controlled_disconnect_reason_detected() {
        assert!(is_iroh_controlled_disconnect_reason(Some(
            "closed by peer: qypha-policy-disconnect (code 0)"
        )));
        assert!(!is_iroh_controlled_disconnect_reason(Some(
            "closed by peer: idle timeout"
        )));
        assert!(!is_iroh_controlled_disconnect_reason(None));
    }

    #[test]
    fn test_scoped_env_var_restore_restores_previous_value() {
        let key = "QYPHA_TEST_RUNTIME_TMPDIR";
        let original = std::path::Path::new("/tmp/original-runtime");
        let replacement = std::path::Path::new("/tmp/replacement-runtime");
        std::env::set_var(key, original);
        {
            let _guard = ScopedEnvVarRestore::set(key, replacement);
            assert_eq!(
                std::env::var_os(key).as_deref(),
                Some(replacement.as_os_str())
            );
        }
        assert_eq!(std::env::var_os(key).as_deref(), Some(original.as_os_str()));
        std::env::remove_var(key);
    }

    #[test]
    fn test_scoped_env_var_restore_removes_new_value_when_unset_before_scope() {
        let key = "QYPHA_TEST_RUNTIME_TMPDIR_UNSET";
        let replacement = std::path::Path::new("/tmp/replacement-runtime");
        std::env::remove_var(key);
        {
            let _guard = ScopedEnvVarRestore::set(key, replacement);
            assert_eq!(
                std::env::var_os(key).as_deref(),
                Some(replacement.as_os_str())
            );
        }
        assert!(std::env::var_os(key).is_none());
    }

    #[tokio::test]
    async fn test_shared_temp_file_cleanup_is_noop_but_owned_cleanup_wipes_file() {
        let shared_dir = tempfile::tempdir().unwrap();
        let shared_path = shared_dir.path().join("shared.bin");
        std::fs::write(&shared_path, b"shared-fast-transfer").unwrap();

        let mut shared = ChunkSource::SharedTempFile(shared_path.clone());
        shared.secure_cleanup_async().await;
        assert!(shared_path.exists());
        assert_eq!(
            std::fs::read(&shared_path).unwrap(),
            b"shared-fast-transfer"
        );

        let owned_dir = tempfile::tempdir().unwrap();
        let owned_path = owned_dir.path().join("owned.bin");
        std::fs::write(&owned_path, b"owned-fast-transfer").unwrap();

        let mut owned = ChunkSource::TempFile(owned_path.clone());
        owned.secure_cleanup_async().await;
        assert!(!owned_path.exists());
    }
}

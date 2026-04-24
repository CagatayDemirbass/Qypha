use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colored::Colorize;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::control_plane::audit::{AuditLog, LogMode};
use crate::network::contact_did::is_contact_did;
use crate::network::peer_store::PeerStore;
use crate::network::protocol::AgentRequest;

use super::contact_requests::ContactRequestRegistry;
use super::group_mailbox::{
    accept_pending_group_handshake_offer, approve_pending_group_file_offer,
    clear_pending_group_handshake_offers, describe_group, emit_ui_event,
    reject_pending_group_file_offer, reject_pending_group_handshake_offer, GroupMailboxRegistry,
    GroupMailboxUiEvent, GroupPendingFileOfferAction,
};
use super::handshake_request_gate::{self, HandshakeRequestGate, OutgoingHandshakeOfferDecision};
use super::incoming_connect_gate::{self, IncomingConnectGate};
use super::paths::{default_receive_root, emit_transfer_event, expand_receive_path};
use super::peer::{print_auto_reconnect_state, PeerInfo};
use super::receive_dir::{
    effective_receive_base_dir, ensure_private_receive_dir, harden_configured_receive_dirs,
    persist_receive_dir_config, ReceiveDirConfig,
};
use super::repl::{
    resolve_active_chat_peer, selected_reconnecting_direct_peer, sync_active_direct_prompt_target,
};
use super::selectors::{
    canonicalize_did_selector, resolve_direct_peer_selector, resolve_sender_selector,
    ConnectedPeerSelectorResolution, SenderSelectorResolution,
};
use super::transfer_gate::{
    IncomingTransferPolicy, PendingIncomingTransfer, PendingTransferKind, TransferDecisionState,
};
use super::NetworkCommand;

pub(crate) struct ReplCommandContext {
    pub(crate) cmd_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) msg_tx_repl: mpsc::Sender<crate::network::IncomingRequestEnvelope>,
    pub(crate) peers: Arc<DashMap<String, PeerInfo>>,
    pub(crate) direct_peer_dids: Arc<DashMap<String, bool>>,
    pub(crate) active_chat_target_did: Arc<Mutex<Option<String>>>,
    pub(crate) active_chat_target_group_id: Arc<Mutex<Option<String>>>,
    pub(crate) active_chat_target_group_label: Arc<Mutex<Option<String>>>,
    pub(crate) audit: Arc<tokio::sync::Mutex<AuditLog>>,
    pub(crate) agent_did: String,
    pub(crate) receive_dir_config: Arc<tokio::sync::Mutex<ReceiveDirConfig>>,
    pub(crate) receive_dir_path: PathBuf,
    pub(crate) peer_store: Arc<tokio::sync::Mutex<PeerStore>>,
    pub(crate) transfer_decisions: Arc<tokio::sync::Mutex<TransferDecisionState>>,
    pub(crate) pending_contact_requests: Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    pub(crate) group_mailboxes: Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    pub(crate) handshake_request_gate: Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    pub(crate) incoming_connect_gate: Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    pub(crate) ratchet_mgr: Arc<tokio::sync::Mutex<crate::crypto::double_ratchet::RatchetManager>>,
    pub(crate) agent_data_dir: PathBuf,
    pub(crate) log_mode: LogMode,
    pub(crate) ack_tx: std::sync::mpsc::Sender<()>,
}

async fn wait_output(tx: &mpsc::Sender<NetworkCommand>) {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let _ = tx.send(NetworkCommand::OutputDone(done_tx)).await;
    let _ = done_rx.await;
}

fn dispatch_background_command(cmd_tx: &mpsc::Sender<NetworkCommand>, cmd: NetworkCommand) {
    let tx = cmd_tx.clone();
    tokio::spawn(async move {
        if let Err(error) = tx.send(cmd).await {
            tracing::warn!(%error, "failed to dispatch background REPL command");
        }
    });
}

fn flush_command_output() {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

fn display_contact_request_did(pending: &super::contact_requests::PendingContactRequest) -> String {
    crate::network::contact_did::encode_contact_did(&pending.sender_profile)
        .unwrap_or_else(|_| pending.sender_did.clone())
}

fn print_ambiguous_selector(selector: &str, candidates: Vec<(String, String)>) {
    println!(
        "   {} selector '{}' is ambiguous. Use DID:",
        "Error:".red(),
        selector
    );
    for (did, name) in candidates {
        println!(
            "   - {} ({})",
            name.cyan(),
            crate::agent::contact_identity::displayed_did(&did).dimmed()
        );
    }
}

fn print_peer_not_found(selector: &str) {
    println!(
        "   {} peer '{}' not found. Use /peers or /all to inspect peers.",
        "Error:".red(),
        selector
    );
}

fn known_peer_disconnect_peer_id_hint(
    known_peer: &crate::network::peer_store::KnownPeer,
) -> Option<String> {
    if let Some(endpoint_addr_json) = known_peer.iroh_endpoint_addr.as_deref() {
        let endpoint_addr = serde_json::from_str::<iroh::EndpointAddr>(endpoint_addr_json).ok()?;
        return Some(
            crate::network::iroh_transport::peer_id_from_endpoint_id(&endpoint_addr.id).to_string(),
        );
    }

    let peer_id = known_peer.peer_id.trim();
    (!peer_id.is_empty()).then(|| peer_id.to_string())
}

fn clear_active_direct_target_if_matching(
    peers: &Arc<DashMap<String, PeerInfo>>,
    direct_peer_dids: &Arc<DashMap<String, bool>>,
    active_chat_target_did: &Arc<Mutex<Option<String>>>,
    active_chat_target_group_label: &Arc<Mutex<Option<String>>>,
    peer_did: &str,
) {
    let mut cleared = false;
    if let Ok(mut target) = active_chat_target_did.lock() {
        if target.as_deref() == Some(peer_did) {
            *target = None;
            cleared = true;
        }
    }
    if cleared {
        sync_active_direct_prompt_target(
            peers,
            active_chat_target_did,
            direct_peer_dids,
            Some(active_chat_target_group_label),
        );
    }
}

fn print_sender_not_found(selector: &str) {
    println!(
        "   {} sender '{}' not found (try /accept to list pending).",
        "Error:".red(),
        selector
    );
}

fn print_pending_target_not_found(selector: &str) {
    println!(
        "   {} pending selector '{}' not found (try /accept to list pending).",
        "Error:".red(),
        selector
    );
}

enum OutgoingHandshakeInvitePreflightError {
    Validation(String),
    RateLimited {
        member_id: String,
        retry_after_ms: u64,
    },
}

const UI_BRIDGE_PREFIX: &str = "/ui ";
const UI_BRIDGE_MAX_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum UiBridgeCommand {
    SendTo { selector: String, message: String },
    ConnectInvite { code: String },
    ConnectDid { did: String },
    DisconnectPeer { did: String },
    CreateGroup { anonymous: bool, name: String },
    GenerateGroupInvite { group_id: String },
    GenerateAnonymousGroupInvite { owner_special_id: String },
    Accept { selector: String },
    Reject { selector: String },
    Block { selector: String },
    AcceptAlways { selector: String },
    AcceptAsk { selector: String },
    SendGroupHandshakeInvite { group_id: String, member_id: String },
    SetHandshakeRequestBlock { member_id: String, blocked: bool },
    SetIncomingConnectBlock { did: String, blocked: bool },
    KickGroupMember { member_id: String },
    SetGroupJoinLock { group_id: String, locked: bool },
    LeaveGroup { group_id: String },
    DisbandGroup { group_id: String },
    TransferToPeer { selector: String, path: String },
    TransferToGroup { group_id: String, path: String },
    SetReceiveDir { path: Option<String> },
}

fn normalize_command_token(field: &str, value: String) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} is required"));
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(format!(
            "{field} contains forbidden whitespace or control characters"
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_command_text(field: &str, value: String) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} is required"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(format!("{field} contains forbidden control characters"));
    }
    Ok(trimmed.to_string())
}

fn trim_matching_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[trimmed.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

fn normalize_ui_bridge_command(command: UiBridgeCommand) -> Result<String, String> {
    match command {
        UiBridgeCommand::SendTo { selector, message } => Ok(format!(
            "/sendto {} {}",
            normalize_command_token("Selector", selector)?,
            normalize_command_text("Message", message)?
        )),
        UiBridgeCommand::ConnectInvite { code } => Ok(format!(
            "/connect {}",
            normalize_command_text("Invite code", code)?
        )),
        UiBridgeCommand::ConnectDid { did } => Ok(format!(
            "/connect {}",
            normalize_command_token("Peer DID", did)?
        )),
        UiBridgeCommand::DisconnectPeer { did } => Ok(format!(
            "/disconnect {}",
            normalize_command_token("Peer DID", did)?
        )),
        UiBridgeCommand::CreateGroup { anonymous, name } => {
            let name = normalize_command_text("Group name", name)?;
            Ok(if anonymous {
                format!("/group_anon {}", name)
            } else {
                format!("/group_normal {}", name)
            })
        }
        UiBridgeCommand::GenerateGroupInvite { group_id } => Ok(format!(
            "/invite_g {}",
            normalize_command_token("Group id", group_id)?
        )),
        UiBridgeCommand::GenerateAnonymousGroupInvite { owner_special_id } => Ok(format!(
            "/invite_anon {}",
            normalize_command_token("Owner special id", owner_special_id)?
        )),
        UiBridgeCommand::Accept { selector } => Ok(format!(
            "/accept {}",
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::Reject { selector } => Ok(format!(
            "/reject {}",
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::Block { selector } => Ok(format!(
            "/block {}",
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::AcceptAlways { selector } => Ok(format!(
            "/accept_always {}",
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::AcceptAsk { selector } => Ok(format!(
            "/accept_ask {}",
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::SendGroupHandshakeInvite {
            group_id,
            member_id,
        } => Ok(format!(
            "/invite_hg {} {}",
            normalize_command_token("Group id", group_id)?,
            normalize_command_token("Member id", member_id)?
        )),
        UiBridgeCommand::SetHandshakeRequestBlock { member_id, blocked } => Ok(format!(
            "{} {}",
            if blocked { "/block_r" } else { "/unblock_r" },
            normalize_command_token("Member id", member_id)?
        )),
        UiBridgeCommand::SetIncomingConnectBlock { did, blocked } => Ok(format!(
            "{} {}",
            if blocked { "/block_inv" } else { "/unlock_inv" },
            normalize_command_token("Peer DID", did)?
        )),
        UiBridgeCommand::KickGroupMember { member_id } => Ok(format!(
            "/kick_g {}",
            normalize_command_token("Member id", member_id)?
        )),
        UiBridgeCommand::SetGroupJoinLock { group_id, locked } => Ok(format!(
            "{} {}",
            if locked { "/lock_g" } else { "/unlock_g" },
            normalize_command_token("Group id", group_id)?
        )),
        UiBridgeCommand::LeaveGroup { group_id } => Ok(format!(
            "/leave_g {}",
            normalize_command_token("Group id", group_id)?
        )),
        UiBridgeCommand::DisbandGroup { group_id } => Ok(format!(
            "/disband {}",
            normalize_command_token("Group id", group_id)?
        )),
        UiBridgeCommand::TransferToPeer { selector, path } => Ok(format!(
            "/transfer {} {}",
            normalize_command_text("Transfer path", path)?,
            normalize_command_token("Selector", selector)?
        )),
        UiBridgeCommand::TransferToGroup { group_id, path } => Ok(format!(
            "/transfer_g {} {}",
            normalize_command_token("Group id", group_id)?,
            normalize_command_text("Transfer path", path)?
        )),
        UiBridgeCommand::SetReceiveDir { path } => match path {
            Some(path) => Ok(format!(
                "/set_receive_dir {}",
                normalize_command_text("Receive directory", path)?
            )),
            None => Ok("/set_receive_dir reset".to_string()),
        },
    }
}

fn decode_ui_bridge_line(raw_line: &str) -> Result<String, String> {
    let Some(payload) = raw_line.strip_prefix(UI_BRIDGE_PREFIX) else {
        return Ok(raw_line.to_string());
    };
    let payload = payload.trim();
    if payload.is_empty() {
        return Err("UI bridge payload is empty".to_string());
    }
    if payload.len() > UI_BRIDGE_MAX_PAYLOAD_LEN {
        return Err(format!(
            "UI bridge payload exceeds {} bytes",
            UI_BRIDGE_MAX_PAYLOAD_LEN
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "UI bridge payload is not valid base64".to_string())?;
    let command = serde_json::from_slice::<UiBridgeCommand>(&decoded)
        .map_err(|_| "UI bridge payload is not valid JSON".to_string())?;
    normalize_ui_bridge_command(command)
}

async fn preflight_outgoing_group_handshake_offer(
    group_mailboxes: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    handshake_request_gate: &Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    group_id: Option<&str>,
    member_id: &str,
) -> std::result::Result<String, OutgoingHandshakeInvitePreflightError> {
    let canonical_member_id = {
        let registry = group_mailboxes.lock().await;
        let resolved = match group_id {
            Some(group_id) => {
                registry.resolve_identified_handshake_target_in_group(group_id, member_id)
            }
            None => registry.resolve_identified_handshake_target(member_id),
        };
        match resolved {
            Ok((_session, profile)) => profile.member_id,
            Err(error) => {
                return Err(OutgoingHandshakeInvitePreflightError::Validation(
                    error.to_string(),
                ))
            }
        }
    };
    let decision = {
        let mut gate = handshake_request_gate.lock().await;
        gate.evaluate_outgoing_offer(
            &canonical_member_id,
            chrono::Utc::now().timestamp_millis().max(0) as u64,
        )
    };
    match decision {
        OutgoingHandshakeOfferDecision::Allow => Ok(canonical_member_id),
        OutgoingHandshakeOfferDecision::RateLimited { retry_after_ms } => {
            Err(OutgoingHandshakeInvitePreflightError::RateLimited {
                member_id: canonical_member_id,
                retry_after_ms,
            })
        }
    }
}

fn looks_like_group_id(selector: &str) -> bool {
    let selector = selector.trim();
    if selector.is_empty() {
        return false;
    }
    let known_prefix = selector.starts_with("grp_")
        || selector.starts_with("gmbx_")
        || selector.starts_with("group:");
    known_prefix
        && selector
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':'))
}

fn clear_active_group_target(
    active_chat_target_group_id: &Arc<Mutex<Option<String>>>,
    active_chat_target_group_label: &Arc<Mutex<Option<String>>>,
) {
    {
        let mut target = active_chat_target_group_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *target = None;
    }
    {
        let mut label = active_chat_target_group_label
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *label = None;
    }
}

async fn resolve_active_chat_group(
    group_mailboxes: &Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
    active_chat_target_group_id: &Arc<Mutex<Option<String>>>,
    active_chat_target_group_label: &Arc<Mutex<Option<String>>>,
) -> Option<String> {
    let group_id = active_chat_target_group_id
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()?;
    let exists = {
        let registry = group_mailboxes.lock().await;
        registry.get_cloned(&group_id).is_some()
    };
    if exists {
        return Some(group_id);
    }
    clear_active_group_target(active_chat_target_group_id, active_chat_target_group_label);
    None
}

fn print_pending_transfers(
    gate: &TransferDecisionState,
    pending_contact_requests: &ContactRequestRegistry,
    group_mailboxes: &GroupMailboxRegistry,
) {
    let group_offers = group_mailboxes.pending_file_offers();
    let handshake_offers = group_mailboxes.pending_handshake_offers();
    let contact_requests = pending_contact_requests.pending_cloned();
    if gate.pending_count() == 0
        && contact_requests.is_empty()
        && group_offers.is_empty()
        && handshake_offers.is_empty()
    {
        println!("   {}", "No pending approvals.".dimmed());
    } else {
        println!("   {}", "Pending approvals:".yellow().bold());
        for pending in gate.pending_transfers() {
            match pending.kind {
                PendingTransferKind::File {
                    filename,
                    encrypted_size,
                } => {
                    let mb = encrypted_size as f64 / (1024.0 * 1024.0);
                    println!(
                        "   - {} ({}) -> file {} ({:.1} MB, encrypted)",
                        pending.sender_name.cyan(),
                        crate::agent::contact_identity::displayed_did(&pending.sender_did).dimmed(),
                        filename.cyan(),
                        mb
                    );
                }
                PendingTransferKind::ChunkInit {
                    total_chunks,
                    sealed_v2,
                    filename_hint,
                    total_size_hint,
                    ..
                } => {
                    if sealed_v2 {
                        println!(
                            "   - {} ({}) -> chunked transfer ({} chunks, sealed v2)",
                            pending.sender_name.cyan(),
                            crate::agent::contact_identity::displayed_did(&pending.sender_did)
                                .dimmed(),
                            total_chunks
                        );
                    } else {
                        let name = filename_hint.unwrap_or_else(|| "unknown".to_string());
                        let mb = total_size_hint.unwrap_or_default() as f64 / (1024.0 * 1024.0);
                        println!(
                            "   - {} ({}) -> chunked {} ({:.1} MB, {} chunks)",
                            pending.sender_name.cyan(),
                            crate::agent::contact_identity::displayed_did(&pending.sender_did)
                                .dimmed(),
                            name.cyan(),
                            mb,
                            total_chunks
                        );
                    }
                }
            }
        }
        for pending in contact_requests {
            let display_did = display_contact_request_did(&pending);
            println!(
                "   - {} ({}) -> direct contact request",
                pending.sender_name.cyan(),
                display_did.dimmed()
            );
        }
        for offer in group_offers {
            println!(
                "   - {} ({}) -> group file {} ({} bytes, manifest {})",
                offer
                    .group_name
                    .clone()
                    .unwrap_or_else(|| offer.group_id.clone())
                    .cyan(),
                offer.group_id.dimmed(),
                offer.filename.cyan(),
                offer.size_bytes,
                offer.manifest_id.dimmed()
            );
        }
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        for offer in handshake_offers {
            let remaining_secs = offer
                .expires_at_ms
                .saturating_sub(now_ms)
                .saturating_add(999)
                / 1_000;
            println!(
                "   - {} -> direct trust via {} (expires in {}s)",
                crate::agent::contact_identity::displayed_did(&offer.sender_member_id).dimmed(),
                offer
                    .group_name
                    .clone()
                    .unwrap_or_else(|| offer.group_id.clone())
                    .cyan(),
                remaining_secs
            );
        }
    }
    println!(
        "   {} /accept <peer|group_id|manifest_id>  |  /accept_always <peer>  |  /accept_ask <peer>  |  /reject <peer|group_id|manifest_id>",
        "Usage:".dimmed()
    );
    println!(
        "   {} use DID for peer safety, manifest id for group file offers, and /accept <peer-did> for pending DID contact or /invite_h requests",
        "Tip:".dimmed()
    );
    println!(
        "   {} /reject or /block without args works when exactly one direct-trust offer is pending",
        "Tip:".dimmed()
    );
    println!(
        "   {} /block_inv <peer-did|all> blocks new DID/invite first-contact requests from one peer or globally",
        "Tip:".dimmed()
    );
    println!(
        "   {} DID-first flow: share your exported contact DID and use /connect did:qypha:...",
        "Tip:".dimmed()
    );
}

pub(crate) async fn run_repl_command_loop(
    mut line_rx: mpsc::Receiver<String>,
    ctx: ReplCommandContext,
) -> Result<()> {
    let ReplCommandContext {
        cmd_tx,
        msg_tx_repl,
        peers,
        direct_peer_dids,
        active_chat_target_did,
        active_chat_target_group_id,
        active_chat_target_group_label,
        audit,
        agent_did,
        receive_dir_config,
        receive_dir_path,
        peer_store,
        transfer_decisions,
        pending_contact_requests,
        group_mailboxes,
        handshake_request_gate,
        incoming_connect_gate,
        ratchet_mgr,
        agent_data_dir,
        log_mode,
        ack_tx,
    } = ctx;

    while let Some(raw_line) = line_rx.recv().await {
        let line = match decode_ui_bridge_line(&raw_line) {
            Ok(line) => line,
            Err(error) => {
                println!("   {} {}", "UI bridge rejected:".red().bold(), error);
                flush_command_output();
                ack_tx.send(()).ok();
                continue;
            }
        };
        if line.is_empty() {
            flush_command_output();
            ack_tx.send(()).ok();
            continue;
        }

        match line.as_str() {
            "/quit" | "/exit" | "/q" => {
                super::mark_graceful_shutdown_requested();
                println!("   {}", "Shutting down...".red());
                {
                    let mut a = audit.lock().await;
                    a.record("AGENT_STOP", &agent_did, "graceful shutdown");
                }
                flush_command_output();
                ack_tx.send(()).ok();
                break;
            }
            "/peers -v" | "/p -v" => {
                cmd_tx.send(NetworkCommand::ListPeersVerbose).await?;
                wait_output(&cmd_tx).await;
            }
            "/all" => {
                cmd_tx.send(NetworkCommand::ListAllPeers).await?;
                wait_output(&cmd_tx).await;
            }
            "/peers" | "/p" => {
                cmd_tx.send(NetworkCommand::ListPeers).await?;
                wait_output(&cmd_tx).await;
            }
            "/groups" | "/g" => {
                cmd_tx.send(NetworkCommand::ListGroups).await?;
                wait_output(&cmd_tx).await;
            }
            "/whoami" | "/w" => {
                cmd_tx.send(NetworkCommand::WhoAmI).await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/send ") => {
                let message = line.strip_prefix("/send ").unwrap().to_string();
                cmd_tx.send(NetworkCommand::SendChat { message }).await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/sendto ") || line.starts_with("/msg ") => {
                let raw = if line.starts_with("/sendto ") {
                    line.strip_prefix("/sendto ").unwrap()
                } else {
                    line.strip_prefix("/msg ").unwrap()
                };
                let args: Vec<&str> = raw.splitn(2, ' ').collect();
                if args.len() != 2 || args[0].trim().is_empty() || args[1].trim().is_empty() {
                    println!(
                        "   Usage: /sendto <peer|group_id> <message>  (peer: number|name-unique|did)"
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let selector = args[0].trim();
                let message = args[1].to_string();
                if looks_like_group_id(selector) {
                    let group_session = {
                        let registry = group_mailboxes.lock().await;
                        registry.get_cloned(selector)
                    };
                    let Some(group_session) = group_session else {
                        if active_chat_target_group_id
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .as_deref()
                            == Some(selector)
                        {
                            clear_active_group_target(
                                &active_chat_target_group_id,
                                &active_chat_target_group_label,
                            );
                        }
                        println!(
                        "   {} mailbox group {} is not joined. Use /groups to inspect active mailbox groups.",
                        "Error:".red(),
                        selector
                    );
                        ack_tx.send(()).ok();
                        continue;
                    };
                    {
                        let mut target = active_chat_target_group_id
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        *target = Some(selector.to_string());
                    }
                    {
                        let mut label = active_chat_target_group_label
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        *label = Some(describe_group(&group_session));
                    }
                    {
                        let mut target = active_chat_target_did
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        *target = None;
                    }
                    cmd_tx
                        .send(NetworkCommand::SendChatToGroup {
                            group_id: selector.to_string(),
                            message,
                        })
                        .await?;
                    wait_output(&cmd_tx).await;
                    ack_tx.send(()).ok();
                    continue;
                }
                if peers.is_empty() {
                    println!("   {}", "No peers connected.".dimmed());
                    ack_tx.send(()).ok();
                    continue;
                }
                match resolve_direct_peer_selector(selector, &peers, &direct_peer_dids) {
                    ConnectedPeerSelectorResolution::Resolved(peer) => {
                        clear_active_group_target(
                            &active_chat_target_group_id,
                            &active_chat_target_group_label,
                        );
                        {
                            let mut target = active_chat_target_did
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *target = Some(peer.did.clone());
                        }
                        sync_active_direct_prompt_target(
                            &peers,
                            &active_chat_target_did,
                            &direct_peer_dids,
                            Some(&active_chat_target_group_label),
                        );
                        cmd_tx
                            .send(NetworkCommand::SendChatToPeer {
                                peer_id: peer.peer_id,
                                peer_did: peer.did.clone(),
                                peer_name: peer.name.clone(),
                                message,
                            })
                            .await?;
                        wait_output(&cmd_tx).await;
                    }
                    ConnectedPeerSelectorResolution::Ambiguous(candidates) => {
                        print_ambiguous_selector(selector, candidates);
                    }
                    ConnectedPeerSelectorResolution::NotFound => {
                        print_peer_not_found(selector);
                    }
                }
            }
            _ if line.starts_with("/disconnect ") || line.starts_with("/dc ") => {
                let selector = if line.starts_with("/disconnect ") {
                    line.strip_prefix("/disconnect ").unwrap().trim()
                } else {
                    line.strip_prefix("/dc ").unwrap().trim()
                };
                if selector.is_empty() {
                    println!("   Usage: /disconnect <peer>  (peer: number|name-unique|did)");
                    ack_tx.send(()).ok();
                    continue;
                }

                match resolve_direct_peer_selector(selector, &peers, &direct_peer_dids) {
                    ConnectedPeerSelectorResolution::Resolved(peer) => {
                        {
                            let mut ps = peer_store.lock().await;
                            ps.remove(&peer.did);
                        }
                        {
                            let peer_id = peer.peer_id.to_string();
                            let mut gate = incoming_connect_gate.lock().await;
                            let _ = gate.block_peer_identity(&peer.did, Some(&peer_id));
                        }
                        print_auto_reconnect_state(&peer.did, false);
                        {
                            let mut rmgr = ratchet_mgr.lock().await;
                            rmgr.remove_session(&peer.did);
                        }
                        clear_active_direct_target_if_matching(
                            &peers,
                            &direct_peer_dids,
                            &active_chat_target_did,
                            &active_chat_target_group_label,
                            &peer.did,
                        );
                        cmd_tx
                            .send(NetworkCommand::DisconnectPeerIntent {
                                peer_id: peer.peer_id,
                                peer_did: peer.did.clone(),
                                peer_name: peer.name.clone(),
                            })
                            .await?;
                        println!(
                            "   {} disconnect requested for {} ({})",
                            "Disconnect:".yellow().bold(),
                            peer.name.cyan(),
                            crate::agent::contact_identity::displayed_known_peer_contact_did(
                                &agent_data_dir,
                                &peer.did,
                            )
                            .dimmed()
                        );
                        wait_output(&cmd_tx).await;
                    }
                    ConnectedPeerSelectorResolution::Ambiguous(candidates) => {
                        print_ambiguous_selector(selector, candidates);
                    }
                    ConnectedPeerSelectorResolution::NotFound => {
                        if let Some(peer_did) = canonicalize_did_selector(selector) {
                            let known_peer = {
                                let mut ps = peer_store.lock().await;
                                let known = ps.get(&peer_did).cloned();
                                if known.is_some() {
                                    ps.remove(&peer_did);
                                }
                                known
                            };
                            if let Some(known_peer) = known_peer {
                                {
                                    let peer_id_hint =
                                        known_peer_disconnect_peer_id_hint(&known_peer);
                                    let mut gate = incoming_connect_gate.lock().await;
                                    let _ = gate
                                        .block_peer_identity(&peer_did, peer_id_hint.as_deref());
                                }
                                print_auto_reconnect_state(&peer_did, false);
                                {
                                    let mut rmgr = ratchet_mgr.lock().await;
                                    rmgr.remove_session(&peer_did);
                                }
                                clear_active_direct_target_if_matching(
                                    &peers,
                                    &direct_peer_dids,
                                    &active_chat_target_did,
                                    &active_chat_target_group_label,
                                    &peer_did,
                                );
                                cmd_tx
                                    .send(NetworkCommand::DisconnectKnownPeer {
                                        peer_did: peer_did.clone(),
                                        peer_name: known_peer.name.clone(),
                                    })
                                    .await?;
                                println!(
                                    "   {} disconnect requested for {} ({})",
                                    "Disconnect:".yellow().bold(),
                                    known_peer.name.cyan(),
                                    crate::agent::contact_identity::displayed_known_peer_contact_did(
                                        &agent_data_dir,
                                        &peer_did,
                                    )
                                    .dimmed()
                                );
                                wait_output(&cmd_tx).await;
                            } else {
                                print_peer_not_found(selector);
                            }
                        } else {
                            print_peer_not_found(selector);
                        }
                    }
                }
            }
            _ if line.starts_with("/transfer ") => {
                let payload = line.strip_prefix("/transfer ").unwrap().trim();
                let mut parts = payload.rsplitn(2, ' ');
                let selector = parts.next().unwrap_or("").trim();
                let path = trim_matching_quotes(parts.next().unwrap_or("").trim());
                if !path.is_empty() && !selector.is_empty() {
                    cmd_tx
                        .send(NetworkCommand::SendFile {
                            path: path.to_string(),
                            peer_selector: selector.to_string(),
                        })
                        .await?;
                    wait_output(&cmd_tx).await;
                } else {
                    println!("   Usage: /transfer <file path> <number|name|did>");
                }
            }
            _ if line.starts_with("/transfer_g ") => {
                let payload = line.strip_prefix("/transfer_g ").unwrap().trim();
                let args: Vec<&str> = payload.splitn(2, ' ').collect();
                if args.len() != 2 || args[0].trim().is_empty() || args[1].trim().is_empty() {
                    println!("   Usage: /transfer_g <group_id> <file path>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::SendGroupFile {
                        group_id: args[0].trim().to_string(),
                        path: trim_matching_quotes(args[1]).to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/get_receive_dir" => {
                let cfg = receive_dir_config.lock().await;
                let dir = cfg.global_dir.clone().unwrap_or_else(default_receive_root);
                println!("RECEIVE_DIR:{}", dir.display());
            }
            _ if line.starts_with("/get_receive_dir ") => {
                let selector = line.strip_prefix("/get_receive_dir ").unwrap().trim();
                if selector.is_empty() {
                    let cfg = receive_dir_config.lock().await;
                    let dir = cfg.global_dir.clone().unwrap_or_else(default_receive_root);
                    println!("RECEIVE_DIR:{}", dir.display());
                } else {
                    match resolve_direct_peer_selector(selector, &peers, &direct_peer_dids) {
                        ConnectedPeerSelectorResolution::Resolved(peer) => {
                            let cfg = receive_dir_config.lock().await;
                            let dir = effective_receive_base_dir(&cfg, &peer.did);
                            println!("RECEIVE_DIR_PEER:{}:{}", peer.did, dir.display());
                        }
                        ConnectedPeerSelectorResolution::Ambiguous(candidates) => {
                            print_ambiguous_selector(selector, candidates);
                        }
                        ConnectedPeerSelectorResolution::NotFound => {
                            print_peer_not_found(selector);
                        }
                    }
                }
            }
            "/receive_dir" | "/set_receive_dir" => {
                let cfg = receive_dir_config.lock().await;
                let dir = cfg.global_dir.clone().unwrap_or_else(default_receive_root);
                println!("   Usage: /receive_dir [peer] <path|reset>");
                println!("RECEIVE_DIR:{}", dir.display());
            }
            _ if line.starts_with("/receive_dir ") || line.starts_with("/set_receive_dir ") => {
                let raw = if line.starts_with("/receive_dir ") {
                    line.strip_prefix("/receive_dir ").unwrap().trim()
                } else {
                    line.strip_prefix("/set_receive_dir ").unwrap().trim()
                };
                if raw.is_empty() {
                    let cfg = receive_dir_config.lock().await;
                    let dir = cfg.global_dir.clone().unwrap_or_else(default_receive_root);
                    println!("   Usage: /receive_dir [peer] <path|reset>");
                    println!("RECEIVE_DIR:{}", dir.display());
                    ack_tx.send(()).ok();
                    continue;
                }

                let mut peer_target: Option<PeerInfo> = None;
                let mut path_arg = raw;
                if let Some((first, rest)) = raw.split_once(' ') {
                    let rest = rest.trim();
                    if !rest.is_empty() {
                        match resolve_direct_peer_selector(first.trim(), &peers, &direct_peer_dids)
                        {
                            ConnectedPeerSelectorResolution::Resolved(peer) => {
                                peer_target = Some(peer);
                                path_arg = rest;
                            }
                            ConnectedPeerSelectorResolution::Ambiguous(candidates) => {
                                print_ambiguous_selector(first.trim(), candidates);
                                ack_tx.send(()).ok();
                                continue;
                            }
                            ConnectedPeerSelectorResolution::NotFound => {}
                        }
                    }
                }

                let is_reset = path_arg.eq_ignore_ascii_case("reset")
                    || path_arg.eq_ignore_ascii_case("default");
                let new_path = if is_reset {
                    None
                } else {
                    Some(expand_receive_path(path_arg))
                };

                let mut cfg = receive_dir_config.lock().await;
                if let Some(peer) = peer_target {
                    if let Some(path) = new_path {
                        if let Err(e) = ensure_private_receive_dir(&path) {
                            println!(
                                "   {} could not prepare receive directory: {}",
                                "SECURITY REJECT:".red().bold(),
                                e
                            );
                            ack_tx.send(()).ok();
                            continue;
                        }
                        cfg.per_peer_dirs.insert(peer.did.clone(), path);
                    } else {
                        cfg.per_peer_dirs.remove(&peer.did);
                    }
                    if let Err(e) = harden_configured_receive_dirs(&cfg) {
                        println!(
                            "   {} receive directory hardening failed: {}",
                            "Warning:".yellow().bold(),
                            e
                        );
                    }
                    persist_receive_dir_config(&receive_dir_path, &cfg);
                    let dir = effective_receive_base_dir(&cfg, &peer.did);
                    println!(
                        "   {} {} -> {}",
                        "Receive dir:".green().bold(),
                        peer.name.cyan(),
                        dir.display()
                    );
                    println!("RECEIVE_DIR_PEER:{}:{}", peer.did, dir.display());
                } else {
                    if let Some(ref path) = new_path {
                        if let Err(e) = ensure_private_receive_dir(path) {
                            println!(
                                "   {} could not prepare receive directory: {}",
                                "SECURITY REJECT:".red().bold(),
                                e
                            );
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                    cfg.global_dir = new_path;
                    if let Err(e) = harden_configured_receive_dirs(&cfg) {
                        println!(
                            "   {} receive directory hardening failed: {}",
                            "Warning:".yellow().bold(),
                            e
                        );
                    }
                    persist_receive_dir_config(&receive_dir_path, &cfg);
                    let dir = cfg.global_dir.clone().unwrap_or_else(default_receive_root);
                    println!("   {} {}", "Receive dir:".green().bold(), dir.display());
                    println!("RECEIVE_DIR:{}", dir.display());
                }
            }
            "/accept" => {
                let gate = transfer_decisions.lock().await;
                let pending_contact_requests = pending_contact_requests.lock().await;
                let group_mailboxes = group_mailboxes.lock().await;
                print_pending_transfers(&gate, &pending_contact_requests, &group_mailboxes);
            }
            _ if line.starts_with("/accept ") => {
                let args: Vec<&str> = line
                    .strip_prefix("/accept ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if args.len() != 1 {
                    println!(
                        "   Usage: /accept <peer|group_id|manifest_id>  (peer: number|name-unique|did)"
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let selector = args[0];

                if selector.starts_with("did:") {
                    let pending_contact = {
                        let mut registry = pending_contact_requests.lock().await;
                        registry.take_by_selector(selector)
                    };
                    if let Some(pending) = pending_contact {
                        cmd_tx
                            .send(NetworkCommand::SendContactAccept { pending })
                            .await?;
                        wait_output(&cmd_tx).await;
                        ack_tx.send(()).ok();
                        continue;
                    }
                    match accept_pending_group_handshake_offer(&group_mailboxes, selector).await {
                        Ok(Some(offer)) => {
                            let group_label = offer
                                .group_name
                                .clone()
                                .unwrap_or_else(|| offer.group_id.clone());
                            cmd_tx
                                .send(NetworkCommand::ConnectInvite {
                                    code: offer.invite_code.clone(),
                                })
                                .await?;
                            wait_output(&cmd_tx).await;
                            emit_ui_event(&GroupMailboxUiEvent {
                                kind: "direct_handshake_offer_accepted".to_string(),
                                group_id: offer.group_id.clone(),
                                group_name: offer.group_name.clone(),
                                anonymous_group: false,
                                manifest_id: None,
                                sender_member_id: Some(offer.sender_member_id.clone()),
                                message: Some("accepted via secure /connect flow".to_string()),
                                filename: None,
                                size_bytes: None,
                                member_id: None,
                                member_display_name: None,
                                invite_code: Some(offer.invite_code.clone()),
                                mailbox_epoch: None,
                                kicked_member_id: None,
                                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                            });
                            println!(
                                "   {} direct trust offer from {} via {}",
                                "Accepted:".green().bold(),
                                crate::agent::contact_identity::displayed_did(
                                    &offer.sender_member_id
                                )
                                .dimmed(),
                                group_label.cyan()
                            );
                            {
                                let mut a = audit.lock().await;
                                a.record(
                                    "GROUP_MAILBOX_DIRECT_OFFER_ACCEPT",
                                    &agent_did,
                                    &format!(
                                        "group_id={} from_member_id={}",
                                        offer.group_id, offer.sender_member_id
                                    ),
                                );
                            }
                            ack_tx.send(()).ok();
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                }

                let mut to_reinject: Vec<(libp2p::PeerId, AgentRequest)> = vec![];
                let (resolved_did, accepted_count, sender_name, ambiguous) = {
                    let mut gate = transfer_decisions.lock().await;
                    match resolve_sender_selector(selector, &peers, &gate) {
                        SenderSelectorResolution::Resolved {
                            did: sender_did,
                            name: sender_name,
                        } => {
                            if let Some(item) = gate.take_one_for_sender(&sender_did) {
                                gate.approve_key(item.decision_key.clone());
                                to_reinject.push((item.peer_id, item.request));
                            }
                            (Some(sender_did), to_reinject.len(), sender_name, Vec::new())
                        }
                        SenderSelectorResolution::Ambiguous(candidates) => {
                            (None, 0usize, String::new(), candidates)
                        }
                        SenderSelectorResolution::NotFound => {
                            (None, 0usize, String::new(), Vec::new())
                        }
                    }
                };

                if !ambiguous.is_empty() {
                    print_ambiguous_selector(selector, ambiguous);
                    ack_tx.send(()).ok();
                    continue;
                }
                if let Some(resolved_did) = resolved_did {
                    for (peer_id, req) in to_reinject {
                        let _ = msg_tx_repl
                            .send(crate::network::IncomingRequestEnvelope {
                                peer_id,
                                request: req,
                                iroh_stable_id: None,
                                iroh_active_session: None,
                            })
                            .await;
                    }

                    if accepted_count > 0 {
                        println!(
                            "   {} approved transfer from {}",
                            "Approved:".green().bold(),
                            sender_name.cyan()
                        );
                        emit_transfer_event(
                            "incoming_accepted",
                            "in",
                            Some(&resolved_did),
                            Some(&sender_name),
                            None,
                            None,
                            Some("approved_by_user"),
                        );
                    } else {
                        println!(
                            "   {} no pending transfer found for {}",
                            "Info:".yellow(),
                            sender_name.cyan()
                        );
                    }
                    ack_tx.send(()).ok();
                    continue;
                }

                match approve_pending_group_file_offer(
                    &group_mailboxes,
                    selector,
                    &receive_dir_config,
                    &log_mode,
                    &agent_data_dir,
                )
                .await
                {
                    Ok(Some(outcome)) => {
                        let group_label = outcome
                            .group_name
                            .clone()
                            .unwrap_or_else(|| outcome.group_id.clone());
                        let event_message = match &outcome.action {
                            GroupPendingFileOfferAction::InlineSaved { path, handoff_id } => {
                                handoff_id
                                    .as_ref()
                                    .map(|id| format!("accepted • secure handoff {id}"))
                                    .unwrap_or_else(|| {
                                        format!("accepted • saved to {}", path.display())
                                    })
                            }
                            GroupPendingFileOfferAction::FastRelayRequested { transfer_id } => {
                                format!("accepted • fast relay requested {transfer_id}")
                            }
                            GroupPendingFileOfferAction::ChunkDownloadQueued { transfer_id } => {
                                format!("accepted • download queued {transfer_id}")
                            }
                        };
                        emit_ui_event(&GroupMailboxUiEvent {
                            kind: "file_offer_accepted".to_string(),
                            group_id: outcome.group_id.clone(),
                            group_name: outcome.group_name.clone(),
                            anonymous_group: outcome.anonymous_group,
                            manifest_id: Some(outcome.manifest_id.clone()),
                            sender_member_id: outcome.sender_member_id.clone(),
                            message: Some(event_message),
                            filename: Some(outcome.filename.clone()),
                            size_bytes: Some(outcome.size_bytes),
                            member_id: None,
                            member_display_name: None,
                            invite_code: None,
                            mailbox_epoch: None,
                            kicked_member_id: None,
                            ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                        });
                        match outcome.action {
                            GroupPendingFileOfferAction::InlineSaved { path, handoff_id } => {
                                let target_label = handoff_id
                                    .map(|id| format!("secure handoff {}", id))
                                    .unwrap_or_else(|| path.display().to_string());
                                println!(
                                    "   {} approved group file {} from {} -> {}",
                                    "Approved:".green().bold(),
                                    outcome.filename.cyan(),
                                    group_label.cyan(),
                                    target_label
                                );
                            }
                            GroupPendingFileOfferAction::FastRelayRequested { transfer_id } => {
                                println!(
                                    "   {} approved group file {} from {} (fast relay requested: {})",
                                    "Approved:".green().bold(),
                                    outcome.filename.cyan(),
                                    group_label.cyan(),
                                    transfer_id.dimmed()
                                );
                            }
                            GroupPendingFileOfferAction::ChunkDownloadQueued { transfer_id } => {
                                println!(
                                    "   {} approved group file {} from {} (download queued: {})",
                                    "Approved:".green().bold(),
                                    outcome.filename.cyan(),
                                    group_label.cyan(),
                                    transfer_id.dimmed()
                                );
                            }
                        }
                        if let Some(fast_transfer_id) = outcome.fast_transfer_id.clone() {
                            let _ = cmd_tx
                                .send(NetworkCommand::SendGroupFastFileAccept {
                                    group_id: outcome.group_id.clone(),
                                    transfer_id: fast_transfer_id,
                                })
                                .await;
                        }
                    }
                    Ok(None) => {
                        print_pending_target_not_found(selector);
                    }
                    Err(error) => {
                        println!("   {} {}", "Error:".red(), error);
                    }
                }
            }
            _ if line.starts_with("/accept_always ") => {
                let raw = line.strip_prefix("/accept_always ").unwrap();
                let args: Vec<&str> = raw.split_whitespace().collect();
                if args.len() != 1 {
                    println!("   Usage: /accept_always <peer>  (peer: number|name-unique|did)");
                    ack_tx.send(()).ok();
                    continue;
                }
                let selector = args[0];
                let mut to_reinject: Vec<(libp2p::PeerId, AgentRequest)> = vec![];
                let (resolved_did, sender_name, ambiguous) = {
                    let mut gate = transfer_decisions.lock().await;
                    match resolve_sender_selector(selector, &peers, &gate) {
                        SenderSelectorResolution::Resolved {
                            did: sender_did,
                            name: sender_name,
                        } => {
                            gate.set_policy(&sender_did, IncomingTransferPolicy::AlwaysAccept);
                            let pending_items = gate.take_all_for_sender(&sender_did);
                            for item in pending_items {
                                gate.approve_key(item.decision_key.clone());
                                to_reinject.push((item.peer_id, item.request));
                            }
                            (Some(sender_did), sender_name, Vec::new())
                        }
                        SenderSelectorResolution::Ambiguous(candidates) => {
                            (None, String::new(), candidates)
                        }
                        SenderSelectorResolution::NotFound => (None, String::new(), Vec::new()),
                    }
                };
                if !ambiguous.is_empty() {
                    print_ambiguous_selector(selector, ambiguous);
                    ack_tx.send(()).ok();
                    continue;
                }
                if resolved_did.is_none() {
                    print_sender_not_found(selector);
                    ack_tx.send(()).ok();
                    continue;
                }
                let released = to_reinject.len();
                for (peer_id, req) in to_reinject {
                    let _ = msg_tx_repl
                        .send(crate::network::IncomingRequestEnvelope {
                            peer_id,
                            request: req,
                            iroh_stable_id: None,
                            iroh_active_session: None,
                        })
                        .await;
                }
                println!(
                    "   {} policy set to ALWAYS_ACCEPT for {} (released {} pending transfer)",
                    "Policy:".green().bold(),
                    sender_name.cyan(),
                    released
                );
                if released > 0 {
                    emit_transfer_event(
                        "incoming_accepted",
                        "in",
                        resolved_did.as_deref(),
                        Some(&sender_name),
                        None,
                        None,
                        Some("approved_by_policy_always_accept"),
                    );
                }
            }
            _ if line.starts_with("/accept_ask ") => {
                let args: Vec<&str> = line
                    .strip_prefix("/accept_ask ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if args.len() != 1 {
                    println!("   Usage: /accept_ask <peer>  (peer: number|name-unique|did)");
                    ack_tx.send(()).ok();
                    continue;
                }
                let selector = args[0];
                let mut to_reinject: Vec<(libp2p::PeerId, AgentRequest)> = vec![];
                let (resolved_did, resolved_name, released_count, ambiguous) = {
                    let mut gate = transfer_decisions.lock().await;
                    match resolve_sender_selector(selector, &peers, &gate) {
                        SenderSelectorResolution::Resolved {
                            did: sender_did,
                            name: sender_name,
                        } => {
                            gate.set_policy(&sender_did, IncomingTransferPolicy::AskEveryTime);
                            if let Some(item) = gate.take_one_for_sender(&sender_did) {
                                gate.approve_key(item.decision_key.clone());
                                to_reinject.push((item.peer_id, item.request));
                            }
                            (
                                Some(sender_did),
                                Some(sender_name),
                                to_reinject.len(),
                                Vec::new(),
                            )
                        }
                        SenderSelectorResolution::Ambiguous(candidates) => {
                            (None, None, 0usize, candidates)
                        }
                        SenderSelectorResolution::NotFound => (None, None, 0usize, Vec::new()),
                    }
                };
                if !ambiguous.is_empty() {
                    print_ambiguous_selector(selector, ambiguous);
                    ack_tx.send(()).ok();
                    continue;
                }
                for (peer_id, req) in to_reinject {
                    let _ = msg_tx_repl
                        .send(crate::network::IncomingRequestEnvelope {
                            peer_id,
                            request: req,
                            iroh_stable_id: None,
                            iroh_active_session: None,
                        })
                        .await;
                }
                if let Some(sender_name) = resolved_name {
                    if released_count > 0 {
                        println!(
                            "   {} policy set to ASK_EVERY_TIME for {} (approved {} pending transfer)",
                            "Policy:".green().bold(),
                            sender_name.cyan(),
                            released_count
                        );
                        emit_transfer_event(
                            "incoming_accepted",
                            "in",
                            resolved_did.as_deref(),
                            Some(&sender_name),
                            None,
                            None,
                            Some("approved_by_policy_ask_every_time"),
                        );
                    } else {
                        println!(
                            "   {} policy set to ASK_EVERY_TIME for {}",
                            "Policy:".green().bold(),
                            sender_name.cyan()
                        );
                    }
                } else {
                    print_sender_not_found(selector);
                }
            }
            "/reject" => {
                let pending_contact = {
                    let mut registry = pending_contact_requests.lock().await;
                    registry
                        .single_pending_cloned()
                        .and_then(|request| registry.take(&request.sender_did).or(Some(request)))
                };
                if let Some(pending) = pending_contact {
                    cmd_tx
                        .send(NetworkCommand::SendContactReject {
                            pending,
                            reason: Some("rejected by user".to_string()),
                        })
                        .await?;
                    wait_output(&cmd_tx).await;
                    ack_tx.send(()).ok();
                    continue;
                }
                let pending_handshake_offers = {
                    let registry = group_mailboxes.lock().await;
                    registry.pending_handshake_offers()
                };
                match pending_handshake_offers.len() {
                    1 => match reject_pending_group_handshake_offer(&group_mailboxes, None).await {
                        Ok(Some(offer)) => {
                            let group_label = offer
                                .group_name
                                .clone()
                                .unwrap_or_else(|| offer.group_id.clone());
                            emit_ui_event(&GroupMailboxUiEvent {
                                kind: "direct_handshake_offer_rejected".to_string(),
                                group_id: offer.group_id.clone(),
                                group_name: offer.group_name.clone(),
                                anonymous_group: false,
                                manifest_id: None,
                                sender_member_id: Some(offer.sender_member_id.clone()),
                                message: Some("direct trust offer rejected".to_string()),
                                filename: None,
                                size_bytes: None,
                                member_id: None,
                                member_display_name: None,
                                invite_code: None,
                                mailbox_epoch: None,
                                kicked_member_id: None,
                                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                            });
                            println!(
                                "   {} direct trust offer from {} via {}",
                                "Rejected:".yellow().bold(),
                                crate::agent::contact_identity::displayed_did(
                                    &offer.sender_member_id
                                )
                                .dimmed(),
                                group_label.cyan()
                            );
                            {
                                let mut a = audit.lock().await;
                                a.record(
                                    "GROUP_MAILBOX_DIRECT_OFFER_REJECT",
                                    &agent_did,
                                    &format!(
                                        "group_id={} from_member_id={}",
                                        offer.group_id, offer.sender_member_id
                                    ),
                                );
                            }
                        }
                        Ok(None) => {
                            println!(
                                "   {} no pending direct trust offer found. Use /accept to list pending approvals.",
                                "Info:".yellow()
                            );
                        }
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                        }
                    },
                    0 => {
                        println!(
                            "   Usage: /reject <peer|group_id|manifest_id>  (or plain /reject when exactly one direct trust offer is pending)"
                        );
                    }
                    _ => {
                        println!(
                            "   {} multiple direct trust offers are pending. Use /reject <peer-did>.",
                            "Error:".red()
                        );
                    }
                }
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/reject ") => {
                let args: Vec<&str> = line
                    .strip_prefix("/reject ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if args.is_empty() {
                    println!(
                        "   Usage: /reject <peer|group_id|manifest_id>  (peer: number|name-unique|did)"
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let selector = args[0];

                if selector.starts_with("did:") {
                    let pending_contact = {
                        let mut registry = pending_contact_requests.lock().await;
                        registry.take_by_selector(selector)
                    };
                    if let Some(pending) = pending_contact {
                        cmd_tx
                            .send(NetworkCommand::SendContactReject {
                                pending,
                                reason: Some("rejected by user".to_string()),
                            })
                            .await?;
                        wait_output(&cmd_tx).await;
                        ack_tx.send(()).ok();
                        continue;
                    }
                    match reject_pending_group_handshake_offer(&group_mailboxes, Some(selector))
                        .await
                    {
                        Ok(Some(offer)) => {
                            let group_label = offer
                                .group_name
                                .clone()
                                .unwrap_or_else(|| offer.group_id.clone());
                            emit_ui_event(&GroupMailboxUiEvent {
                                kind: "direct_handshake_offer_rejected".to_string(),
                                group_id: offer.group_id.clone(),
                                group_name: offer.group_name.clone(),
                                anonymous_group: false,
                                manifest_id: None,
                                sender_member_id: Some(offer.sender_member_id.clone()),
                                message: Some("direct trust offer rejected".to_string()),
                                filename: None,
                                size_bytes: None,
                                member_id: None,
                                member_display_name: None,
                                invite_code: None,
                                mailbox_epoch: None,
                                kicked_member_id: None,
                                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                            });
                            println!(
                                "   {} direct trust offer from {} via {}",
                                "Rejected:".yellow().bold(),
                                crate::agent::contact_identity::displayed_did(
                                    &offer.sender_member_id
                                )
                                .dimmed(),
                                group_label.cyan()
                            );
                            {
                                let mut a = audit.lock().await;
                                a.record(
                                    "GROUP_MAILBOX_DIRECT_OFFER_REJECT",
                                    &agent_did,
                                    &format!(
                                        "group_id={} from_member_id={}",
                                        offer.group_id, offer.sender_member_id
                                    ),
                                );
                            }
                            ack_tx.send(()).ok();
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                }

                let (resolved, rejected_name, rejected_desc, rejected_pending, ambiguous) = {
                    let mut gate = transfer_decisions.lock().await;
                    match resolve_sender_selector(selector, &peers, &gate) {
                        SenderSelectorResolution::Resolved {
                            did: sender_did,
                            name: sender_name,
                        } => {
                            let pending = gate.reject_one_for_sender(&sender_did);
                            let desc = pending
                                .as_ref()
                                .map(|p| match &p.kind {
                                    PendingTransferKind::File { filename, .. } => {
                                        format!("file {}", filename)
                                    }
                                    PendingTransferKind::ChunkInit { total_chunks, .. } => {
                                        format!("chunked transfer ({} chunks)", total_chunks)
                                    }
                                })
                                .unwrap_or_else(|| "no pending transfer".to_string());
                            (true, sender_name, desc, pending, Vec::new())
                        }
                        SenderSelectorResolution::Ambiguous(candidates) => {
                            (false, String::new(), String::new(), None, candidates)
                        }
                        SenderSelectorResolution::NotFound => {
                            (false, String::new(), String::new(), None, Vec::new())
                        }
                    }
                };
                if !ambiguous.is_empty() {
                    print_ambiguous_selector(selector, ambiguous);
                    ack_tx.send(()).ok();
                    continue;
                }
                if resolved {
                    if rejected_desc == "no pending transfer" {
                        println!(
                            "   {} no pending transfer found for {}",
                            "Info:".yellow(),
                            rejected_name.cyan()
                        );
                    } else {
                        println!(
                            "   {} {} from {}",
                            "Rejected:".yellow().bold(),
                            rejected_desc,
                            rejected_name.cyan()
                        );
                        if let Some(pending) = rejected_pending {
                            let (session_id, filename) = match &pending.kind {
                                PendingTransferKind::ChunkInit {
                                    session_id,
                                    filename_hint,
                                    ..
                                } => (Some(session_id.clone()), filename_hint.clone()),
                                PendingTransferKind::File { filename, .. } => {
                                    (None, Some(filename.clone()))
                                }
                            };
                            emit_transfer_event(
                                "incoming_rejected",
                                "in",
                                Some(&pending.sender_did),
                                Some(&pending.sender_name),
                                session_id.as_deref(),
                                filename.as_deref(),
                                Some("rejected_by_user"),
                            );
                            dispatch_background_command(
                                &cmd_tx,
                                NetworkCommand::SendTransferReject {
                                    peer_id: pending.peer_id,
                                    session_id,
                                    request_message_id: Some(pending.request.message_id),
                                    reason: "rejected_by_user".to_string(),
                                },
                            );
                        }
                    }
                    ack_tx.send(()).ok();
                    continue;
                }

                match reject_pending_group_file_offer(&group_mailboxes, selector).await {
                    Ok(Some(offer)) => {
                        let group_label = offer
                            .group_name
                            .clone()
                            .unwrap_or_else(|| offer.group_id.clone());
                        emit_ui_event(&GroupMailboxUiEvent {
                            kind: "file_offer_rejected".to_string(),
                            group_id: offer.group_id.clone(),
                            group_name: offer.group_name.clone(),
                            anonymous_group: offer.anonymous_group,
                            manifest_id: Some(offer.manifest_id.clone()),
                            sender_member_id: offer.sender_member_id.clone(),
                            message: Some("rejected by user".to_string()),
                            filename: Some(offer.filename.clone()),
                            size_bytes: Some(offer.size_bytes),
                            member_id: None,
                            member_display_name: None,
                            invite_code: None,
                            mailbox_epoch: None,
                            kicked_member_id: None,
                            ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                        });
                        println!(
                            "   {} group file {} from {}",
                            "Rejected:".yellow().bold(),
                            offer.filename.cyan(),
                            group_label.cyan()
                        );
                    }
                    Ok(None) => {
                        print_pending_target_not_found(selector);
                    }
                    Err(error) => {
                        println!("   {} {}", "Error:".red(), error);
                    }
                }
            }
            "/invite" | "/inv" => {
                cmd_tx.send(NetworkCommand::GenerateInvite).await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/group_normal ") => {
                if matches!(log_mode, LogMode::Ghost) {
                    println!(
                        "   {} Ghost mode only allows anonymous mailbox groups.",
                        "Error:".red()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let group_name = line.strip_prefix("/group_normal ").unwrap().trim();
                if group_name.is_empty() {
                    println!("   Usage: /group_normal <group-name>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::CreateNormalGroup {
                        group_name: group_name.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/group_anon ") => {
                if !matches!(log_mode, LogMode::Ghost) {
                    println!(
                        "   {} {} is only available in Ghost mode. This session is using the durable group plane; use /group_normal here or restart in Ghost mode for anonymous groups.",
                        "Error:".red().bold(),
                        "/group_anon".cyan()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let group_name = line.strip_prefix("/group_anon ").unwrap().trim();
                let group_name = (!group_name.is_empty()).then(|| group_name.to_string());
                cmd_tx
                    .send(NetworkCommand::CreateAnonymousGroup { group_name })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/group_anon" => {
                if !matches!(log_mode, LogMode::Ghost) {
                    println!(
                        "   {} {} is only available in Ghost mode. This session is using the durable group plane; use /group_normal here or restart in Ghost mode for anonymous groups.",
                        "Error:".red().bold(),
                        "/group_anon".cyan()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::CreateAnonymousGroup { group_name: None })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/invite_g ") || line.starts_with("/invg ") => {
                if matches!(log_mode, LogMode::Ghost) {
                    println!(
                        "   {} Ghost mode does not expose reusable durable-group invites.",
                        "Error:".red()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let group_id = if line.starts_with("/invite_g ") {
                    line.strip_prefix("/invite_g ").unwrap().trim()
                } else {
                    line.strip_prefix("/invg ").unwrap().trim()
                };
                if group_id.is_empty() {
                    println!("   Usage: /invite_g <group-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::GenerateGroupInvite {
                        group_id: group_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/invite_g" | "/invg" => {
                println!("   Usage: /invite_g <group-id>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/invite_anon ") => {
                let group_special_id = line.strip_prefix("/invite_anon ").unwrap().trim();
                if group_special_id.is_empty() {
                    println!("   Usage: /invite_anon <group-special-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::GenerateAnonymousGroupInvite {
                        group_special_id: group_special_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/invite_anon" => {
                println!("   Usage: /invite_anon <group-special-id>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/invite_hg ") => {
                if matches!(log_mode, LogMode::Ghost) {
                    println!(
                        "   {} /invite_hg is disabled in Ghost mode.",
                        "Error:".red()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let args = line.strip_prefix("/invite_hg ").unwrap().trim();
                let mut parts = args.split_whitespace();
                let Some(group_id) = parts.next() else {
                    println!("   Usage: /invite_hg <group-id> <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                };
                let Some(member_id) = parts.next() else {
                    println!("   Usage: /invite_hg <group-id> <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                };
                if parts.next().is_some() {
                    println!("   Usage: /invite_hg <group-id> <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                match preflight_outgoing_group_handshake_offer(
                    &group_mailboxes,
                    &handshake_request_gate,
                    Some(group_id),
                    member_id,
                )
                .await
                {
                    Ok(_) => {}
                    Err(OutgoingHandshakeInvitePreflightError::Validation(error)) => {
                        println!("   {} {}", "Error:".red().bold(), error);
                        ack_tx.send(()).ok();
                        continue;
                    }
                    Err(OutgoingHandshakeInvitePreflightError::RateLimited {
                        member_id,
                        retry_after_ms,
                    }) => {
                        let retry_after_secs = retry_after_ms.saturating_add(999) / 1_000;
                        {
                            let mut a = audit.lock().await;
                            a.record(
                                "GROUP_MAILBOX_DIRECT_OFFER_SEND_RATE_LIMIT",
                                &agent_did,
                                &format!(
                                    "group_id={} target_member_id={} retry_after_ms={}",
                                    group_id, member_id, retry_after_ms
                                ),
                            );
                        }
                        println!(
                            "   {} {} is cooling down. Retry in {}s.",
                            "Slow down:".yellow().bold(),
                            member_id.dimmed(),
                            retry_after_secs
                        );
                        ack_tx.send(()).ok();
                        continue;
                    }
                }
                cmd_tx
                    .send(NetworkCommand::SendHandshakeInviteScoped {
                        group_id: group_id.to_string(),
                        member_id: member_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/invite_hg" => {
                println!("   Usage: /invite_hg <group-id> <group-member-did>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/invite_h ") => {
                if matches!(log_mode, LogMode::Ghost) {
                    println!("   {} /invite_h is disabled in Ghost mode.", "Error:".red());
                    ack_tx.send(()).ok();
                    continue;
                }
                let member_id = line.strip_prefix("/invite_h ").unwrap().trim();
                if member_id.is_empty() {
                    println!("   Usage: /invite_h <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                match preflight_outgoing_group_handshake_offer(
                    &group_mailboxes,
                    &handshake_request_gate,
                    None,
                    member_id,
                )
                .await
                {
                    Ok(_) => {}
                    Err(OutgoingHandshakeInvitePreflightError::Validation(error)) => {
                        println!("   {} {}", "Error:".red().bold(), error);
                        ack_tx.send(()).ok();
                        continue;
                    }
                    Err(OutgoingHandshakeInvitePreflightError::RateLimited {
                        member_id,
                        retry_after_ms,
                    }) => {
                        let retry_after_secs = retry_after_ms.saturating_add(999) / 1_000;
                        {
                            let mut a = audit.lock().await;
                            a.record(
                                "GROUP_MAILBOX_DIRECT_OFFER_SEND_RATE_LIMIT",
                                &agent_did,
                                &format!(
                                    "target_member_id={} retry_after_ms={}",
                                    member_id, retry_after_ms
                                ),
                            );
                        }
                        println!(
                            "   {} {} is cooling down. Retry in {}s.",
                            "Slow down:".yellow().bold(),
                            member_id.dimmed(),
                            retry_after_secs
                        );
                        ack_tx.send(()).ok();
                        continue;
                    }
                }
                cmd_tx
                    .send(NetworkCommand::SendHandshakeInvite {
                        member_id: member_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/invite_h" => {
                println!("   Usage: /invite_h <group-member-did>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/block_inv ") => {
                let selector = line.strip_prefix("/block_inv ").unwrap().trim();
                if selector.is_empty() {
                    println!("   Usage: /block_inv <peer-did|all>");
                    ack_tx.send(()).ok();
                    continue;
                }
                if selector.eq_ignore_ascii_case("all") {
                    let snapshot = {
                        let mut gate = incoming_connect_gate.lock().await;
                        match gate.set_block_all(true) {
                            Ok(_) => gate.snapshot(),
                            Err(error) => {
                                println!("   {} {}", "Block-all failed:".red().bold(), error);
                                ack_tx.send(()).ok();
                                continue;
                            }
                        }
                    };
                    incoming_connect_gate::emit_headless_policy_snapshot(&snapshot);
                    let cleared_count = {
                        let mut registry = pending_contact_requests.lock().await;
                        registry.clear_all()
                    };
                    {
                        let mut a = audit.lock().await;
                        a.record("INCOMING_CONNECT_BLOCK_ALL", &agent_did, "scope=global");
                    }
                    println!(
                        "   {} all DID/invite first-contact requests are now blocked.",
                        "Blocked:".yellow().bold()
                    );
                    if cleared_count > 0 {
                        println!(
                            "   {} cleared {} pending DID contact request{}.",
                            "Cleared:".dimmed(),
                            cleared_count,
                            if cleared_count == 1 { "" } else { "s" }
                        );
                    }
                    ack_tx.send(()).ok();
                    continue;
                }
                let block_result = {
                    let mut gate = incoming_connect_gate.lock().await;
                    gate.block_selector(selector)
                };
                let (changed, canonical_did) = match block_result {
                    Ok(result) => result,
                    Err(error) => {
                        println!("   {} {}", "Block failed:".red().bold(), error);
                        ack_tx.send(()).ok();
                        continue;
                    }
                };
                incoming_connect_gate::emit_headless_policy_snapshot(&{
                    let gate = incoming_connect_gate.lock().await;
                    gate.snapshot()
                });
                let removed_pending = {
                    let mut registry = pending_contact_requests.lock().await;
                    registry.take_by_selector(selector).is_some()
                };
                let display_did = crate::agent::contact_identity::displayed_did(&canonical_did);
                if changed {
                    let mut a = audit.lock().await;
                    a.record(
                        "INCOMING_CONNECT_BLOCK",
                        &agent_did,
                        &format!("sender_did={}", canonical_did),
                    );
                    println!(
                        "   {} {} can no longer send DID/invite first-contact requests to you.",
                        "Blocked:".yellow().bold(),
                        display_did.dimmed()
                    );
                } else {
                    println!(
                        "   {} {} is already blocked for DID/invite first-contact requests.",
                        "Blocked:".yellow().bold(),
                        display_did.dimmed()
                    );
                }
                if removed_pending {
                    println!(
                        "   {} pending DID contact request cleared.",
                        "Cleared:".dimmed()
                    );
                }
                ack_tx.send(()).ok();
                continue;
            }
            "/block_inv" => {
                println!("   Usage: /block_inv <peer-did|all>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/unlock_inv ") => {
                let selector = line.strip_prefix("/unlock_inv ").unwrap().trim();
                if selector.is_empty() {
                    println!("   Usage: /unlock_inv <peer-did|all>");
                    ack_tx.send(()).ok();
                    continue;
                }
                if selector.eq_ignore_ascii_case("all") {
                    let snapshot = {
                        let mut gate = incoming_connect_gate.lock().await;
                        match gate.set_block_all(false) {
                            Ok(_) => gate.snapshot(),
                            Err(error) => {
                                println!("   {} {}", "Unlock-all failed:".red().bold(), error);
                                ack_tx.send(()).ok();
                                continue;
                            }
                        }
                    };
                    incoming_connect_gate::emit_headless_policy_snapshot(&snapshot);
                    {
                        let mut a = audit.lock().await;
                        a.record("INCOMING_CONNECT_UNLOCK_ALL", &agent_did, "scope=global");
                    }
                    println!(
                        "   {} DID/invite first-contact requests are allowed again.",
                        "Unlocked:".green().bold()
                    );
                    ack_tx.send(()).ok();
                    continue;
                }
                let unblock_result = {
                    let mut gate = incoming_connect_gate.lock().await;
                    gate.unblock_selector(selector)
                };
                let (changed, canonical_did) = match unblock_result {
                    Ok(result) => result,
                    Err(error) => {
                        println!("   {} {}", "Unlock failed:".red().bold(), error);
                        ack_tx.send(()).ok();
                        continue;
                    }
                };
                incoming_connect_gate::emit_headless_policy_snapshot(&{
                    let gate = incoming_connect_gate.lock().await;
                    gate.snapshot()
                });
                let display_did = crate::agent::contact_identity::displayed_did(&canonical_did);
                if changed {
                    let mut a = audit.lock().await;
                    a.record(
                        "INCOMING_CONNECT_UNLOCK",
                        &agent_did,
                        &format!("sender_did={}", canonical_did),
                    );
                    println!(
                        "   {} {} can send DID/invite first-contact requests again.",
                        "Unlocked:".green().bold(),
                        display_did.dimmed()
                    );
                } else {
                    println!(
                        "   {} {} was not blocked for DID/invite first-contact requests.",
                        "Unlocked:".green().bold(),
                        display_did.dimmed()
                    );
                }
                ack_tx.send(()).ok();
                continue;
            }
            "/unlock_inv" => {
                println!("   Usage: /unlock_inv <peer-did|all>");
                ack_tx.send(()).ok();
                continue;
            }
            "/block" => {
                let pending_handshake_offers = {
                    let registry = group_mailboxes.lock().await;
                    registry.pending_handshake_offers()
                };
                match pending_handshake_offers.len() {
                    1 => {
                        let member_id = pending_handshake_offers[0].sender_member_id.clone();
                        let cleared_offer = match reject_pending_group_handshake_offer(
                            &group_mailboxes,
                            None,
                        )
                        .await
                        {
                            Ok(offer) => offer,
                            Err(error) => {
                                println!("   {} {}", "Error:".red(), error);
                                ack_tx.send(()).ok();
                                continue;
                            }
                        };
                        let snapshot = {
                            let mut gate = handshake_request_gate.lock().await;
                            match gate.block_member(&member_id) {
                                Ok(_) => gate.snapshot(),
                                Err(error) => {
                                    println!("   {} {}", "Block failed:".red().bold(), error);
                                    ack_tx.send(()).ok();
                                    continue;
                                }
                            }
                        };
                        handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                        if let Some(offer) = cleared_offer {
                            emit_ui_event(&GroupMailboxUiEvent {
                                kind: "direct_handshake_offer_blocked".to_string(),
                                group_id: offer.group_id.clone(),
                                group_name: offer.group_name.clone(),
                                anonymous_group: false,
                                manifest_id: None,
                                sender_member_id: Some(offer.sender_member_id.clone()),
                                message: Some("direct trust offer blocked".to_string()),
                                filename: None,
                                size_bytes: None,
                                member_id: None,
                                member_display_name: None,
                                invite_code: None,
                                mailbox_epoch: None,
                                kicked_member_id: None,
                                ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                            });
                        }
                        {
                            let mut a = audit.lock().await;
                            a.record(
                                "GROUP_MAILBOX_DIRECT_OFFER_BLOCK",
                                &agent_did,
                                &format!("from_member_id={}", member_id),
                            );
                        }
                        println!(
                            "   {} {} can no longer send direct handshake requests to you.",
                            "Blocked:".yellow().bold(),
                            member_id.dimmed()
                        );
                    }
                    0 => {
                        println!(
                            "   Usage: /block <group-member-did>  (or plain /block when exactly one direct trust offer is pending)"
                        );
                    }
                    _ => {
                        println!(
                            "   {} multiple direct trust offers are pending. Use /block <peer-did>.",
                            "Error:".red()
                        );
                    }
                }
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/block ") => {
                let member_id = line.strip_prefix("/block ").unwrap().trim();
                if member_id.is_empty() {
                    println!("   Usage: /block <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                let cleared_offer =
                    match reject_pending_group_handshake_offer(&group_mailboxes, Some(member_id))
                        .await
                    {
                        Ok(offer) => offer,
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    };
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.block_member(member_id) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Block failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                if let Some(offer) = cleared_offer {
                    emit_ui_event(&GroupMailboxUiEvent {
                        kind: "direct_handshake_offer_blocked".to_string(),
                        group_id: offer.group_id.clone(),
                        group_name: offer.group_name.clone(),
                        anonymous_group: false,
                        manifest_id: None,
                        sender_member_id: Some(offer.sender_member_id.clone()),
                        message: Some("direct trust offer blocked".to_string()),
                        filename: None,
                        size_bytes: None,
                        member_id: None,
                        member_display_name: None,
                        invite_code: None,
                        mailbox_epoch: None,
                        kicked_member_id: None,
                        ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                    });
                }
                {
                    let mut a = audit.lock().await;
                    a.record(
                        "GROUP_MAILBOX_DIRECT_OFFER_BLOCK",
                        &agent_did,
                        &format!("from_member_id={}", member_id),
                    );
                }
                println!(
                    "   {} {} can no longer send direct handshake requests to you.",
                    "Blocked:".yellow().bold(),
                    member_id.dimmed()
                );
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/block_r ") => {
                let member_id = line.strip_prefix("/block_r ").unwrap().trim();
                if member_id.is_empty() {
                    println!("   Usage: /block_r <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                let cleared_offer =
                    match reject_pending_group_handshake_offer(&group_mailboxes, Some(member_id))
                        .await
                    {
                        Ok(offer) => offer,
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    };
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.block_member(member_id) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Block failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                if let Some(offer) = cleared_offer {
                    emit_ui_event(&GroupMailboxUiEvent {
                        kind: "direct_handshake_offer_blocked".to_string(),
                        group_id: offer.group_id.clone(),
                        group_name: offer.group_name.clone(),
                        anonymous_group: false,
                        manifest_id: None,
                        sender_member_id: Some(offer.sender_member_id.clone()),
                        message: Some("direct trust offer blocked".to_string()),
                        filename: None,
                        size_bytes: None,
                        member_id: None,
                        member_display_name: None,
                        invite_code: None,
                        mailbox_epoch: None,
                        kicked_member_id: None,
                        ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                    });
                }
                println!(
                    "   {} {} can no longer send direct handshake requests to you.",
                    "Blocked:".yellow().bold(),
                    member_id.dimmed()
                );
                ack_tx.send(()).ok();
                continue;
            }
            "/block_r" => {
                println!("   Usage: /block_r <group-member-did>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/unblock ") => {
                let member_id = line.strip_prefix("/unblock ").unwrap().trim();
                if member_id.is_empty() {
                    println!("   Usage: /unblock <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.unblock_member(member_id) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Unblock failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                println!(
                    "   {} {} can send direct handshake requests again.",
                    "Unblocked:".green().bold(),
                    member_id.dimmed()
                );
                ack_tx.send(()).ok();
                continue;
            }
            "/unblock" => {
                println!("   Usage: /unblock <group-member-did>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/unblock_r ") => {
                let member_id = line.strip_prefix("/unblock_r ").unwrap().trim();
                if member_id.is_empty() {
                    println!("   Usage: /unblock_r <group-member-did>");
                    ack_tx.send(()).ok();
                    continue;
                }
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.unblock_member(member_id) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Unblock failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                println!(
                    "   {} {} can send direct handshake requests again.",
                    "Unblocked:".green().bold(),
                    member_id.dimmed()
                );
                ack_tx.send(()).ok();
                continue;
            }
            "/unblock_r" => {
                println!("   Usage: /unblock_r <group-member-did>");
                ack_tx.send(()).ok();
                continue;
            }
            "/block_all_r" => {
                let cleared_offers =
                    match clear_pending_group_handshake_offers(&group_mailboxes).await {
                        Ok(offers) => offers,
                        Err(error) => {
                            println!("   {} {}", "Error:".red(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    };
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.set_block_all(true) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Block-all failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                for offer in cleared_offers {
                    emit_ui_event(&GroupMailboxUiEvent {
                        kind: "direct_handshake_offer_blocked".to_string(),
                        group_id: offer.group_id.clone(),
                        group_name: offer.group_name.clone(),
                        anonymous_group: false,
                        manifest_id: None,
                        sender_member_id: Some(offer.sender_member_id.clone()),
                        message: Some("direct trust offer blocked".to_string()),
                        filename: None,
                        size_bytes: None,
                        member_id: None,
                        member_display_name: None,
                        invite_code: None,
                        mailbox_epoch: None,
                        kicked_member_id: None,
                        ts_ms: chrono::Utc::now().timestamp_millis().max(0),
                    });
                }
                println!(
                    "   {} all incoming direct handshake requests are now blocked.",
                    "Shield enabled:".yellow().bold()
                );
                ack_tx.send(()).ok();
                continue;
            }
            "/unblock_all_r" => {
                let snapshot = {
                    let mut gate = handshake_request_gate.lock().await;
                    match gate.set_block_all(false) {
                        Ok(_) => gate.snapshot(),
                        Err(error) => {
                            println!("   {} {}", "Unblock-all failed:".red().bold(), error);
                            ack_tx.send(()).ok();
                            continue;
                        }
                    }
                };
                handshake_request_gate::emit_headless_policy_snapshot(&snapshot);
                println!(
                    "   {} incoming direct handshake requests are allowed again.",
                    "Shield disabled:".green().bold()
                );
                ack_tx.send(()).ok();
                continue;
            }
            "/connect" | _ if line.starts_with("/connect ") => {
                let arg = line.strip_prefix("/connect").unwrap().trim();
                if arg.is_empty() {
                    println!("   Usage: /connect did:qypha:...  or  /connect <invite-code>");
                    ack_tx.send(()).ok();
                    continue;
                }
                if let Some(path) = arg.strip_prefix('@') {
                    let path = path.trim();
                    match std::fs::read_to_string(path) {
                        Ok(code) => {
                            let code = code.trim().to_string();
                            if let Ok(crate::network::invite::DecodedInvite::Peer(invite)) =
                                crate::network::invite::DecodedInvite::from_code(&code)
                            {
                                if let Ok(invite_did) = invite.canonical_did() {
                                    let mut gate = incoming_connect_gate.lock().await;
                                    let _ = gate.unblock_selector(&invite_did);
                                }
                            }
                            cmd_tx.send(NetworkCommand::ConnectInvite { code }).await?;
                            wait_output(&cmd_tx).await;
                        }
                        Err(e) => {
                            println!("   {} {}", "Failed to read invite file:".red(), e);
                        }
                    }
                    ack_tx.send(()).ok();
                    continue;
                }
                if arg.starts_with("did:") {
                    let did = arg.to_string();
                    if !is_contact_did(&did) {
                        println!(
                            "   {} {}",
                            "Connect failed:".red().bold(),
                            "expected shareable DID format did:qypha:..."
                        );
                        ack_tx.send(()).ok();
                        continue;
                    }
                    if let Some(canonical_did) = canonicalize_did_selector(&did) {
                        let mut gate = incoming_connect_gate.lock().await;
                        let _ = gate.unblock_selector(&canonical_did);
                    }
                    cmd_tx
                        .send(NetworkCommand::ConnectDid {
                            did,
                            intro_message: None,
                        })
                        .await?;
                    wait_output(&cmd_tx).await;
                    ack_tx.send(()).ok();
                    continue;
                }
                let code = arg.to_string();
                if let Ok(crate::network::invite::DecodedInvite::Peer(invite)) =
                    crate::network::invite::DecodedInvite::from_code(&code)
                {
                    if let Ok(invite_did) = invite.canonical_did() {
                        let mut gate = incoming_connect_gate.lock().await;
                        let _ = gate.unblock_selector(&invite_did);
                    }
                }
                cmd_tx.send(NetworkCommand::ConnectInvite { code }).await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/kick_g ") => {
                let member_selector = line.strip_prefix("/kick_g ").unwrap().trim();
                if member_selector.is_empty() {
                    println!("   Usage: /kick_g <peer>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::KickGroupMember {
                        member_selector: member_selector.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            _ if line.starts_with("/lock_g ") => {
                let group_id = line.strip_prefix("/lock_g ").unwrap().trim();
                if group_id.is_empty() {
                    println!("   Usage: /lock_g <group-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::LockGroup {
                        group_id: group_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/lock_g" => {
                println!("   Usage: /lock_g <group-id>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/unlock_g ") => {
                let group_id = line.strip_prefix("/unlock_g ").unwrap().trim();
                if group_id.is_empty() {
                    println!("   Usage: /unlock_g <group-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::UnlockGroup {
                        group_id: group_id.to_string(),
                    })
                    .await?;
                wait_output(&cmd_tx).await;
            }
            "/unlock_g" => {
                println!("   Usage: /unlock_g <group-id>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/leave_g ") => {
                let group_id = line.strip_prefix("/leave_g ").unwrap().trim();
                if group_id.is_empty() {
                    println!("   Usage: /leave_g <group-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::LeaveGroup {
                        group_id: group_id.to_string(),
                    })
                    .await?;
                if active_chat_target_group_id
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_deref()
                    == Some(group_id)
                {
                    clear_active_group_target(
                        &active_chat_target_group_id,
                        &active_chat_target_group_label,
                    );
                }
                wait_output(&cmd_tx).await;
            }
            "/leave_g" => {
                println!("   Usage: /leave_g <group-id>");
                ack_tx.send(()).ok();
                continue;
            }
            _ if line.starts_with("/disband ") => {
                let group_id = line.strip_prefix("/disband ").unwrap().trim();
                if group_id.is_empty() {
                    println!("   Usage: /disband <group-id>");
                    ack_tx.send(()).ok();
                    continue;
                }
                cmd_tx
                    .send(NetworkCommand::DisbandGroup {
                        group_id: group_id.to_string(),
                    })
                    .await?;
                if active_chat_target_group_id
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_deref()
                    == Some(group_id)
                {
                    clear_active_group_target(
                        &active_chat_target_group_id,
                        &active_chat_target_group_label,
                    );
                }
                wait_output(&cmd_tx).await;
            }
            "/disband" => {
                println!("   Usage: /disband <group-id>");
                ack_tx.send(()).ok();
                continue;
            }
            "/onion" => {
                cmd_tx.send(NetworkCommand::ShowOnion).await?;
                wait_output(&cmd_tx).await;
            }
            _ => {
                if let Some(group_id) = resolve_active_chat_group(
                    &group_mailboxes,
                    &active_chat_target_group_id,
                    &active_chat_target_group_label,
                )
                .await
                {
                    cmd_tx
                        .send(NetworkCommand::SendChatToGroup {
                            group_id,
                            message: line,
                        })
                        .await?;
                } else {
                    sync_active_direct_prompt_target(
                        &peers,
                        &active_chat_target_did,
                        &direct_peer_dids,
                        Some(&active_chat_target_group_label),
                    );
                    if let Some(peer) =
                        resolve_active_chat_peer(&peers, &active_chat_target_did, &direct_peer_dids)
                    {
                        cmd_tx
                            .send(NetworkCommand::SendChatToPeer {
                                peer_id: peer.peer_id,
                                peer_did: peer.did,
                                peer_name: peer.name,
                                message: line,
                            })
                            .await?;
                    } else if let Some(peer) = selected_reconnecting_direct_peer(
                        &peers,
                        &active_chat_target_did,
                        &direct_peer_dids,
                    ) {
                        println!(
                            "   {} with {} — try again in a moment",
                            "Peer reconnecting".yellow().bold(),
                            peer.name.cyan()
                        );
                    } else {
                        cmd_tx
                            .send(NetworkCommand::SendChat { message: line })
                            .await?;
                    }
                }
                wait_output(&cmd_tx).await;
            }
        }

        flush_command_output();
        ack_tx.send(()).ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use dashmap::DashMap;
    use tokio::sync::mpsc;

    use super::*;
    use crate::agent::daemon::group_mailbox::{
        build_mailbox_descriptor, create_ghost_anonymous_group,
        seed_identified_group_member_for_test,
    };
    use crate::control_plane::audit::{AuditLog, LogMode};
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::{contact_did_from_canonical_did, encode_contact_did};
    use crate::network::contact_request::ContactRequestPayload;
    use crate::network::did_profile::DidProfile;
    use crate::network::direct_invite_token::DirectInviteTransportPolicy;
    use crate::network::peer_store::{KnownPeer, PeerStore};

    fn encode_ui_bridge(command: &UiBridgeCommand) -> String {
        format!(
            "{}{}",
            UI_BRIDGE_PREFIX,
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(command).unwrap())
        )
    }

    fn sample_peer_info(did: &str, name: &str) -> PeerInfo {
        PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: None,
            verifying_key: Some([3u8; 32]),
            aegis_supported: false,
            ratchet_dh_public: None,
        }
    }

    fn sample_contact_request_payload(keypair: &AgentKeyPair) -> ContactRequestPayload {
        ContactRequestPayload {
            version: 1,
            request_id: format!("req-{}", keypair.did),
            sender_profile: DidProfile::generate(keypair, Vec::new(), None),
            intro_message: Some("hello".to_string()),
            invite_token: None,
            transport_policy: DirectInviteTransportPolicy::Any,
            created_at: 1234,
            signature: vec![7; 64],
        }
    }

    fn spawn_test_repl_with_transfer_decisions(
        log_mode: LogMode,
    ) -> (
        mpsc::Sender<String>,
        mpsc::Receiver<NetworkCommand>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        Arc<DashMap<String, PeerInfo>>,
        Arc<DashMap<String, bool>>,
        Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
        Arc<tokio::sync::Mutex<TransferDecisionState>>,
        Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
        Arc<Mutex<Option<String>>>,
        Arc<Mutex<Option<String>>>,
    ) {
        let (line_tx, line_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (msg_tx_repl, _msg_rx_repl) = mpsc::channel(8);
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let peers = Arc::new(DashMap::new());
        let direct_peer_dids = Arc::new(DashMap::new());
        let group_mailboxes = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        let transfer_decisions =
            Arc::new(tokio::sync::Mutex::new(TransferDecisionState::default()));
        let pending_contact_requests =
            Arc::new(tokio::sync::Mutex::new(ContactRequestRegistry::default()));
        let active_chat_target_group_id = Arc::new(Mutex::new(None));
        let active_chat_target_group_label = Arc::new(Mutex::new(None));
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(
            audit_dir.path(),
            "did:nxf:test-agent",
            &[0u8; 32],
            log_mode.clone(),
        )
        .unwrap();
        let handle = tokio::spawn(run_repl_command_loop(
            line_rx,
            ReplCommandContext {
                cmd_tx,
                msg_tx_repl,
                peers: peers.clone(),
                direct_peer_dids: direct_peer_dids.clone(),
                active_chat_target_did: Arc::new(Mutex::new(None)),
                active_chat_target_group_id: active_chat_target_group_id.clone(),
                active_chat_target_group_label: active_chat_target_group_label.clone(),
                audit: Arc::new(tokio::sync::Mutex::new(audit)),
                agent_did: "did:nxf:test-agent".to_string(),
                receive_dir_config: Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default())),
                receive_dir_path: PathBuf::from("/tmp/qypha-tests/receive_dir.json"),
                peer_store: Arc::new(tokio::sync::Mutex::new(PeerStore::new(None))),
                transfer_decisions: transfer_decisions.clone(),
                pending_contact_requests: pending_contact_requests.clone(),
                group_mailboxes: group_mailboxes.clone(),
                handshake_request_gate: Arc::new(tokio::sync::Mutex::new(
                    HandshakeRequestGate::default(),
                )),
                incoming_connect_gate: Arc::new(tokio::sync::Mutex::new(
                    IncomingConnectGate::default(),
                )),
                ratchet_mgr: Arc::new(tokio::sync::Mutex::new(
                    crate::crypto::double_ratchet::RatchetManager::new(None, None),
                )),
                agent_data_dir: std::env::temp_dir().join("qypha-tests"),
                log_mode,
                ack_tx,
            },
        ));

        (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            peers,
            direct_peer_dids,
            group_mailboxes,
            transfer_decisions,
            pending_contact_requests,
            active_chat_target_group_id,
            active_chat_target_group_label,
        )
    }

    fn spawn_test_repl(
        log_mode: LogMode,
    ) -> (
        mpsc::Sender<String>,
        mpsc::Receiver<NetworkCommand>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        Arc<DashMap<String, PeerInfo>>,
        Arc<DashMap<String, bool>>,
        Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
        Arc<Mutex<Option<String>>>,
        Arc<Mutex<Option<String>>>,
    ) {
        let (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            peers,
            direct_peer_dids,
            group_mailboxes,
            _transfer_decisions,
            _pending_contact_requests,
            active_chat_target_group_id,
            active_chat_target_group_label,
        ) = spawn_test_repl_with_transfer_decisions(log_mode);
        (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            peers,
            direct_peer_dids,
            group_mailboxes,
            active_chat_target_group_id,
            active_chat_target_group_label,
        )
    }

    fn spawn_test_repl_with_peer_store(
        log_mode: LogMode,
    ) -> (
        mpsc::Sender<String>,
        mpsc::Receiver<NetworkCommand>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        Arc<tokio::sync::Mutex<PeerStore>>,
        Arc<tokio::sync::Mutex<IncomingConnectGate>>,
        Arc<Mutex<Option<String>>>,
    ) {
        let (line_tx, line_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (msg_tx_repl, _msg_rx_repl) = mpsc::channel(8);
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(
            audit_dir.path(),
            "did:nxf:test-agent",
            &[0u8; 32],
            log_mode.clone(),
        )
        .unwrap();
        let peer_store = Arc::new(tokio::sync::Mutex::new(PeerStore::new(None)));
        let incoming_connect_gate =
            Arc::new(tokio::sync::Mutex::new(IncomingConnectGate::default()));
        let active_chat_target_did = Arc::new(Mutex::new(None));
        let handle = tokio::spawn(run_repl_command_loop(
            line_rx,
            ReplCommandContext {
                cmd_tx,
                msg_tx_repl,
                peers: Arc::new(DashMap::new()),
                direct_peer_dids: Arc::new(DashMap::new()),
                active_chat_target_did: active_chat_target_did.clone(),
                active_chat_target_group_id: Arc::new(Mutex::new(None)),
                active_chat_target_group_label: Arc::new(Mutex::new(None)),
                audit: Arc::new(tokio::sync::Mutex::new(audit)),
                agent_did: "did:nxf:test-agent".to_string(),
                receive_dir_config: Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default())),
                receive_dir_path: PathBuf::from("/tmp/qypha-tests/receive_dir.json"),
                peer_store: peer_store.clone(),
                transfer_decisions: Arc::new(tokio::sync::Mutex::new(
                    TransferDecisionState::default(),
                )),
                pending_contact_requests: Arc::new(tokio::sync::Mutex::new(
                    ContactRequestRegistry::default(),
                )),
                group_mailboxes: Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default())),
                handshake_request_gate: Arc::new(tokio::sync::Mutex::new(
                    HandshakeRequestGate::default(),
                )),
                incoming_connect_gate: incoming_connect_gate.clone(),
                ratchet_mgr: Arc::new(tokio::sync::Mutex::new(
                    crate::crypto::double_ratchet::RatchetManager::new(None, None),
                )),
                agent_data_dir: std::env::temp_dir().join("qypha-tests"),
                log_mode,
                ack_tx,
            },
        ));

        (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            peer_store,
            incoming_connect_gate,
            active_chat_target_did,
        )
    }

    fn spawn_test_repl_with_handshake_gate(
        log_mode: LogMode,
    ) -> (
        mpsc::Sender<String>,
        mpsc::Receiver<NetworkCommand>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        Arc<tokio::sync::Mutex<GroupMailboxRegistry>>,
        Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
        Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    ) {
        let (line_tx, line_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (msg_tx_repl, _msg_rx_repl) = mpsc::channel(8);
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(
            audit_dir.path(),
            "did:nxf:test-agent",
            &[0u8; 32],
            log_mode.clone(),
        )
        .unwrap();
        let group_mailboxes = Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));
        let incoming_connect_gate =
            Arc::new(tokio::sync::Mutex::new(IncomingConnectGate::default()));
        let handle = tokio::spawn(run_repl_command_loop(
            line_rx,
            ReplCommandContext {
                cmd_tx,
                msg_tx_repl,
                peers: Arc::new(DashMap::new()),
                direct_peer_dids: Arc::new(DashMap::new()),
                active_chat_target_did: Arc::new(Mutex::new(None)),
                active_chat_target_group_id: Arc::new(Mutex::new(None)),
                active_chat_target_group_label: Arc::new(Mutex::new(None)),
                audit: Arc::new(tokio::sync::Mutex::new(audit)),
                agent_did: "did:nxf:test-agent".to_string(),
                receive_dir_config: Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default())),
                receive_dir_path: PathBuf::from("/tmp/qypha-tests/receive_dir.json"),
                peer_store: Arc::new(tokio::sync::Mutex::new(PeerStore::new(None))),
                transfer_decisions: Arc::new(tokio::sync::Mutex::new(
                    TransferDecisionState::default(),
                )),
                pending_contact_requests: Arc::new(tokio::sync::Mutex::new(
                    ContactRequestRegistry::default(),
                )),
                group_mailboxes: group_mailboxes.clone(),
                handshake_request_gate: handshake_request_gate.clone(),
                incoming_connect_gate: incoming_connect_gate.clone(),
                ratchet_mgr: Arc::new(tokio::sync::Mutex::new(
                    crate::crypto::double_ratchet::RatchetManager::new(None, None),
                )),
                agent_data_dir: std::env::temp_dir().join("qypha-tests"),
                log_mode,
                ack_tx,
            },
        ));

        (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            group_mailboxes,
            handshake_request_gate,
            incoming_connect_gate,
        )
    }

    fn spawn_test_repl_with_incoming_connect_gate(
        log_mode: LogMode,
    ) -> (
        mpsc::Sender<String>,
        mpsc::Receiver<NetworkCommand>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
        Arc<tokio::sync::Mutex<IncomingConnectGate>>,
        Arc<tokio::sync::Mutex<HandshakeRequestGate>>,
    ) {
        let (line_tx, line_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (msg_tx_repl, _msg_rx_repl) = mpsc::channel(8);
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(
            audit_dir.path(),
            "did:nxf:test-agent",
            &[0u8; 32],
            log_mode.clone(),
        )
        .unwrap();
        let pending_contact_requests =
            Arc::new(tokio::sync::Mutex::new(ContactRequestRegistry::default()));
        let handshake_request_gate =
            Arc::new(tokio::sync::Mutex::new(HandshakeRequestGate::default()));
        let incoming_connect_gate =
            Arc::new(tokio::sync::Mutex::new(IncomingConnectGate::default()));
        let handle = tokio::spawn(run_repl_command_loop(
            line_rx,
            ReplCommandContext {
                cmd_tx,
                msg_tx_repl,
                peers: Arc::new(DashMap::new()),
                direct_peer_dids: Arc::new(DashMap::new()),
                active_chat_target_did: Arc::new(Mutex::new(None)),
                active_chat_target_group_id: Arc::new(Mutex::new(None)),
                active_chat_target_group_label: Arc::new(Mutex::new(None)),
                audit: Arc::new(tokio::sync::Mutex::new(audit)),
                agent_did: "did:nxf:test-agent".to_string(),
                receive_dir_config: Arc::new(tokio::sync::Mutex::new(ReceiveDirConfig::default())),
                receive_dir_path: PathBuf::from("/tmp/qypha-tests/receive_dir.json"),
                peer_store: Arc::new(tokio::sync::Mutex::new(PeerStore::new(None))),
                transfer_decisions: Arc::new(tokio::sync::Mutex::new(
                    TransferDecisionState::default(),
                )),
                pending_contact_requests: pending_contact_requests.clone(),
                group_mailboxes: Arc::new(tokio::sync::Mutex::new(GroupMailboxRegistry::default())),
                handshake_request_gate: handshake_request_gate.clone(),
                incoming_connect_gate: incoming_connect_gate.clone(),
                ratchet_mgr: Arc::new(tokio::sync::Mutex::new(
                    crate::crypto::double_ratchet::RatchetManager::new(None, None),
                )),
                agent_data_dir: std::env::temp_dir().join("qypha-tests"),
                log_mode,
                ack_tx,
            },
        ));

        (
            line_tx,
            cmd_rx,
            ack_rx,
            handle,
            pending_contact_requests,
            incoming_connect_gate,
            handshake_request_gate,
        )
    }

    async fn complete_output_barrier(cmd_rx: &mut mpsc::Receiver<NetworkCommand>) {
        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::OutputDone(done_tx) => {
                done_tx.send(()).unwrap();
            }
            _ => panic!("expected output barrier"),
        }
    }

    #[test]
    fn detects_supported_group_id_prefixes() {
        assert!(looks_like_group_id("grp_test_group"));
        assert!(looks_like_group_id("gmbx_group-123"));
        assert!(looks_like_group_id("group:ops-room"));
    }

    #[test]
    fn ignores_peer_and_invalid_selectors() {
        assert!(!looks_like_group_id("did:nxf:abc123"));
        assert!(!looks_like_group_id("alice"));
        assert!(!looks_like_group_id("grp bad"));
        assert!(!looks_like_group_id(""));
    }

    #[test]
    fn ui_bridge_rejects_control_characters_in_selector() {
        let encoded = encode_ui_bridge(&UiBridgeCommand::SendTo {
            selector: "did:nxf:alice\n/quit".to_string(),
            message: "hello".to_string(),
        });

        let error = decode_ui_bridge_line(&encoded).unwrap_err();
        assert!(error.contains("Selector"));
    }

    #[test]
    fn ui_bridge_normalizes_transfer_path_with_spaces() {
        let encoded = encode_ui_bridge(&UiBridgeCommand::TransferToPeer {
            selector: "did:nxf:alice".to_string(),
            path: "/tmp/Quarterly Report.pdf".to_string(),
        });

        let line = decode_ui_bridge_line(&encoded).unwrap();
        assert_eq!(line, "/transfer /tmp/Quarterly Report.pdf did:nxf:alice");
    }

    #[tokio::test]
    async fn sendto_group_selector_dispatches_group_plane_command() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _peers,
            _direct_peer_dids,
            group_mailboxes,
            active_chat_target_group_id,
            active_chat_target_group_label,
        ) = spawn_test_repl(LogMode::Ghost);
        let (session, _) = create_ghost_anonymous_group(
            Some("ops"),
            build_mailbox_descriptor(
                "grp_ops",
                "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                5_000,
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        group_mailboxes
            .lock()
            .await
            .insert_session(session)
            .unwrap();

        line_tx
            .send("/sendto grp_ops hello group".to_string())
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendChatToGroup { group_id, message } => {
                assert_eq!(group_id, "grp_ops");
                assert_eq!(message, "hello group");
            }
            _ => panic!("expected SendChatToGroup"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            active_chat_target_group_id.lock().unwrap().as_deref(),
            Some("grp_ops")
        );
        assert_eq!(
            active_chat_target_group_label.lock().unwrap().as_deref(),
            Some("ops")
        );
    }

    #[tokio::test]
    async fn sendto_direct_selector_dispatches_direct_plane_command() {
        let (line_tx, mut cmd_rx, ack_rx, handle, peers, direct_peer_dids, ..) =
            spawn_test_repl(LogMode::Safe);
        let peer = sample_peer_info("did:nxf:alice", "Alice");
        let peer_id = peer.peer_id;
        peers.insert(peer_id.to_string(), peer.clone());
        direct_peer_dids.insert(peer.did.clone(), true);

        line_tx
            .send("/sendto did:nxf:alice hello direct".to_string())
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendChatToPeer {
                peer_id: dispatched_peer_id,
                peer_did,
                peer_name,
                message,
            } => {
                assert_eq!(dispatched_peer_id, peer_id);
                assert_eq!(peer_did, "did:nxf:alice");
                assert_eq!(peer_name, "Alice");
                assert_eq!(message, "hello direct");
            }
            _ => panic!("expected SendChatToPeer"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn ui_bridge_sendto_dispatches_direct_plane_command() {
        let (line_tx, mut cmd_rx, ack_rx, handle, peers, direct_peer_dids, ..) =
            spawn_test_repl(LogMode::Safe);
        let peer = sample_peer_info("did:nxf:alice", "Alice");
        let peer_id = peer.peer_id;
        peers.insert(peer_id.to_string(), peer.clone());
        direct_peer_dids.insert(peer.did.clone(), true);

        line_tx
            .send(encode_ui_bridge(&UiBridgeCommand::SendTo {
                selector: "did:nxf:alice".to_string(),
                message: "hello via ui bridge".to_string(),
            }))
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendChatToPeer {
                peer_id: dispatched_peer_id,
                peer_did,
                peer_name,
                message,
            } => {
                assert_eq!(dispatched_peer_id, peer_id);
                assert_eq!(peer_did, "did:nxf:alice");
                assert_eq!(peer_name, "Alice");
                assert_eq!(message, "hello via ui bridge");
            }
            _ => panic!("expected SendChatToPeer"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn transfer_dispatches_windows_quoted_path_without_quotes() {
        let (line_tx, mut cmd_rx, ack_rx, handle, peers, direct_peer_dids, ..) =
            spawn_test_repl(LogMode::Safe);
        let peer = sample_peer_info("did:nxf:alice", "Alice");
        let peer_id = peer.peer_id;
        peers.insert(peer_id.to_string(), peer.clone());
        direct_peer_dids.insert(peer.did.clone(), true);

        line_tx
            .send(r#"/transfer "C:\Users\koray\OneDrive\Masaüstü\cagatay sonn.mp4" 1"#.to_string())
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendFile {
                path,
                peer_selector,
            } => {
                assert_eq!(path, r#"C:\Users\koray\OneDrive\Masaüstü\cagatay sonn.mp4"#);
                assert_eq!(peer_selector, "1");
            }
            _ => panic!("expected SendFile"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn transfer_g_dispatches_quoted_path_without_quotes() {
        let (line_tx, mut cmd_rx, ack_rx, handle, ..) = spawn_test_repl(LogMode::Ghost);

        line_tx
            .send(
                r#"/transfer_g grp_files "C:\Users\koray\OneDrive\Masaüstü\evidence bin.mp4""#
                    .to_string(),
            )
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendGroupFile { group_id, path } => {
                assert_eq!(group_id, "grp_files");
                assert_eq!(path, r#"C:\Users\koray\OneDrive\Masaüstü\evidence bin.mp4"#);
            }
            _ => panic!("expected SendGroupFile"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn transfer_g_dispatches_group_file_command() {
        let (line_tx, mut cmd_rx, ack_rx, handle, ..) = spawn_test_repl(LogMode::Ghost);

        line_tx
            .send("/transfer_g grp_files /tmp/evidence.bin".to_string())
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendGroupFile { group_id, path } => {
                assert_eq!(group_id, "grp_files");
                assert_eq!(path, "/tmp/evidence.bin");
            }
            _ => panic!("expected SendGroupFile"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn disconnect_offline_contact_did_dispatches_known_peer_disconnect_and_blocks_gate() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            peer_store,
            incoming_connect_gate,
            active_chat_target_did,
        ) = spawn_test_repl_with_peer_store(LogMode::Safe);
        let peer_keypair = AgentKeyPair::generate("Alice", "agent");
        let peer_did = peer_keypair.did.clone();
        let contact_did = contact_did_from_canonical_did(&peer_did).unwrap();
        let known_peer_id = libp2p::PeerId::random().to_string();
        {
            let mut store = peer_store.lock().await;
            store.upsert(KnownPeer {
                did: peer_did.clone(),
                name: "Alice".to_string(),
                role: "agent".to_string(),
                peer_id: known_peer_id.clone(),
                onion_address: None,
                tcp_address: None,
                iroh_endpoint_addr: None,
                onion_port: 9090,
                encryption_public_key_hex: None,
                verifying_key_hex: Some(hex::encode(peer_keypair.verifying_key.to_bytes())),
                kyber_public_key_hex: None,
                last_seen: 0,
                auto_reconnect: true,
            });
        }
        {
            let mut active_target = active_chat_target_did.lock().unwrap();
            *active_target = Some(peer_did.clone());
        }

        line_tx
            .send(format!("/disconnect {}", contact_did))
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::DisconnectKnownPeer {
                peer_did: dispatched_did,
                peer_name,
            } => {
                assert_eq!(dispatched_did, peer_did);
                assert_eq!(peer_name, "Alice");
            }
            _ => panic!("expected DisconnectKnownPeer"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert!(active_chat_target_did.lock().unwrap().is_none());
        let store = peer_store.lock().await;
        assert!(store.get(&peer_did).is_none());
        let gate = incoming_connect_gate.lock().await;
        assert!(gate.is_did_blocked(&peer_did));
        assert!(gate.is_peer_id_blocked(&known_peer_id));
    }

    #[tokio::test]
    async fn connect_did_unblocks_manual_disconnect_gate_before_dispatch() {
        let (line_tx, mut cmd_rx, ack_rx, handle, _peer_store, incoming_connect_gate, _) =
            spawn_test_repl_with_peer_store(LogMode::Safe);
        let peer_keypair = AgentKeyPair::generate("Alice", "agent");
        let peer_did = peer_keypair.did.clone();
        let contact_did = contact_did_from_canonical_did(&peer_did).unwrap();
        let blocked_peer_id = libp2p::PeerId::random().to_string();
        {
            let mut gate = incoming_connect_gate.lock().await;
            gate.block_peer_identity(&peer_did, Some(&blocked_peer_id))
                .unwrap();
            assert!(gate.is_did_blocked(&peer_did));
            assert!(gate.is_peer_id_blocked(&blocked_peer_id));
        }

        line_tx
            .send(format!("/connect {}", contact_did))
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::ConnectDid { did, intro_message } => {
                assert_eq!(did, contact_did);
                assert!(intro_message.is_none());
            }
            _ => panic!("expected ConnectDid"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let gate = incoming_connect_gate.lock().await;
        assert!(!gate.is_did_blocked(&peer_did));
        assert!(!gate.is_peer_id_blocked(&blocked_peer_id));
    }

    #[tokio::test]
    async fn safe_mode_rejects_group_anon_in_repl_without_dispatching_network_command() {
        let (line_tx, mut cmd_rx, _ack_rx, handle, ..) = spawn_test_repl(LogMode::Safe);

        line_tx.send("/group_anon ops".to_string()).await.unwrap();
        drop(line_tx);

        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Ok(None)
        ));
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ghost_mode_blocks_invite_h_before_dispatch() {
        let (line_tx, mut cmd_rx, ack_rx, handle, ..) = spawn_test_repl(LogMode::Ghost);

        line_tx
            .send("/invite_h did:nxf:member".to_string())
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        match tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(_)) => panic!("ghost mode must not dispatch /invite_h"),
        }
    }

    #[tokio::test]
    async fn invite_hg_rate_limits_repeated_dispatches_for_same_member() {
        let (line_tx, mut cmd_rx, ack_rx, handle, group_mailboxes, _handshake_gate, _) =
            spawn_test_repl_with_handshake_gate(LogMode::Safe);
        seed_identified_group_member_for_test(
            &group_mailboxes,
            "grp_team",
            Some("team"),
            "did:nxf:test-agent",
            "agent4",
            "did:nxf:alice",
            "alice",
        )
        .await
        .unwrap();

        line_tx
            .send("/invite_hg grp_team did:nxf:alice".to_string())
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendHandshakeInviteScoped {
                group_id,
                member_id,
            } => {
                assert_eq!(group_id, "grp_team");
                assert_eq!(member_id, "did:nxf:alice");
            }
            _ => panic!("expected SendHandshakeInviteScoped"),
        }
        complete_output_barrier(&mut cmd_rx).await;

        line_tx
            .send("/invite_hg grp_team did:nxf:alice".to_string())
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn reject_direct_transfer_acknowledges_repl_immediately() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            peers,
            direct_peer_dids,
            _group_mailboxes,
            transfer_decisions,
            _pending_contact_requests,
            _active_chat_target_group_id,
            _active_chat_target_group_label,
        ) = spawn_test_repl_with_transfer_decisions(LogMode::Safe);

        let peer = sample_peer_info("did:nxf:alice", "Alice");
        peers.insert(peer.peer_id.to_string(), peer.clone());
        direct_peer_dids.insert(peer.did.clone(), true);
        transfer_decisions.lock().await.queue_pending(
            crate::agent::daemon::transfer_gate::PendingIncomingTransfer {
                peer_id: peer.peer_id,
                sender_did: peer.did.clone(),
                sender_name: peer.name.clone(),
                request: AgentRequest {
                    message_id: "msg-1".to_string(),
                    sender_did: peer.did.clone(),
                    sender_name: peer.name.clone(),
                    sender_role: "agent".to_string(),
                    msg_type: crate::network::protocol::MessageKind::ChunkTransferInit,
                    payload: Vec::new(),
                    signature: Vec::new(),
                    nonce: 1,
                    timestamp: 1,
                    ttl_ms: 0,
                },
                decision_key: "chunk_init|did:nxf:alice|1|1".to_string(),
                kind: PendingTransferKind::ChunkInit {
                    session_id: "sess_test".to_string(),
                    total_chunks: 166,
                    sealed_v2: true,
                    filename_hint: None,
                    total_size_hint: None,
                },
            },
        );

        line_tx
            .send("/reject did:nxf:alice".to_string())
            .await
            .unwrap();

        tokio::task::spawn_blocking(move || ack_rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendTransferReject {
                peer_id,
                session_id,
                request_message_id,
                reason,
            } => {
                assert_eq!(peer_id, peer.peer_id);
                assert_eq!(session_id.as_deref(), Some("sess_test"));
                assert_eq!(request_message_id.as_deref(), Some("msg-1"));
                assert_eq!(reason, "rejected_by_user");
            }
            _ => panic!("expected SendTransferReject"),
        }

        drop(line_tx);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn accept_group_handshake_offer_dispatches_connect_invite() {
        let (line_tx, mut cmd_rx, ack_rx, handle, group_mailboxes, _handshake_gate, _) =
            spawn_test_repl_with_handshake_gate(LogMode::Safe);
        crate::agent::daemon::group_mailbox::seed_pending_group_handshake_offer_for_test(
            &group_mailboxes,
            "grp_team",
            Some("team"),
            "did:nxf:alice",
            "ql://direct-offer",
            crate::agent::daemon::group_mailbox::GroupMailboxPersistence::EncryptedDisk,
        )
        .await
        .unwrap();

        line_tx
            .send("/accept did:nxf:alice".to_string())
            .await
            .unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::ConnectInvite { code } => {
                assert_eq!(code, "ql://direct-offer");
            }
            _ => panic!("expected ConnectInvite"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(group_mailboxes
            .lock()
            .await
            .pending_handshake_offers()
            .is_empty());
    }

    #[tokio::test]
    async fn connect_did_dispatches_did_connect_command() {
        let did = crate::network::contact_did::contact_did_from_verifying_key_bytes([1u8; 32]);
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _peers,
            _direct_peer_dids,
            _group_mailboxes,
            _active_chat_target_group_id,
            _active_chat_target_group_label,
        ) = spawn_test_repl(LogMode::Safe);

        line_tx.send(format!("/connect {did}")).await.unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::ConnectDid { did, intro_message } => {
                assert_eq!(
                    did,
                    crate::network::contact_did::contact_did_from_verifying_key_bytes([1u8; 32])
                );
                assert!(intro_message.is_none());
            }
            _ => panic!("expected ConnectDid"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn connect_did_dispatches_with_extra_spaces() {
        let did = crate::network::contact_did::contact_did_from_verifying_key_bytes([2u8; 32]);
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _peers,
            _direct_peer_dids,
            _group_mailboxes,
            _active_chat_target_group_id,
            _active_chat_target_group_label,
        ) = spawn_test_repl(LogMode::Safe);

        line_tx.send(format!("/connect  {did}")).await.unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::ConnectDid { did, intro_message } => {
                assert_eq!(
                    did,
                    crate::network::contact_did::contact_did_from_verifying_key_bytes([2u8; 32])
                );
                assert!(intro_message.is_none());
            }
            _ => panic!("expected ConnectDid"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn accept_short_contact_did_dispatches_contact_accept() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _peers,
            _direct_peer_dids,
            _group_mailboxes,
            _transfer_decisions,
            pending_contact_requests,
            _active_chat_target_group_id,
            _active_chat_target_group_label,
        ) = spawn_test_repl_with_transfer_decisions(LogMode::Safe);

        let keypair = AgentKeyPair::generate("Alice", "agent");
        let payload = sample_contact_request_payload(&keypair);
        let short_did = encode_contact_did(&payload.sender_profile).unwrap();
        pending_contact_requests
            .lock()
            .await
            .upsert_mailbox("Alice".to_string(), payload);

        line_tx.send(format!("/accept {short_did}")).await.unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendContactAccept { pending } => {
                assert_eq!(pending.sender_did, keypair.did);
                assert_eq!(pending.sender_name, "Alice");
            }
            _ => panic!("expected SendContactAccept"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn reject_short_contact_did_dispatches_contact_reject() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _peers,
            _direct_peer_dids,
            _group_mailboxes,
            _transfer_decisions,
            pending_contact_requests,
            _active_chat_target_group_id,
            _active_chat_target_group_label,
        ) = spawn_test_repl_with_transfer_decisions(LogMode::Safe);

        let keypair = AgentKeyPair::generate("Bob", "agent");
        let payload = sample_contact_request_payload(&keypair);
        let short_did = encode_contact_did(&payload.sender_profile).unwrap();
        pending_contact_requests
            .lock()
            .await
            .upsert_mailbox("Bob".to_string(), payload);

        line_tx.send(format!("/reject {short_did}")).await.unwrap();
        drop(line_tx);

        match tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendContactReject { pending, reason } => {
                assert_eq!(pending.sender_did, keypair.did);
                assert_eq!(pending.sender_name, "Bob");
                assert_eq!(reason.as_deref(), Some("rejected by user"));
            }
            _ => panic!("expected SendContactReject"),
        }
        complete_output_barrier(&mut cmd_rx).await;
        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn block_inv_blocks_contact_did_and_clears_pending_request() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            pending_contact_requests,
            incoming_connect_gate,
            handshake_request_gate,
        ) = spawn_test_repl_with_incoming_connect_gate(LogMode::Safe);

        let keypair = AgentKeyPair::generate("Mallory", "agent");
        let payload = sample_contact_request_payload(&keypair);
        let short_did = encode_contact_did(&payload.sender_profile).unwrap();
        pending_contact_requests
            .lock()
            .await
            .upsert_mailbox("Mallory".to_string(), payload);

        line_tx
            .send(format!("/block_inv {short_did}"))
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(incoming_connect_gate
            .lock()
            .await
            .is_did_blocked(&keypair.did));
        assert!(pending_contact_requests
            .lock()
            .await
            .get(&keypair.did)
            .is_none());
        assert!(!handshake_request_gate
            .lock()
            .await
            .is_member_blocked(&keypair.did));
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn unlock_inv_only_unblocks_incoming_connect_gate() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _pending_contact_requests,
            incoming_connect_gate,
            handshake_request_gate,
        ) = spawn_test_repl_with_incoming_connect_gate(LogMode::Safe);

        let keypair = AgentKeyPair::generate("Trent", "agent");
        let short_did = crate::network::contact_did::contact_did_from_verifying_key_bytes(
            keypair.verifying_key.to_bytes(),
        );
        incoming_connect_gate
            .lock()
            .await
            .block_selector(&short_did)
            .unwrap();
        handshake_request_gate
            .lock()
            .await
            .block_member(&keypair.did)
            .unwrap();

        line_tx
            .send(format!("/unlock_inv {short_did}"))
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!incoming_connect_gate
            .lock()
            .await
            .is_did_blocked(&keypair.did));
        assert!(handshake_request_gate
            .lock()
            .await
            .is_member_blocked(&keypair.did));
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn block_inv_all_sets_global_gate_and_clears_all_pending_requests() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            pending_contact_requests,
            incoming_connect_gate,
            _handshake_request_gate,
        ) = spawn_test_repl_with_incoming_connect_gate(LogMode::Safe);

        let first = AgentKeyPair::generate("FirstBlocked", "agent");
        let second = AgentKeyPair::generate("SecondBlocked", "agent");
        pending_contact_requests.lock().await.upsert_mailbox(
            "FirstBlocked".to_string(),
            sample_contact_request_payload(&first),
        );
        pending_contact_requests.lock().await.upsert_mailbox(
            "SecondBlocked".to_string(),
            sample_contact_request_payload(&second),
        );

        line_tx.send("/block_inv all".to_string()).await.unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(incoming_connect_gate.lock().await.is_block_all());
        assert_eq!(pending_contact_requests.lock().await.len(), 0);
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn unlock_inv_all_clears_global_gate() {
        let (
            line_tx,
            mut cmd_rx,
            ack_rx,
            handle,
            _pending_contact_requests,
            incoming_connect_gate,
            _handshake_request_gate,
        ) = spawn_test_repl_with_incoming_connect_gate(LogMode::Safe);

        incoming_connect_gate
            .lock()
            .await
            .set_block_all(true)
            .unwrap();

        line_tx.send("/unlock_inv all".to_string()).await.unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!incoming_connect_gate.lock().await.is_block_all());
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn reject_group_handshake_offer_clears_pending_offer_without_network_dispatch() {
        let (line_tx, mut cmd_rx, ack_rx, handle, group_mailboxes, _handshake_gate, _) =
            spawn_test_repl_with_handshake_gate(LogMode::Safe);
        crate::agent::daemon::group_mailbox::seed_pending_group_handshake_offer_for_test(
            &group_mailboxes,
            "grp_team",
            Some("team"),
            "did:nxf:alice",
            "ql://direct-offer",
            crate::agent::daemon::group_mailbox::GroupMailboxPersistence::EncryptedDisk,
        )
        .await
        .unwrap();

        line_tx
            .send("/reject did:nxf:alice".to_string())
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(group_mailboxes
            .lock()
            .await
            .pending_handshake_offers()
            .is_empty());
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }

    #[tokio::test]
    async fn block_group_handshake_offer_clears_pending_offer_and_blocks_sender() {
        let (line_tx, mut cmd_rx, ack_rx, handle, group_mailboxes, handshake_gate, _) =
            spawn_test_repl_with_handshake_gate(LogMode::Safe);
        crate::agent::daemon::group_mailbox::seed_pending_group_handshake_offer_for_test(
            &group_mailboxes,
            "grp_team",
            Some("team"),
            "did:nxf:alice",
            "ql://direct-offer",
            crate::agent::daemon::group_mailbox::GroupMailboxPersistence::EncryptedDisk,
        )
        .await
        .unwrap();

        line_tx
            .send("/block did:nxf:alice".to_string())
            .await
            .unwrap();
        drop(line_tx);

        handle.await.unwrap().unwrap();
        ack_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(group_mailboxes
            .lock()
            .await
            .pending_handshake_offers()
            .is_empty());
        assert!(handshake_gate
            .lock()
            .await
            .is_member_blocked("did:nxf:alice"));
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(100), cmd_rx.recv()).await,
            Err(_) | Ok(None)
        ));
    }
}
